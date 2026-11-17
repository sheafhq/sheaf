// Build #1 exit criteria:
//   eight disclosure cases + a swapped-key bundle that must fail with
//   RECORDER_KEY_MISMATCH, plus the fail-closed trust checks.
//
// The fixture creates real Ed25519 signatures and real Merkle trees, but uses
// synthetic chain rows. It never contacts a network.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

import {
  d1DisclosureSource,
  discloseRange,
} from "../.test-dist/disclose.js";
import { canonicalize, hashCanonical } from "../.test-dist/canonical.js";
import { buildMerkleTree } from "../.test-dist/merkle.js";
import {
  PINNED_ANCHORERS,
  PINNED_RECORDER_KEYS,
  verify as verifyReceipt,
  verifyDisclosures,
} from "../packages/verify/dist/index.js";

const { subtle } = webcrypto;
const CHAIN_ID = "test-chain-1";
const ANCHORER = "0x1111111111111111111111111111111111111111";
const OTHER_ANCHORER = "0x2222222222222222222222222222222222222222";

async function makeKey() {
  const pair = await subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  return {
    privateKey: pair.privateKey,
    publicKeyBase64: Buffer.from(raw).toString("base64"),
  };
}

async function signCore(privateKey, core) {
  const message = new TextEncoder().encode(canonicalize(core));
  const signature = new Uint8Array(
    await subtle.sign("Ed25519", privateKey, message),
  );
  return Buffer.from(signature).toString("base64");
}

async function buildFixture({
  count = 6,
  epochRanges = [
    [0, 2, 1001],
    [3, 5, 1002],
  ],
  key,
} = {}) {
  const recorderKey = key ?? (await makeKey());
  const rows = [];
  let prevHash = null;

  for (let seq = 0; seq < count; seq++) {
    const ts = new Date(
      Date.UTC(2026, 10, 10, 16, 0, 0) + seq * 60_000,
    ).toISOString();
    const event = {
      intent: `step ${seq}`,
      actor: "agent://test-agent",
      authority: null,
      tool: "mcp://test/step",
      inputs_hash: await hashCanonical({ seq, kind: "input" }),
      outputs_hash: await hashCanonical({ seq, kind: "output" }),
      result: "ok",
      ts,
    };
    const core = {
      v: "arca/1",
      event,
      chain: { chain_id: CHAIN_ID, seq, prev_hash: prevHash },
    };
    const envelopeHash = await hashCanonical(core);
    rows.push({
      seq,
      envelope_json: JSON.stringify({
        ...core,
        signatures: {
          actor: null,
          recorder: await signCore(recorderKey.privateKey, core),
        },
      }),
      envelope_hash: envelopeHash,
      epoch_id: null,
      epoch_leaf_idx: null,
    });
    prevHash = envelopeHash;
  }

  const epochs = new Map();
  for (const [start, end, epochId] of epochRanges) {
    const epochRows = rows.filter((r) => r.seq >= start && r.seq <= end);
    const leaves = epochRows.map((r) => r.envelope_hash);
    const { root } = await buildMerkleTree(leaves);
    epochRows.forEach((row, idx) => {
      row.epoch_id = epochId;
      row.epoch_leaf_idx = idx;
    });
    epochs.set(epochId, {
      epoch_id: epochId,
      merkle_root: root,
      anchor_tx_hash: "0x" + String(epochId).padStart(64, "0"),
      anchor_block: 1000 + epochId,
    });
  }

  return { rows, epochs, key: recorderKey };
}

function makeSource(fixture) {
  return {
    async listEvents(chainId, fromSeq, toSeq) {
      assert.equal(chainId, CHAIN_ID);
      return fixture.rows
        .filter((r) => r.seq >= fromSeq && r.seq <= toSeq)
        .sort((a, b) => a.seq - b.seq);
    },
    async getEvent(chainId, seq) {
      assert.equal(chainId, CHAIN_ID);
      return fixture.rows.find((r) => r.seq === seq) ?? null;
    },
    async getEpoch(epochId) {
      return fixture.epochs.get(epochId) ?? null;
    },
    async listEpochLeaves(epochId) {
      return fixture.rows
        .filter((r) => r.epoch_id === epochId)
        .sort((a, b) => a.epoch_leaf_idx - b.epoch_leaf_idx)
        .map((r) => r.envelope_hash);
    },
  };
}

function fakeD1(fixture) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async all() {
              if (sql.includes("seq >= ?") && sql.includes("seq <= ?")) {
                const [chainId, fromSeq, toSeq] = args;
                assert.equal(chainId, CHAIN_ID);
                return {
                  results: fixture.rows
                    .filter((r) => r.seq >= fromSeq && r.seq <= toSeq)
                    .sort((a, b) => a.seq - b.seq),
                };
              }
              if (sql.includes("WHERE epoch_id = ?")) {
                const [epochId] = args;
                return {
                  results: fixture.rows
                    .filter((r) => r.epoch_id === epochId)
                    .sort((a, b) => a.epoch_leaf_idx - b.epoch_leaf_idx)
                    .map((r) => ({ envelope_hash: r.envelope_hash })),
                };
              }
              throw new Error(`unexpected all() SQL: ${sql}`);
            },
            async first() {
              if (sql.includes("FROM events")) {
                const [chainId, seq] = args;
                assert.equal(chainId, CHAIN_ID);
                return fixture.rows.find((r) => r.seq === seq) ?? null;
              }
              if (sql.includes("FROM epochs")) {
                const [epochId] = args;
                return fixture.epochs.get(epochId) ?? null;
              }
              throw new Error(`unexpected first() SQL: ${sql}`);
            },
          };
        },
      };
    },
  };
}

function recorderFor(key) {
  return {
    name: "Test Recorder",
    key_id: "test-key-1",
    public_key_base64: key.publicKeyBase64,
    public_key_url: "https://should-never-be-fetched.invalid/key",
  };
}

function trustFor(key, anchorer = ANCHORER) {
  return {
    recorder_keys: [
      {
        key_id: "test-key-1",
        public_key_base64: key.publicKeyBase64,
        active_from: "2020-01-01T00:00:00Z",
        active_until: null,
      },
    ],
    anchorers: [
      {
        network: "eip155:8453",
        address: anchorer,
        active_from: "2020-01-01T00:00:00Z",
        active_until: null,
      },
    ],
  };
}

async function disclose(fixture, fromSeq, toSeq, key = fixture.key) {
  const result = await discloseRange(
    makeSource(fixture),
    CHAIN_ID,
    fromSeq,
    toSeq,
    {
      recorder: recorderFor(key),
      anchorer: ANCHORER,
      network: "eip155:8453",
      blockHashes: Object.fromEntries(
        [...fixture.epochs.keys()].map((id) => [
          id,
          "0x" + String(id).padStart(64, "b"),
        ]),
      ),
    },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.disclosure;
}

function refs(disclosure, from, to) {
  return disclosure.disclosures
    .filter((d) => d.envelope.chain.seq >= from && d.envelope.chain.seq <= to)
    .map((d) => d.envelope.chain.seq);
}

async function verify(disclosure, key = null, trust = null) {
  const result = await verifyDisclosures(disclosure, {
    mode: "dispute",
    trust: trust ?? trustFor(key ?? { publicKeyBase64: "unused" }),
  });
  return result;
}

test("1. single event: one range disclosure plus anchored boundaries", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 2, 2);
  assert.deepEqual(refs(disclosure, 2, 2), [2]);
  assert.equal(disclosure.before_ref?.seq, 1);
  assert.equal(disclosure.after_ref?.seq, 3);
  assert.equal(disclosure.disclosures.length, 3);

  const result = await verify(disclosure, fixture.key);
  assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.checks.selection_contiguous, true);
  assert.equal(result.checks.before_link, true);
  assert.equal(result.checks.after_link, true);
});

test("2. contiguous range: every seq in the window is present and linked", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  assert.deepEqual(refs(disclosure, 1, 4), [1, 2, 3, 4]);

  const result = await verify(disclosure, fixture.key);
  assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.checks.selection_contiguous, true);
  assert.equal(result.checks.chain_links, true);
});

test("3. cross-epoch: one range spans two separate anchor epochs", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  assert.equal(disclosure.anchor.epochs.length, 2);
  assert.deepEqual(
    disclosure.anchor.epochs.map((e) => e.epoch_id),
    [1001, 1002],
  );

  const result = await verify(disclosure, fixture.key);
  assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.checks.merkle_inclusion_proof, true);
  assert.equal(result.checks.anchor_epoch_present, true);
});

test("3b. D1 adapter: the Worker source returns the same disclosures", async () => {
  const fixture = await buildFixture();
  const result = await discloseRange(
    d1DisclosureSource(fakeD1(fixture)),
    CHAIN_ID,
    1,
    4,
    {
      recorder: recorderFor(fixture.key),
      anchorer: ANCHORER,
      network: "eip155:8453",
    },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(refs(result.disclosure, 1, 4), [1, 2, 3, 4]);

  const verified = await verifyDisclosures(result.disclosure, {
    mode: "dispute",
    trust: trustFor(fixture.key),
  });
  assert.equal(verified.valid, true, JSON.stringify(verified));
});

test("3c. chain edges: null before_ref at seq 0 and null after_ref at head", async () => {
  const fixture = await buildFixture();
  const start = await disclose(fixture, 0, 1);
  assert.equal(start.before_ref, null);
  assert.equal(start.after_ref?.seq, 2);
  const startResult = await verify(start, fixture.key);
  assert.equal(startResult.valid, true, JSON.stringify(startResult));

  const head = await disclose(fixture, 4, 5);
  assert.equal(head.before_ref?.seq, 3);
  assert.equal(head.after_ref, null);
  const headResult = await verify(head, fixture.key);
  assert.equal(headResult.valid, true, JSON.stringify(headResult));
});

test("4. odd-leaf tree: a 5-leaf epoch verifies with duplicated internal nodes", async () => {
  const fixture = await buildFixture({
    count: 5,
    epochRanges: [[0, 4, 2001]],
  });
  const disclosure = await disclose(fixture, 4, 4);
  const event = disclosure.disclosures.find(
    (d) => d.envelope.chain.seq === 4,
  );
  assert.ok(event);
  assert.ok(event.proof.siblings.length > 0);
  // The 5th leaf is the odd node: it is paired with itself, so its proof
  // carries its own hash as the right-hand sibling. That is exactly the
  // duplication edge case the verifier must reproduce.
  assert.equal(event.proof.siblings[0].hash, event.envelope_hash);
  assert.equal(event.proof.siblings[0].side, "right");

  const result = await verify(disclosure, fixture.key);
  assert.equal(result.valid, true, JSON.stringify(result));
});

test("5. boundaries: before_ref and after_ref bridge the window to the chain", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 2, 3);
  assert.equal(disclosure.before_ref?.seq, 1);
  assert.equal(disclosure.after_ref?.seq, 4);

  const result = await verify(disclosure, fixture.key);
  assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.checks.before_link, true);
  assert.equal(result.checks.after_link, true);
});

test("6. tampered sibling: proof no longer reproduces the root", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  const tampered = structuredClone(disclosure);
  const event = tampered.disclosures.find(
    (d) => d.envelope.chain.seq >= 1 && d.envelope.chain.seq <= 4,
  );
  assert.ok(event);
  event.proof.siblings[0].hash =
    event.proof.siblings[0].hash.slice(0, -1) +
    (event.proof.siblings[0].hash.endsWith("0") ? "1" : "0");

  const result = await verify(tampered, fixture.key);
  assert.equal(result.valid, false);
  assert.equal(result.code, "MERKLE_PROOF_INVALID");
});

test("7. missing event: the builder refuses a gapped range", async () => {
  const fixture = await buildFixture();
  fixture.rows = fixture.rows.filter((r) => r.seq !== 3);
  const result = await discloseRange(
    makeSource(fixture),
    CHAIN_ID,
    1,
    4,
    { recorder: recorderFor(fixture.key), anchorer: ANCHORER },
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 404);
  assert.equal(result.code, "MISSING_EVENTS");
  assert.deepEqual(result.detail.missing, [3]);
});

test("8. unanchored event: the builder refuses to disclose it", async () => {
  const fixture = await buildFixture();
  const row = fixture.rows.find((r) => r.seq === 2);
  assert.ok(row);
  row.epoch_id = null;
  row.epoch_leaf_idx = null;

  const result = await discloseRange(
    makeSource(fixture),
    CHAIN_ID,
    1,
    4,
    { recorder: recorderFor(fixture.key), anchorer: ANCHORER },
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
  assert.equal(result.code, "UNANCHORED_EVENTS");
  assert.deepEqual(result.detail.seqs, [2]);
});

test("exit criterion: swapped key fails with RECORDER_KEY_MISMATCH", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);

  const attacker = await makeKey();
  const swapped = structuredClone(disclosure);
  for (const d of swapped.disclosures) {
    const core = { v: d.envelope.v, event: d.envelope.event, chain: d.envelope.chain };
    d.envelope.signatures.recorder = await signCore(attacker.privateKey, core);
  }
  swapped.recorder.public_key_base64 = attacker.publicKeyBase64;

  const result = await verifyDisclosures(swapped, {
    mode: "dispute",
    trust: trustFor(fixture.key),
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "RECORDER_KEY_MISMATCH");
  assert.equal(result.checks.recorder_key_known, true);
  assert.equal(result.checks.recorder_key_matches, false);
});

test("trust: unknown recorder key id fails UNKNOWN_RECORDER_KEY", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  disclosure.recorder.key_id = "attacker-key";
  const result = await verifyDisclosures(disclosure, {
    mode: "dispute",
    trust: trustFor(fixture.key),
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "UNKNOWN_RECORDER_KEY");
});

test("trust: unknown anchorer fails UNKNOWN_ANCHORER", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  disclosure.anchor.anchorer = OTHER_ANCHORER;
  const result = await verifyDisclosures(disclosure, {
    mode: "dispute",
    trust: trustFor(fixture.key),
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "UNKNOWN_ANCHORER");
});

test("trust: dispute mode is opt-in", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  const result = await verifyDisclosures(disclosure, {
    trust: trustFor(fixture.key),
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "DISPUTE_MODE_REQUIRED");
});

test("trust: public_key_url is never fetched in offline mode", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  disclosure.recorder.public_key_url = "https://sheafhq.invalid/should-not-fetch";

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("fetch must not be called by offline disclosure verification");
  };
  try {
    const result = await verifyDisclosures(disclosure, {
      mode: "dispute",
      trust: trustFor(fixture.key),
    });
    assert.equal(result.valid, true, JSON.stringify(result));
    assert.equal(result.anchor_confirmed, false);
    assert.equal(result.checks.anchor_tx_on_chain, null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("anchor: online mode confirms the calldata via the Base RPC", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);
  const epochsByHash = new Map(
    disclosure.anchor.epochs.map((e) => [e.tx_hash.toLowerCase(), e]),
  );

  const originalFetch = globalThis.fetch;
  const fetchedUrls = [];
  globalThis.fetch = async (url, init) => {
    fetchedUrls.push(String(url));
    const body = JSON.parse(String(init?.body ?? "{}"));
    if (body.method === "eth_chainId") {
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x2105" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(body.method, "eth_getTransactionByHash");
    const epoch = epochsByHash.get(String(body.params?.[0] ?? "").toLowerCase());
    assert.ok(epoch);
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          from: ANCHORER,
          to: ANCHORER,
          input: epoch.calldata,
          blockNumber: "0x" + epoch.block_number.toString(16),
          hash: epoch.tx_hash,
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  try {
    const result = await verifyDisclosures(disclosure, {
      mode: "dispute",
      trust: trustFor(fixture.key),
      base_rpc: "https://rpc.invalid",
    });
    assert.equal(result.valid, true, JSON.stringify(result));
    assert.equal(result.anchor_confirmed, true);
    assert.equal(result.checks.anchor_tx_on_chain, true);
    assert.equal(result.checks.anchor_from_authorized_anchorer, true);
    assert.deepEqual(new Set(fetchedUrls), new Set(["https://rpc.invalid"]));
    assert.equal(
      fetchedUrls.some((u) => /sheaf|goldencalf/i.test(u)),
      false,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("anchor: wrong RPC chain fails WRONG_CHAIN before trusting the tx", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 1, 4);

  const originalFetch = globalThis.fetch;
  const fetchedUrls = [];
  globalThis.fetch = async (url) => {
    fetchedUrls.push(String(url));
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  try {
    const result = await verifyDisclosures(disclosure, {
      mode: "dispute",
      trust: trustFor(fixture.key),
      base_rpc: "https://ethereum.invalid",
    });
    assert.equal(result.valid, false);
    assert.equal(result.code, "WRONG_CHAIN");
    assert.deepEqual(fetchedUrls, ["https://ethereum.invalid"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("regression: legacy verify() still accepts sheaf-bundle/1 shape", async () => {
  const fixture = await buildFixture();
  const disclosure = await disclose(fixture, 0, 0);
  const event = disclosure.disclosures.find((d) => d.envelope.chain.seq === 0);
  const epoch = disclosure.anchor.epochs.find((e) => e.epoch_id === 1001);
  assert.ok(event);
  assert.ok(epoch);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          from: ANCHORER,
          to: ANCHORER,
          input: epoch.calldata,
          blockNumber: "0x10",
          hash: epoch.tx_hash,
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  try {
    const result = await verifyReceipt(
      {
        envelope: event.envelope,
        inclusion_proof: {
          leaf: event.envelope_hash,
          leaf_index: event.leaf_index,
          merkle_root: event.proof.root,
          siblings: event.proof.siblings,
        },
        anchor_tx_hash: epoch.tx_hash,
      },
      {
        base_rpc: "https://rpc.invalid",
        recorder_public_key_base64: fixture.key.publicKeyBase64,
        expected_anchorer_address: ANCHORER,
      },
    );
    assert.equal(result.valid, true, JSON.stringify(result));
    assert.equal(result.checks.recorder_signature_verifies, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("trust: shipped JSON matches the runtime pinned constants", async () => {
  const keysDoc = JSON.parse(
    readFileSync(
      new URL("../packages/verify/trust/recorder-keys.json", import.meta.url),
      "utf8",
    ),
  );
  const anchorersDoc = JSON.parse(
    readFileSync(
      new URL("../packages/verify/trust/base-anchorers.json", import.meta.url),
      "utf8",
    ),
  );

  assert.deepEqual(
    keysDoc.keys.map(({ key_id, public_key_base64, active_from, active_until }) => ({
      key_id,
      public_key_base64,
      active_from,
      active_until,
    })),
    PINNED_RECORDER_KEYS,
  );

  const flattened = Object.entries(anchorersDoc.networks).flatMap(
    ([network, entries]) =>
      entries.map((entry) => ({
        network,
        address: entry.address,
        active_from: entry.active_from,
        active_until: entry.active_until,
      })),
  );
  assert.deepEqual(flattened, PINNED_ANCHORERS);
});
