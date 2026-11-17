// Build #3: assembler, verifier, CLI, and browser parity.
//
// Most tests use a local synthetic 5-event archive so they never touch the
// network. The walking-skeleton test uses the real Base-anchored fixture when
// it is present.

import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webcrypto } from "node:crypto";

import {
  authorityRef,
  buildEvidenceSubmission,
  signEvidenceDocument,
} from "../.test-dist/evidence.js";
import { canonicalize, hashCanonical } from "../.test-dist/canonical.js";
import { buildMerkleTree } from "../.test-dist/merkle.js";
import { runCli } from "../dist-cli/cli.js";
import {
  computeDisputeBundleId,
  formatDisputeVerification,
  verifyDisputeBundle,
} from "../packages/verify/dist/index.js";

const { subtle } = webcrypto;
const CHAIN = "dispute-unit-1";
const ANCHORER = "0x1111111111111111111111111111111111111111";
const ZERO = "0".repeat(64);

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function makeKey() {
  const pair = await subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(
    await subtle.exportKey("pkcs8", pair.privateKey),
  );
  return {
    privateKey: pair.privateKey,
    publicKeyBase64: Buffer.from(raw).toString("base64"),
    privateKeyPkcs8Base64: Buffer.from(pkcs8).toString("base64"),
  };
}

async function signCore(privateKey, core) {
  const signature = new Uint8Array(
    await subtle.sign(
      "Ed25519",
      privateKey,
      new TextEncoder().encode(canonicalize(core)),
    ),
  );
  return Buffer.from(signature).toString("base64");
}

async function record(submission, recorderKey) {
  const core = {
    v: submission.v,
    event: submission.event,
    chain: submission.chain,
  };
  return {
    envelope: {
      ...core,
      signatures: {
        actor: submission.signatures.actor,
        recorder: await signCore(recorderKey.privateKey, core),
      },
    },
    envelope_hash: await hashCanonical(core),
  };
}

async function toolCall({
  chainId,
  seq,
  prevHash,
  authority,
  ts,
  intent,
  tool,
  args,
  result,
}) {
  return {
    v: "arca/1",
    event: {
      kind: "tool_call",
      intent,
      actor: "agent://shopper-7",
      authority,
      tool,
      inputs_hash: `sha256:${await hashCanonical(args)}`,
      outputs_hash: `sha256:${await hashCanonical(result)}`,
      result: "ok",
      ts,
    },
    chain: { chain_id: chainId, seq, prev_hash: prevHash },
    signatures: { actor: null },
  };
}

async function captureStdout(fn) {
  const original = process.stdout.write;
  let text = "";
  process.stdout.write = (chunk) => {
    text += String(chunk);
    return true;
  };
  try {
    const code = await fn();
    return { code, text };
  } finally {
    process.stdout.write = original;
  }
}

async function makeLocalBundle() {
  const recorderKey = await makeKey();
  const principalKey = await makeKey();
  const dir = mkdtempSync(join(tmpdir(), "sheaf-dispute-"));
  mkdirSync(join(dir, "payloads"), { recursive: true });

  const mandate = readJson("test/fixtures/evidence/mandate.json");
  const delegation = readJson("test/fixtures/evidence/delegation.json");
  const consent = readJson("test/fixtures/evidence/consent.json");
  const signedMandate = await signEvidenceDocument(mandate, {
    private_key_pkcs8_base64: principalKey.privateKeyPkcs8Base64,
    key_id: "principal-unit-1",
    public_key_base64: principalKey.publicKeyBase64,
  });
  const signedDelegation = await signEvidenceDocument(delegation, {
    private_key_pkcs8_base64: principalKey.privateKeyPkcs8Base64,
    key_id: "principal-unit-1",
    public_key_base64: principalKey.publicKeyBase64,
  });
  const signedConsent = await signEvidenceDocument(consent, {
    private_key_pkcs8_base64: principalKey.privateKeyPkcs8Base64,
    key_id: "principal-unit-1",
    public_key_base64: principalKey.publicKeyBase64,
  });

  const args = {
    merchant: "northwind-outfitters.example",
    amount_minor: 12900,
    currency: "USD",
    order_id: "order_demo_001",
    mandate_id: "mnd_demo_001",
    consent_id: "consent_demo_001",
  };
  const result = {
    status: "authorized",
    order_id: "order_demo_001",
    authorization_ref: "auth_demo_001",
  };
  const trailingArgs = { order_id: "order_demo_001" };
  const trailingResult = { status: "confirmed", order_id: "order_demo_001" };

  const rows = [];
  let prevHash = null;

  const mandateSub = await buildEvidenceSubmission(signedMandate, {
    chain: { chain_id: CHAIN, seq: 0, prev_hash: null },
    ts: signedMandate.issued_at,
    authority: null,
  });
  let rec = await record(mandateSub, recorderKey);
  rows.push(rec);
  prevHash = rec.envelope_hash;

  const delegationSub = await buildEvidenceSubmission(signedDelegation, {
    chain: { chain_id: CHAIN, seq: 1, prev_hash: prevHash },
    ts: signedDelegation.issued_at,
    authority: authorityRef(CHAIN, 0),
  });
  rec = await record(delegationSub, recorderKey);
  rows.push(rec);
  prevHash = rec.envelope_hash;

  const consentSub = await buildEvidenceSubmission(signedConsent, {
    chain: { chain_id: CHAIN, seq: 2, prev_hash: prevHash },
    ts: signedConsent.consented_at,
    authority: authorityRef(CHAIN, 1),
  });
  rec = await record(consentSub, recorderKey);
  rows.push(rec);
  prevHash = rec.envelope_hash;

  const disputedSub = await toolCall({
    chainId: CHAIN,
    seq: 3,
    prevHash,
    authority: authorityRef(CHAIN, 1),
    ts: "2026-11-10T16:42:11Z",
    intent: "authorize payment",
    tool: "mcp://shop/payment",
    args,
    result,
  });
  rec = await record(disputedSub, recorderKey);
  rows.push(rec);
  prevHash = rec.envelope_hash;

  const trailingSub = await toolCall({
    chainId: CHAIN,
    seq: 4,
    prevHash,
    authority: null,
    ts: "2026-11-10T16:43:20Z",
    intent: "check order status",
    tool: "mcp://shop/order",
    args: trailingArgs,
    result: trailingResult,
  });
  rec = await record(trailingSub, recorderKey);
  rows.push(rec);

  const leaves = rows.map((r) => r.envelope_hash);
  const { root } = await buildMerkleTree(leaves);
  const epoch = {
    epoch_id: 0,
    merkle_root: root,
    anchor_tx_hash: "0x" + "a".repeat(64),
    anchor_block: 123456,
  };

  const archiveLines = [
    JSON.stringify({
      type: "meta",
      chain_id: CHAIN,
      recorder: {
        name: "Unit Recorder",
        key_id: "unit-recorder-1",
        public_key_base64: recorderKey.publicKeyBase64,
        public_key_url: "https://should-not-fetch.invalid/key",
      },
      anchorer: ANCHORER,
      network: "eip155:8453",
      created_at: "2026-11-12T21:00:00Z",
    }),
    JSON.stringify({ type: "epoch", ...epoch }),
    ...rows.map((r, idx) =>
      JSON.stringify({
        type: "event",
        seq: idx,
        envelope: r.envelope,
        envelope_hash: r.envelope_hash,
        epoch_id: 0,
        epoch_leaf_idx: idx,
      }),
    ),
  ];

  const caseManifest = {
    case: {
      case_id: "CB-UNIT-001",
      card_network: "visa",
      reason_code: {
        schema: "unit-test",
        value: "10.4",
        label: "unit",
      },
      transaction: {
        reference: "txn_unit_001",
        amount_minor: 12900,
        currency: "USD",
        occurred_at: "2026-11-10T16:42:11Z",
      },
      merchant: {
        id: "merchant_unit",
        name: "Northwind Outfitters (synthetic)",
        url: "https://northwind-outfitters.example",
      },
      response_due_at: "2026-11-24T23:59:59Z",
      dispute_basis: {
        category: "friendly_fraud",
        asserted_by: "merchant",
        merchant_position: "Payer authorized the agent and signed consent.",
      },
      created_at: "2026-11-12T21:00:00Z",
    },
    subject: {
      from_seq: 3,
      to_seq: 4,
      disputed_event_seqs: [3],
      claims: {
        agent_id: {
          value: "agent://shopper-7",
          derived_from: "event.actor",
          ref: "seq:3",
        },
        tool: {
          value: "mcp://shop/payment",
          derived_from: "event.tool",
          ref: "seq:3",
        },
        merchant: {
          value: "northwind-outfitters.example",
          derived_from: "payload",
          ref: "pl_3_args",
          path: "$.merchant",
        },
        amount_minor: {
          value: 12900,
          derived_from: "payload",
          ref: "pl_3_args",
          path: "$.amount_minor",
        },
        currency: {
          value: "USD",
          derived_from: "payload",
          ref: "pl_3_args",
          path: "$.currency",
        },
      },
    },
    evidence: {
      mandate: { seq: 0, document: "mandate.json" },
      delegation: {
        chain: [{ seq: 1, parent_seq: 0, document: "delegation.json" }],
      },
      consent: { seq: 2, document: "consent.json" },
    },
    payloads: [
      { seq: 3, kind: "tool_arguments", path: "payloads/3-args.json" },
      { seq: 3, kind: "tool_result", path: "payloads/3-result.json" },
      { seq: 4, kind: "tool_arguments", path: "payloads/4-args.json" },
      { seq: 4, kind: "tool_result", path: "payloads/4-result.json" },
    ],
  };

  writeFileSync(join(dir, "mandate.json"), JSON.stringify(signedMandate, null, 2));
  writeFileSync(join(dir, "delegation.json"), JSON.stringify(signedDelegation, null, 2));
  writeFileSync(join(dir, "consent.json"), JSON.stringify(signedConsent, null, 2));
  writeFileSync(join(dir, "payloads", "3-args.json"), JSON.stringify(args, null, 2));
  writeFileSync(join(dir, "payloads", "3-result.json"), JSON.stringify(result, null, 2));
  writeFileSync(join(dir, "payloads", "4-args.json"), JSON.stringify(trailingArgs, null, 2));
  writeFileSync(join(dir, "payloads", "4-result.json"), JSON.stringify(trailingResult, null, 2));
  writeFileSync(join(dir, "archive.jsonl"), archiveLines.join("\n") + "\n");
  writeFileSync(join(dir, "case.json"), JSON.stringify(caseManifest, null, 2));

  const trust = {
    recorder_keys: [
      {
        key_id: "unit-recorder-1",
        public_key_base64: recorderKey.publicKeyBase64,
        active_from: "2020-01-01T00:00:00Z",
        active_until: null,
      },
    ],
    anchorers: [{ network: "eip155:8453", address: ANCHORER }],
  };
  writeFileSync(join(dir, "trust.json"), JSON.stringify(trust, null, 2));

  const out = join(dir, "bundle.sheaf");
  const exported = await captureStdout(() =>
    runCli([
      "dispute",
      "export",
      "--archive",
      join(dir, "archive.jsonl"),
      "--case",
      join(dir, "case.json"),
      "--out",
      out,
    ]),
  );
  assert.equal(exported.code, 0, exported.text);
  assert.match(exported.text, /^WROTE /);

  return {
    dir,
    out,
    trustPath: join(dir, "trust.json"),
    bundle: readJson(out),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

async function reseal(bundle) {
  const copy = structuredClone(bundle);
  copy.bundle_id = await computeDisputeBundleId(copy);
  return copy;
}

test("export + offline verify: local archive, zero Sheaf network", async () => {
  const fx = await makeLocalBundle();
  try {
    let calls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      calls += 1;
      throw new Error("offline verify must not fetch");
    };
    try {
      const result = await verifyDisputeBundle(fx.bundle, {
        trust: readJson(fx.trustPath),
      });
      assert.equal(result.valid, true, formatDisputeVerification(result));
      assert.equal(result.complete, true);
      assert.equal(result.anchor_confirmed, false);
      assert.equal(calls, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  } finally {
    fx.cleanup();
  }
});

test("CLI offline exits 3 without --allow-unconfirmed-anchor", async () => {
  const fx = await makeLocalBundle();
  try {
    const without = await captureStdout(() =>
      runCli([
        "dispute",
        "verify",
        fx.out,
        "--offline",
        "--trust",
        fx.trustPath,
      ]),
    );
    assert.equal(without.code, 3);
    assert.match(
      without.text,
      /^VALID \(integrity only; anchor unconfirmed\)/,
    );

    const withFlag = await captureStdout(() =>
      runCli([
        "dispute",
        "verify",
        fx.out,
        "--offline",
        "--trust",
        fx.trustPath,
        "--allow-unconfirmed-anchor",
      ]),
    );
    assert.equal(withFlag.code, 0);
  } finally {
    fx.cleanup();
  }
});

test("--strict refuses placeholders and writes nothing", async () => {
  const fx = await makeLocalBundle();
  try {
    const manifest = readJson(join(fx.dir, "case.json"));
    manifest.case.reason_code.value = "[PLACEHOLDER: reason code]";
    const casePath = join(fx.dir, "case-strict.json");
    writeFileSync(casePath, JSON.stringify(manifest, null, 2));
    const out = join(fx.dir, "strict.sheaf");
    await assert.rejects(
      () =>
        runCli([
          "dispute",
          "export",
          "--archive",
          join(fx.dir, "archive.jsonl"),
          "--case",
          casePath,
          "--out",
          out,
          "--self-check",
          "--offline",
          "--strict",
        ]),
      /placeholders remain/,
    );
    assert.equal(existsSync(out), false);
  } finally {
    fx.cleanup();
  }
});

test("--strict refuses absent evidence and writes nothing", async () => {
  const fx = await makeLocalBundle();
  try {
    const manifest = readJson(join(fx.dir, "case.json"));
    manifest.evidence.consent = { status: "absent" };
    const casePath = join(fx.dir, "case-no-consent.json");
    writeFileSync(casePath, JSON.stringify(manifest, null, 2));
    const out = join(fx.dir, "strict-no-consent.sheaf");
    await assert.rejects(
      () =>
        runCli([
          "dispute",
          "export",
          "--archive",
          join(fx.dir, "archive.jsonl"),
          "--case",
          casePath,
          "--out",
          out,
          "--self-check",
          "--offline",
          "--strict",
          "--trust",
          fx.trustPath,
        ]),
      /completeness is not complete/,
    );
    assert.equal(existsSync(out), false);
  } finally {
    fx.cleanup();
  }
});

test("bundle_id: mutation in every sealed section is caught", async () => {
  const fx = await makeLocalBundle();
  try {
    const mutations = {
      case: (b) => { b.case.case_id = "CB-MUTATED"; },
      subject: (b) => { b.subject.claims.agent_id.value = "agent://mutated"; },
      disclosures: (b) => { b.disclosures[0].envelope.event.intent = "mutated"; },
      evidence: (b) => { b.evidence.mandate.document_hash = ZERO; },
      anchor: (b) => { b.anchor.epochs[0].merkle_root = ZERO; },
      payloads: (b) => { b.payloads[0].content.amount_minor = 1; },
      presentation: (b) => { b.presentation.title = "mutated"; },
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const copy = structuredClone(fx.bundle);
      mutate(copy);
      const result = await verifyDisputeBundle(copy, {
        trust: readJson(fx.trustPath),
      });
      assert.equal(result.valid, false, `${name} should fail`);
      assert.equal(result.code, "BUNDLE_ID_MISMATCH", `${name}`);
      assert.equal(result.checks[1].code, "BUNDLE_ID_MISMATCH", `${name}`);
    }
  } finally {
    fx.cleanup();
  }
});

test("valid_partial: consent removed yields evidence_gaps [consent]", async () => {
  const fx = await makeLocalBundle();
  try {
    const copy = structuredClone(fx.bundle);
    copy.evidence.consent = {
      status: "absent",
      event_ref: null,
      document: null,
      document_hash: null,
      document_signature: null,
      authorization_basis: null,
      consent_type: null,
      captured_at: null,
      artifact: null,
    };
    const resealed = await reseal(copy);
    const result = await verifyDisputeBundle(resealed, {
      trust: readJson(fx.trustPath),
    });
    assert.equal(result.valid, true, formatDisputeVerification(result));
    assert.equal(result.complete, false);
    assert.deepEqual(result.evidence_gaps, ["consent"]);
    assert.equal(
      formatDisputeVerification({ ...result, anchor_confirmed: true }).split(
        "\n",
      )[0],
      "VALID (partial)",
    );
  } finally {
    fx.cleanup();
  }
});

test("valid_partial: delegation signed, mandate recorder-observed", async () => {
  const fx = await makeLocalBundle();
  try {
    const copy = structuredClone(fx.bundle);
    delete copy.evidence.mandate.document.document_signature;
    copy.evidence.mandate.document_signature = null;
    copy.evidence.mandate.authorization_basis = "recorder_observed";
    const resealed = await reseal(copy);
    const result = await verifyDisputeBundle(resealed, {
      trust: readJson(fx.trustPath),
    });
    assert.equal(result.valid, true, formatDisputeVerification(result));
    assert.equal(result.complete, false);
    assert.ok(result.evidence_gaps.includes("mandate_signature"));
    assert.equal(
      formatDisputeVerification({ ...result, anchor_confirmed: true }).split(
        "\n",
      )[0],
      "VALID (partial)",
    );
  } finally {
    fx.cleanup();
  }
});

test("DELEGATION_PARENT_MISMATCH is a hard failure", async () => {
  const fx = await makeLocalBundle();
  try {
    const copy = structuredClone(fx.bundle);
    copy.evidence.delegation.chain[0].parent_event_ref.seq = 2;
    const resealed = await reseal(copy);
    const result = await verifyDisputeBundle(resealed, {
      trust: readJson(fx.trustPath),
    });
    assert.equal(result.valid, false);
    assert.equal(result.code, "DELEGATION_PARENT_MISMATCH");
    assert.equal(result.checks[8].ok, false);
  } finally {
    fx.cleanup();
  }
});

test("walking skeleton: real Base anchor verifies offline and online", async () => {
  const path = "test/fixtures/dispute-walking/bundle.sheaf";
  assert.ok(existsSync(path), `missing ${path}`);
  const bundle = readJson(path);

  assert.equal(bundle.schema, "sheaf.dispute-bundle/1");
  assert.equal(
    bundle.anchor.epochs[0].tx_hash,
    "0x847c6b718e7ebc0ef0efae87f74f10bf58c14ba668832896244dee2bb3a8271a",
  );
  assert.equal(bundle.anchor.epochs[0].block_number, 56647675);
  assert.deepEqual(
    bundle.disclosures.map((d) => [
      d.envelope.chain.seq,
      d.envelope.event.kind ?? "tool_call",
    ]),
    [
      [0, "mandate"],
      [1, "delegation"],
      [2, "consent"],
      [3, "tool_call"],
      [4, "tool_call"],
    ],
  );

  const offline = await verifyDisputeBundle(bundle);
  assert.equal(offline.valid, true, formatDisputeVerification(offline));
  assert.equal(offline.complete, true);
  assert.equal(offline.anchor_confirmed, false);
  assert.deepEqual(offline.evidence_gaps, []);
  assert.equal(offline.checks.length, 14);
  assert.deepEqual(
    offline.checks.map((c) => c.name),
    [
      "schema_supported",
      "bundle_id_matches",
      "selection_contiguous",
      "chain_links",
      "disclosure_signatures_and_proofs",
      "anchor_roots_match",
      "payload_hashes_match",
      "mandate_evidence",
      "delegation_authority",
      "consent_evidence",
      "temporal_order",
      "anchor_on_base",
      "completeness",
      "policy_enforced",
    ],
  );

  const online = await verifyDisputeBundle(bundle, {
    base_rpc: "https://mainnet.base.org",
  });
  assert.equal(online.valid, true, formatDisputeVerification(online));
  assert.equal(online.complete, true);
  assert.equal(online.anchor_confirmed, true);
  assert.equal(online.checks[11].ok, true);
});

test("firewall walking skeleton: 14/14 with policy_enforced", async () => {
  const path = "test/fixtures/dispute-walking/bundle-policy.sheaf";
  assert.ok(existsSync(path), `missing ${path}`);
  const bundle = readJson(path);

  assert.equal(
    bundle.anchor.epochs[0].tx_hash,
    "0x9862358bd78c6c09ede9550ebb2d159b0f1ad37773eff8735cdb2784a7280575",
  );
  assert.equal(bundle.anchor.epochs[0].block_number, 57016675);
  assert.equal(bundle.policy.schema, "sheaf.policy/1");
  assert.equal(bundle.policy.document.policy_id, "demo-agent-payments-001");
  assert.deepEqual(
    bundle.disclosures.map((d) => [
      d.envelope.chain.seq,
      d.envelope.event.kind ?? "tool_call",
      d.envelope.event.result,
      d.envelope.event.policy?.verdict ?? null,
    ]),
    [
      [1, "mandate", "ok", null],
      [2, "delegation", "ok", null],
      [3, "consent", "ok", null],
      [4, "tool_call", "ok", "ALLOW"],
      [5, "tool_call", "blocked", "BLOCK"],
    ],
  );

  const result = await verifyDisputeBundle(bundle, {
    base_rpc: "https://mainnet.base.org",
  });
  assert.equal(result.valid, true, formatDisputeVerification(result));
  assert.equal(result.complete, true);
  assert.equal(result.checks.length, 14);
  assert.ok(result.checks.every((check) => check.ok === true));
  assert.equal(result.checks[13].name, "policy_enforced");
  assert.equal(result.checks[13].ok, true);
});

test("network boundary: online dispute mode only contacts the supplied RPC", async () => {
  const fx = await makeLocalBundle();
  try {
    const originalFetch = globalThis.fetch;
    const hosts = [];
    globalThis.fetch = async (url, init) => {
      hosts.push(new URL(String(url)).host);
      const body = JSON.parse(String(init?.body ?? "{}"));
      if (body.method === "eth_chainId") {
        return new Response(
          JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x2105" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      const epoch = fx.bundle.anchor.epochs[0];
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            from: ANCHORER,
            to: ANCHORER,
            input: epoch.calldata,
            blockNumber: "0x" + Number(epoch.block_number).toString(16),
            hash: epoch.tx_hash,
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };
    try {
      const result = await verifyDisputeBundle(fx.bundle, {
        trust: readJson(fx.trustPath),
        base_rpc: "https://rpc.invalid",
      });
      assert.equal(result.valid, true, formatDisputeVerification(result));
      assert.equal(result.anchor_confirmed, true);
      assert.deepEqual([...new Set(hosts)], ["rpc.invalid"]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  } finally {
    fx.cleanup();
  }
});
