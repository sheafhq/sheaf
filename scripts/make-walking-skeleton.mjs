// Build a real 5-event demo chain on the hosted recorder, wait for the
// production cron to anchor it on Base mainnet, and write a local archive.
//
// The chain is a labelled demo chain. It uses the recorder's canonical
// anchorer because no funded demo anchorer key is available in this
// environment; the bundle reports that address explicitly.
//
// Usage: node scripts/make-walking-skeleton.mjs
// Requires: .test-dist/evidence.js and .test-dist/canonical.js built.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  authorityRef,
  buildEvidenceSubmission,
} from "../.test-dist/evidence.js";
import { hashCanonical } from "../.test-dist/canonical.js";

const BASE = "https://sheaf-recorder.goldencalf.workers.dev";
const OUT = "test/fixtures/dispute-walking";
const ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const RECORDER = {
  name: "sheaf",
  key_id: "sheaf-ed25519-2026-11-09",
  public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
  public_key_url:
    "https://sheaf-recorder.goldencalf.workers.dev/.well-known/sheaf-public-key",
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function fetchJson(url, init) {
  const response = await fetch(url, init);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${init?.method ?? "GET"} ${url} -> ${response.status}: ${text}`);
  }
  return JSON.parse(text);
}

async function postEvent(apiKey, submission) {
  return fetchJson(`${BASE}/events`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(submission),
  });
}

// hashCanonical is async; resolve the payload hashes before constructing the
// submission.
async function buildToolCall(opts) {
  return {
    v: "arca/1",
    event: {
      kind: "tool_call",
      intent: opts.intent,
      actor: "agent://shopper-7",
      authority: opts.authority,
      tool: opts.tool,
      inputs_hash: `sha256:${await hashCanonical(opts.args)}`,
      outputs_hash: `sha256:${await hashCanonical(opts.result)}`,
      result: "ok",
      ts: opts.ts,
    },
    chain: {
      chain_id: opts.chainId,
      seq: opts.seq,
      prev_hash: opts.prevHash,
    },
    signatures: { actor: null },
  };
}

async function main() {
  mkdirSync(join(OUT, "payloads"), { recursive: true });

  const mandate = readJson("test/fixtures/evidence/mandate.json");
  const delegation = readJson("test/fixtures/evidence/delegation.json");
  const consent = readJson("test/fixtures/evidence/consent.json");

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

  const chainId = `demo-dispute-walking-${new Date()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\..+$/, "Z")
    .toLowerCase()}`;

  const account = await fetchJson(`${BASE}/accounts`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  const apiKey = account.api_key;
  if (!apiKey) throw new Error("no api_key returned by POST /accounts");

  let prevHash = null;
  const receipts = [];

  const mandateSub = await buildEvidenceSubmission(mandate, {
    chain: { chain_id: chainId, seq: 0, prev_hash: null },
    ts: mandate.issued_at,
    authority: null,
  });
  let receipt = await postEvent(apiKey, mandateSub);
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  const delegationSub = await buildEvidenceSubmission(delegation, {
    chain: { chain_id: chainId, seq: 1, prev_hash: prevHash },
    ts: delegation.issued_at,
    authority: authorityRef(chainId, 0),
  });
  receipt = await postEvent(apiKey, delegationSub);
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  const consentSub = await buildEvidenceSubmission(consent, {
    chain: { chain_id: chainId, seq: 2, prev_hash: prevHash },
    ts: consent.consented_at,
    authority: authorityRef(chainId, 1),
  });
  receipt = await postEvent(apiKey, consentSub);
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  const disputedSub = await buildToolCall({
    chainId,
    seq: 3,
    prevHash,
    authority: authorityRef(chainId, 1),
    ts: "2026-11-10T16:42:11Z",
    intent: "authorize payment",
    tool: "mcp://shop/payment",
    args,
    result,
  });
  receipt = await postEvent(apiKey, disputedSub);
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  const trailingSub = await buildToolCall({
    chainId,
    seq: 4,
    prevHash,
    authority: null,
    ts: "2026-11-10T16:43:20Z",
    intent: "check order status",
    tool: "mcp://shop/order",
    args: trailingArgs,
    result: trailingResult,
  });
  receipt = await postEvent(apiKey, trailingSub);
  receipts.push(receipt);

  console.log(`chain_id=${chainId}`);
  console.log(`events=${receipts.length}`);
  console.log("waiting for cron anchor (up to 30 minutes)...");

  let archive = null;
  const deadline = Date.now() + 30 * 60 * 1000;
  while (Date.now() < deadline) {
    const events = [];
    for (let seq = 0; seq < receipts.length; seq++) {
      const ev = await fetchJson(`${BASE}/events/${chainId}/${seq}`);
      events.push(ev);
    }
    const epochIds = [...new Set(events.map((e) => e.epoch_id))];
    if (epochIds.every((id) => id !== null)) {
      const epochs = [];
      let ready = true;
      for (const epochId of epochIds) {
        const epoch = await fetchJson(`${BASE}/epoch/${epochId}`);
        epochs.push(epoch);
        if (!epoch.anchor_tx_hash || epoch.anchor_block === null) ready = false;
      }
      if (ready) {
        archive = { chainId, events, epochs };
        break;
      }
    }
    await sleep(20_000);
  }

  if (!archive) throw new Error("timed out waiting for anchor");

  writeFileSync(
    join(OUT, "mandate.json"),
    JSON.stringify(mandate, null, 2) + "\n",
  );
  writeFileSync(
    join(OUT, "delegation.json"),
    JSON.stringify(delegation, null, 2) + "\n",
  );
  writeFileSync(
    join(OUT, "consent.json"),
    JSON.stringify(consent, null, 2) + "\n",
  );
  writeFileSync(
    join(OUT, "payloads", "3-args.json"),
    JSON.stringify(args, null, 2) + "\n",
  );
  writeFileSync(
    join(OUT, "payloads", "3-result.json"),
    JSON.stringify(result, null, 2) + "\n",
  );
  writeFileSync(
    join(OUT, "payloads", "4-args.json"),
    JSON.stringify(trailingArgs, null, 2) + "\n",
  );
  writeFileSync(
    join(OUT, "payloads", "4-result.json"),
    JSON.stringify(trailingResult, null, 2) + "\n",
  );

  const lines = [];
  lines.push(
    JSON.stringify({
      type: "meta",
      chain_id: chainId,
      recorder: RECORDER,
      anchorer: ANCHORER,
      network: "eip155:8453",
      created_at: new Date().toISOString(),
    }),
  );
  for (const epoch of archive.epochs) {
    lines.push(
      JSON.stringify({
        type: "epoch",
        epoch_id: epoch.epoch_id,
        merkle_root: epoch.merkle_root,
        anchor_tx_hash: epoch.anchor_tx_hash,
        anchor_block: epoch.anchor_block,
      }),
    );
  }
  for (const ev of archive.events) {
    lines.push(
      JSON.stringify({
        type: "event",
        seq: ev.envelope.chain.seq,
        envelope: ev.envelope,
        envelope_hash: ev.envelope_hash,
        epoch_id: ev.epoch_id,
        epoch_leaf_idx: ev.epoch_leaf_idx,
      }),
    );
  }
  writeFileSync(join(OUT, "events.jsonl"), lines.join("\n") + "\n");

  const caseManifest = {
    case: {
      case_id: "CB-DEMO-WALK-001",
      card_network: "[PLACEHOLDER: card network]",
      reason_code: {
        schema: "[PLACEHOLDER: 2026 Visa Claims Resolution guide]",
        value: "[PLACEHOLDER: reason code]",
        label: null,
      },
      transaction: {
        reference: "txn_demo_001",
        amount_minor: 12900,
        currency: "USD",
        occurred_at: "2026-11-10T16:42:11Z",
      },
      merchant: {
        id: "merchant_demo_001",
        name: "Northwind Outfitters (synthetic)",
        url: "https://northwind-outfitters.example",
      },
      response_due_at: "2026-11-24T23:59:59Z",
      dispute_basis: {
        category: "friendly_fraud",
        asserted_by: "merchant",
        merchant_position:
          "The payer authorized this agent and signed the consent receipt before checkout.",
      },
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
  writeFileSync(
    join(OUT, "case.json"),
    JSON.stringify(caseManifest, null, 2) + "\n",
  );

  const meta = {
    chain_id: chainId,
    anchorer: ANCHORER,
    anchorer_note:
      "Canonical hosted-recorder anchorer. No funded separate demo anchorer key was available; the chain is labelled as a demo.",
    epochs: archive.epochs.map((e) => ({
      epoch_id: e.epoch_id,
      merkle_root: e.merkle_root,
      tx_hash: e.anchor_tx_hash,
      block: e.anchor_block,
    })),
    event_kinds: archive.events.map((e) => ({
      seq: e.envelope.chain.seq,
      kind: e.envelope.event.kind ?? "tool_call",
    })),
  };
  writeFileSync(join(OUT, "meta.json"), JSON.stringify(meta, null, 2) + "\n");

  console.log(`archive=${join(OUT, "events.jsonl")}`);
  console.log(`tx=${archive.epochs.map((e) => e.anchor_tx_hash).join(",")}`);
  console.log(`block=${archive.epochs.map((e) => e.anchor_block).join(",")}`);
}

main().catch((err) => {
  console.error(err.stack ?? err.message);
  process.exit(1);
});
