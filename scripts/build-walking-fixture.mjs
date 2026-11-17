// Build the committed walking-skeleton fixture from the real demo chain that
// the hosted recorder anchored on Base mainnet. This script is intentionally
// separate from the chain-creation script so a transient cron timing issue
// does not lose the fixture.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { webcrypto } from "node:crypto";

import { signEvidenceDocument } from "../.test-dist/evidence.js";

const BASE = "https://sheaf-recorder.goldencalf.workers.dev";
const CHAIN = "demo-dispute-walking-20261112t213407z";
const EPOCH = 5;
const TX = "0x847c6b718e7ebc0ef0efae87f74f10bf58c14ba668832896244dee2bb3a8271a";
const BLOCK = 56647675;
const ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const OUT = "test/fixtures/dispute-walking";
const { subtle } = webcrypto;

async function fetchJson(url, init) {
  const r = await fetch(url, init);
  const text = await r.text();
  if (!r.ok) throw new Error(`${url} -> ${r.status}: ${text}`);
  return JSON.parse(text);
}

async function makePrincipalKey() {
  const pair = await subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  return {
    publicKeyBase64: Buffer.from(raw).toString("base64"),
    privateKeyPkcs8Base64: Buffer.from(pkcs8).toString("base64"),
  };
}

async function main() {
  mkdirSync(join(OUT, "payloads"), { recursive: true });

  const events = [];
  for (let seq = 0; seq < 5; seq++) {
    events.push(await fetchJson(`${BASE}/events/${CHAIN}/${seq}`));
  }
  const epoch = await fetchJson(`${BASE}/epoch/${EPOCH}`);
  if (epoch.anchor_tx_hash !== TX) {
    throw new Error(`unexpected anchor tx ${epoch.anchor_tx_hash}`);
  }

  const principal = await makePrincipalKey();
  const mandate = JSON.parse(readFileSync("test/fixtures/evidence/mandate.json", "utf8"));
  const delegation = JSON.parse(readFileSync("test/fixtures/evidence/delegation.json", "utf8"));
  const consent = JSON.parse(readFileSync("test/fixtures/evidence/consent.json", "utf8"));

  const signedMandate = await signEvidenceDocument(mandate, {
    private_key_pkcs8_base64: principal.privateKeyPkcs8Base64,
    key_id: "demo-principal-1",
    public_key_base64: principal.publicKeyBase64,
  });
  const signedDelegation = await signEvidenceDocument(delegation, {
    private_key_pkcs8_base64: principal.privateKeyPkcs8Base64,
    key_id: "demo-principal-1",
    public_key_base64: principal.publicKeyBase64,
  });
  const signedConsent = await signEvidenceDocument(consent, {
    private_key_pkcs8_base64: principal.privateKeyPkcs8Base64,
    key_id: "demo-principal-1",
    public_key_base64: principal.publicKeyBase64,
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

  writeFileSync(join(OUT, "mandate.json"), JSON.stringify(signedMandate, null, 2) + "\n");
  writeFileSync(join(OUT, "delegation.json"), JSON.stringify(signedDelegation, null, 2) + "\n");
  writeFileSync(join(OUT, "consent.json"), JSON.stringify(signedConsent, null, 2) + "\n");
  writeFileSync(join(OUT, "payloads", "3-args.json"), JSON.stringify(args, null, 2) + "\n");
  writeFileSync(join(OUT, "payloads", "3-result.json"), JSON.stringify(result, null, 2) + "\n");
  writeFileSync(join(OUT, "payloads", "4-args.json"), JSON.stringify(trailingArgs, null, 2) + "\n");
  writeFileSync(join(OUT, "payloads", "4-result.json"), JSON.stringify(trailingResult, null, 2) + "\n");

  const recorder = {
    name: "sheaf",
    key_id: "sheaf-ed25519-2026-11-09",
    public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
    public_key_url:
      "https://sheaf-recorder.goldencalf.workers.dev/.well-known/sheaf-public-key",
  };

  const lines = [
    JSON.stringify({
      type: "meta",
      chain_id: CHAIN,
      recorder,
      anchorer: ANCHORER,
      network: "eip155:8453",
      created_at: new Date().toISOString(),
    }),
    JSON.stringify({
      type: "epoch",
      epoch_id: EPOCH,
      merkle_root: epoch.merkle_root,
      anchor_tx_hash: TX,
      anchor_block: BLOCK,
    }),
    ...events.map((ev) =>
      JSON.stringify({
        type: "event",
        seq: ev.envelope.chain.seq,
        envelope: ev.envelope,
        envelope_hash: ev.envelope_hash,
        epoch_id: ev.epoch_id,
        epoch_leaf_idx: ev.epoch_leaf_idx,
      }),
    ),
  ];
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
      created_at: "2026-11-12T22:05:00Z",
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
        root: {
          type: "human",
          id: "payer_demo_001",
          display_name: "A. Rivera (synthetic)",
          attestation: {
            basis: "principal_signature",
            key_id: "demo-principal-1",
            public_key_base64: principal.publicKeyBase64,
            signature_base64: signedMandate.document_signature.signature_base64,
          },
        },
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
  writeFileSync(join(OUT, "case.json"), JSON.stringify(caseManifest, null, 2) + "\n");

  const meta = {
    chain_id: CHAIN,
    anchorer: ANCHORER,
    anchorer_note:
      "The hosted recorder's canonical anchorer. No funded separate demo anchorer key was available; this is a labelled demo chain.",
    epoch_id: EPOCH,
    merkle_root: epoch.merkle_root,
    tx_hash: TX,
    block: BLOCK,
    event_kinds: events.map((ev) => ({
      seq: ev.envelope.chain.seq,
      kind: ev.envelope.event.kind ?? "tool_call",
    })),
  };
  writeFileSync(join(OUT, "meta.json"), JSON.stringify(meta, null, 2) + "\n");

  console.log(`wrote ${OUT}`);
  console.log(`tx=${TX}`);
  console.log(`block=${BLOCK}`);
  console.log(
    `kinds=${meta.event_kinds.map((e) => `${e.seq}:${e.kind}`).join(",")}`,
  );
}

main().catch((err) => {
  console.error(err.stack ?? err.message);
  process.exit(1);
});
