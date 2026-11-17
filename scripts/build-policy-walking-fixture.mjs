// Build the committed Agent Firewall fixture from the real demo chain that the
// hosted recorder anchored on Base mainnet (epoch 11).
//
// The hosted Worker exposes anchor_tx_hash but leaves anchor_block null until a
// separate confirmation pass, so the block is read from the Base receipt here.

import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { webcrypto } from "node:crypto";

import {
  buildEvidenceSubmission,
  signEvidenceDocument,
} from "../.test-dist/evidence.js";
import { hashCanonical } from "../.test-dist/canonical.js";
import { runCli } from "../dist-cli/cli.js";
import {
  formatDisputeVerification,
  verifyDisputeBundle,
} from "../packages/verify/dist/index.js";

const BASE = "https://api.sheafhq.io";
const CHAIN = "demo-dispute-firewall-20261113t180116z";
const EPOCH = 11;
const TX = "0x9862358bd78c6c09ede9550ebb2d159b0f1ad37773eff8735cdb2784a7280575";
const BLOCK = 57016675;
const OUT = "test/fixtures/dispute-walking";
const WORK = join(OUT, "policy");
const BUNDLE = join(OUT, "bundle-policy.sheaf");
const { subtle } = webcrypto;

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function fetchJson(url) {
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) throw new Error(`GET ${url} -> ${response.status}: ${text}`);
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
  mkdirSync(join(WORK, "payloads"), { recursive: true });

  const events = [];
  for (let seq = 0; seq < 6; seq++) {
    events.push(await fetchJson(`${BASE}/events/${CHAIN}/${seq}`));
  }
  const epoch = await fetchJson(`${BASE}/epoch/${EPOCH}`);
  if (epoch.anchor_tx_hash !== TX) {
    throw new Error(`unexpected anchor tx ${epoch.anchor_tx_hash}`);
  }

  const principal = await makePrincipalKey();
  const signOpts = {
    private_key_pkcs8_base64: principal.privateKeyPkcs8Base64,
    key_id: "demo-policy-principal-1",
    public_key_base64: principal.publicKeyBase64,
  };
  const mandate = await signEvidenceDocument(
    readJson("test/fixtures/evidence/mandate.json"),
    signOpts,
  );
  const delegation = await signEvidenceDocument(
    readJson("test/fixtures/evidence/delegation.json"),
    signOpts,
  );
  const consent = await signEvidenceDocument(
    readJson("test/fixtures/evidence/consent.json"),
    signOpts,
  );
  const policy = readJson(join(OUT, "policy.json"));

  writeFileSync(join(WORK, "mandate.json"), JSON.stringify(mandate, null, 2) + "\n");
  writeFileSync(
    join(WORK, "delegation.json"),
    JSON.stringify(delegation, null, 2) + "\n",
  );
  writeFileSync(join(WORK, "consent.json"), JSON.stringify(consent, null, 2) + "\n");
  writeFileSync(join(WORK, "policy.json"), JSON.stringify(policy, null, 2) + "\n");

  const allowedArgs = {
    merchant: "northwind-outfitters.example",
    amount_minor: 12900,
    currency: "USD",
    order_id: "order_demo_001",
    mandate_id: "mnd_demo_001",
    consent_id: "consent_demo_001",
  };
  const allowedResult = {
    status: "authorized",
    order_id: "order_demo_001",
    authorization_ref: "auth_demo_001",
  };
  const blockedArgs = {
    ...allowedArgs,
    amount_minor: 20000,
    order_id: "order_demo_blocked_001",
  };
  writeFileSync(
    join(WORK, "payloads", "4-args.json"),
    JSON.stringify(allowedArgs, null, 2) + "\n",
  );
  writeFileSync(
    join(WORK, "payloads", "4-result.json"),
    JSON.stringify(allowedResult, null, 2) + "\n",
  );
  writeFileSync(
    join(WORK, "payloads", "5-args-blocked.json"),
    JSON.stringify(blockedArgs, null, 2) + "\n",
  );

  const lines = [
    JSON.stringify({
      type: "meta",
      chain_id: CHAIN,
      recorder: {
        name: "sheaf",
        key_id: "sheaf-ed25519-2026-11-09",
        public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
        public_key_url: "https://api.sheafhq.io/.well-known/sheaf-public-key",
      },
      anchorer: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
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
  writeFileSync(join(WORK, "events.jsonl"), lines.join("\n") + "\n");

  const caseManifest = {
    case: {
      case_id: "CB-DEMO-FIREWALL-001",
      card_network: "visa",
      reason_code: {
        schema: "2026 Visa Claims Resolution guide",
        value: "10.4",
        label: "Other fraud — card-absent environment",
      },
      transaction: {
        reference: "txn_demo_firewall_001",
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
          "The $129 payment was within the signed mandate and policy. The agent later attempted a $200 payment; the policy blocked it before execution and recorded the violation.",
      },
      created_at: "2026-11-13T18:00:00Z",
    },
    subject: {
      from_seq: 4,
      to_seq: 5,
      disputed_event_seqs: [4],
      claims: {
        agent_id: {
          value: "agent://shopper-7",
          derived_from: "event.actor",
          ref: "seq:4",
        },
        tool: {
          value: "mcp://shop/payment",
          derived_from: "event.tool",
          ref: "seq:4",
        },
        merchant: {
          value: "northwind-outfitters.example",
          derived_from: "payload",
          ref: "pl_4_args",
          path: "$.merchant",
        },
        amount_minor: {
          value: 12900,
          derived_from: "payload",
          ref: "pl_4_args",
          path: "$.amount_minor",
        },
        currency: {
          value: "USD",
          derived_from: "payload",
          ref: "pl_4_args",
          path: "$.currency",
        },
      },
    },
    evidence: {
      mandate: { seq: 1, document: "mandate.json" },
      delegation: {
        root: {
          type: "human",
          id: "payer_demo_001",
          display_name: "A. Rivera (synthetic)",
          attestation: {
            basis: "principal_signature",
            key_id: "demo-policy-principal-1",
            public_key_base64: principal.publicKeyBase64,
            signature_base64: mandate.document_signature.signature_base64,
          },
        },
        chain: [{ seq: 2, parent_seq: 1, document: "delegation.json" }],
      },
      consent: { seq: 3, document: "consent.json" },
    },
    payloads: [
      { seq: 4, kind: "tool_arguments", path: "payloads/4-args.json" },
      { seq: 4, kind: "tool_result", path: "payloads/4-result.json" },
      { seq: 5, kind: "tool_arguments", path: "payloads/5-args-blocked.json" },
    ],
  };
  writeFileSync(
    join(WORK, "case.json"),
    JSON.stringify(caseManifest, null, 2) + "\n",
  );

  const meta = {
    chain_id: CHAIN,
    anchorer: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
    anchorer_note:
      "Canonical hosted-recorder anchorer. Labelled demo chain for Agent Firewall.",
    epoch_id: EPOCH,
    merkle_root: epoch.merkle_root,
    tx_hash: TX,
    block: BLOCK,
    event_kinds: events.map((ev) => ({
      seq: ev.envelope.chain.seq,
      kind: ev.envelope.event.kind ?? "tool_call",
      result: ev.envelope.event.result,
      policy_verdict: ev.envelope.event.policy?.verdict ?? null,
    })),
  };
  writeFileSync(join(WORK, "meta.json"), JSON.stringify(meta, null, 2) + "\n");

  const exportCode = await runCli([
    "dispute",
    "export",
    "--archive",
    join(WORK, "events.jsonl"),
    "--case",
    join(WORK, "case.json"),
    "--out",
    BUNDLE,
    "--policy",
    join(OUT, "policy.json"),
    "--self-check",
    "--strict",
    "--rpc",
    "https://mainnet.base.org",
  ]);
  if (exportCode !== 0) throw new Error(`export failed with code ${exportCode}`);

  const bundle = JSON.parse(readFileSync(BUNDLE, "utf8"));
  const verified = await verifyDisputeBundle(bundle, {
    base_rpc: "https://mainnet.base.org",
  });
  console.log(formatDisputeVerification(verified));
  console.log(`bundle_id=${verified.bundle_id}`);
  console.log(
    `checks=${verified.checks.filter((c) => c.ok === true).length}/${verified.checks.length}`,
  );
  console.log(`policy_enforced=${verified.checks[13].ok}`);
  if (!verified.valid || !verified.complete || verified.checks.some((c) => c.ok !== true)) {
    throw new Error("bundle is not complete with all checks passing");
  }
  console.log(`bundle=${BUNDLE}`);
  console.log(`tx=${TX}`);
  console.log(`block=${BLOCK}`);
}

main().catch((err) => {
  console.error(err.stack ?? err.message);
  process.exit(1);
});
