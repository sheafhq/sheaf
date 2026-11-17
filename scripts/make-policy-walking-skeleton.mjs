// Build the Agent Firewall walking skeleton on the hosted recorder, wait for
// the production cron to anchor it on Base mainnet, then export a complete
// Dispute Bundle with the policy attached.
//
// Chain layout:
//   0 policy event (sheaf.policy/1 commitment, first event)
//   1 mandate
//   2 delegation
//   3 consent
//   4 ALLOWED payment ($129, under the $150 cap)
//   5 BLOCKED payment ($200, over the $150 cap; recorded with result "blocked")
//
// Usage: node scripts/make-policy-walking-skeleton.mjs
// Requires: .test-dist/evidence.js, .test-dist/canonical.js, dist-cli/cli.js.

import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { webcrypto } from "node:crypto";

import {
  authorityRef,
  buildEvidenceSubmission,
  signEvidenceDocument,
} from "../.test-dist/evidence.js";
import { hashCanonical } from "../.test-dist/canonical.js";
import { runCli } from "../dist-cli/cli.js";

const BASE = "https://api.sheafhq.io";
const OUT = "test/fixtures/dispute-walking";
const WORK = join(OUT, "policy");
const BUNDLE = join(OUT, "bundle-policy.sheaf");
const ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const { subtle } = webcrypto;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function fetchJson(url, init) {
  const response = await fetch(url, init);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      `${init?.method ?? "GET"} ${url} -> ${response.status}: ${text}`,
    );
  }
  return JSON.parse(text);
}

async function blockForTx(tx) {
  try {
    const response = await fetch("https://mainnet.base.org", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getTransactionReceipt",
        params: [tx],
      }),
    });
    const body = await response.json();
    if (body.result?.blockNumber) {
      return parseInt(body.result.blockNumber, 16);
    }
  } catch {}
  return null;
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

async function toolCall(opts) {
  return {
    v: "arca/1",
    event: {
      kind: "tool_call",
      intent: opts.intent,
      actor: "agent://shopper-7",
      authority: opts.authority,
      tool: "mcp://shop/payment",
      inputs_hash: `sha256:${await hashCanonical(opts.args)}`,
      outputs_hash: opts.result
        ? `sha256:${await hashCanonical(opts.result)}`
        : null,
      result: opts.result ? "ok" : "blocked",
      ts: opts.ts,
      policy: {
        schema: "sheaf.policy/1",
        hash: opts.policyHash,
        verdict: opts.verdict,
        reason_code: opts.reason,
      },
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
  mkdirSync(WORK, { recursive: true });
  mkdirSync(join(WORK, "payloads"), { recursive: true });

  const policy = readJson(join(OUT, "policy.json"));
  const policyHash = `sha256:${await hashCanonical(policy)}`;
  const principal = await makePrincipalKey();

  const baseMandate = readJson("test/fixtures/evidence/mandate.json");
  const baseDelegation = readJson("test/fixtures/evidence/delegation.json");
  const baseConsent = readJson("test/fixtures/evidence/consent.json");
  const signOpts = {
    private_key_pkcs8_base64: principal.privateKeyPkcs8Base64,
    key_id: "demo-policy-principal-1",
    public_key_base64: principal.publicKeyBase64,
  };
  const mandate = await signEvidenceDocument(baseMandate, signOpts);
  const delegation = await signEvidenceDocument(baseDelegation, signOpts);
  const consent = await signEvidenceDocument(baseConsent, signOpts);

  const chainId = `demo-dispute-firewall-${new Date()
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

  // seq 0: policy commitment, first event on the chain
  const policyEvent = {
    v: "arca/1",
    event: {
      kind: "policy",
      intent: "register Agent Firewall policy",
      actor: "payer_demo_001",
      authority: null,
      tool: "sheaf.policy",
      inputs_hash: policyHash,
      outputs_hash: null,
      result: "ok",
      ts: "2026-11-10T16:28:00Z",
      policy: {
        schema: "sheaf.policy/1",
        hash: policyHash,
        verdict: "ALLOW",
        reason_code: "policy_registered",
      },
    },
    chain: { chain_id: chainId, seq: 0, prev_hash: null },
    signatures: { actor: null },
  };
  let receipt = await postEvent(apiKey, policyEvent);
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  // seq 1: mandate
  receipt = await postEvent(
    apiKey,
    await buildEvidenceSubmission(mandate, {
      chain: { chain_id: chainId, seq: 1, prev_hash: prevHash },
      ts: mandate.issued_at,
      authority: null,
    }),
  );
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  // seq 2: delegation
  receipt = await postEvent(
    apiKey,
    await buildEvidenceSubmission(delegation, {
      chain: { chain_id: chainId, seq: 2, prev_hash: prevHash },
      ts: delegation.issued_at,
      authority: authorityRef(chainId, 1),
    }),
  );
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  // seq 3: consent
  receipt = await postEvent(
    apiKey,
    await buildEvidenceSubmission(consent, {
      chain: { chain_id: chainId, seq: 3, prev_hash: prevHash },
      ts: consent.consented_at,
      authority: authorityRef(chainId, 2),
    }),
  );
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

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

  // seq 4: ALLOWED payment
  receipt = await postEvent(
    apiKey,
    await toolCall({
      chainId,
      seq: 4,
      prevHash,
      authority: authorityRef(chainId, 2),
      ts: "2026-11-10T16:42:11Z",
      intent: "authorize payment",
      args: allowedArgs,
      result: allowedResult,
      policyHash,
      verdict: "ALLOW",
      reason: "allowed",
    }),
  );
  receipts.push(receipt);
  prevHash = receipt.envelope_hash;

  // seq 5: BLOCKED payment attempt (recorded, never forwarded)
  receipt = await postEvent(
    apiKey,
    await toolCall({
      chainId,
      seq: 5,
      prevHash,
      authority: authorityRef(chainId, 2),
      ts: "2026-11-10T16:44:00Z",
      intent: "attempt $200 payment (blocked by policy)",
      args: blockedArgs,
      result: null,
      policyHash,
      verdict: "BLOCK",
      reason: "amount_exceeds_limit",
    }),
  );
  receipts.push(receipt);

  console.log(`chain_id=${chainId}`);
  console.log(`events=${receipts.length}`);
  console.log(`policy_hash=${policyHash}`);
  console.log("waiting for cron anchor (up to 40 minutes)...");

  let archive = null;
  const deadline = Date.now() + 40 * 60 * 1000;
  while (Date.now() < deadline) {
    const events = [];
    for (let seq = 0; seq < receipts.length; seq++) {
      events.push(await fetchJson(`${BASE}/events/${chainId}/${seq}`));
    }
    const epochIds = [...new Set(events.map((e) => e.epoch_id))];
    if (epochIds.every((id) => id !== null)) {
      const epochs = [];
      let ready = true;
      for (const epochId of epochIds) {
        const epoch = await fetchJson(`${BASE}/epoch/${epochId}`);
        if (epoch.anchor_tx_hash && epoch.anchor_block === null) {
          epoch.anchor_block = await blockForTx(epoch.anchor_tx_hash);
        }
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
    join(WORK, "mandate.json"),
    JSON.stringify(mandate, null, 2) + "\n",
  );
  writeFileSync(
    join(WORK, "delegation.json"),
    JSON.stringify(delegation, null, 2) + "\n",
  );
  writeFileSync(
    join(WORK, "consent.json"),
    JSON.stringify(consent, null, 2) + "\n",
  );
  writeFileSync(
    join(WORK, "policy.json"),
    JSON.stringify(policy, null, 2) + "\n",
  );
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
      chain_id: chainId,
      recorder: {
        name: "sheaf",
        key_id: "sheaf-ed25519-2026-11-09",
        public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
        public_key_url:
          "https://api.sheafhq.io/.well-known/sheaf-public-key",
      },
      anchorer: ANCHORER,
      network: "eip155:8453",
      created_at: new Date().toISOString(),
    }),
    ...archive.epochs.map((epoch) =>
      JSON.stringify({
        type: "epoch",
        epoch_id: epoch.epoch_id,
        merkle_root: epoch.merkle_root,
        anchor_tx_hash: epoch.anchor_tx_hash,
        anchor_block: epoch.anchor_block,
      }),
    ),
    ...archive.events.map((ev) =>
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
    chain_id: chainId,
    anchorer: ANCHORER,
    anchorer_note:
      "Canonical hosted-recorder anchorer. Labelled demo chain for Agent Firewall.",
    epochs: archive.epochs.map((epoch) => ({
      epoch_id: epoch.epoch_id,
      merkle_root: epoch.merkle_root,
      tx_hash: epoch.anchor_tx_hash,
      block: epoch.anchor_block,
    })),
    event_kinds: archive.events.map((ev) => ({
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

  console.log(`bundle=${BUNDLE}`);
  console.log(`tx=${archive.epochs.map((e) => e.anchor_tx_hash).join(",")}`);
  console.log(`block=${archive.epochs.map((e) => e.anchor_block).join(",")}`);
}

main().catch((err) => {
  console.error(err.stack ?? err.message);
  process.exit(1);
});
