// S2 regression tests: subject.claims are the bundle author's statements and
// must never stand in for the signed data they cite.
//
// Before S2, check 8 (mandate_evidence) compared the mandate scope with the
// VALUES written in subject.claims. A bundle author could understate or omit
// the amount and the verifier reported the mandate as covering a transaction
// whose signed payload exceeded the cap. See CHANGELOG "SECURITY (S2)".

import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { LocalLedger } from "../packages/mcp-recorder/dist/local.js";
import { hashCanonical } from "../packages/mcp-recorder/dist/canonical.js";
import { runCli } from "../dist-cli/cli.js";
import {
  computeDisputeBundleId,
  formatDisputeVerification,
  verifyDisputeBundle,
} from "../packages/verify/dist/index.js";

const WALKING = "test/fixtures/dispute-walking/bundle.sheaf";

async function capture(fn) {
  const out = process.stdout.write;
  const err = process.stderr.write;
  let stdout = "";
  let stderr = "";
  process.stdout.write = (c) => ((stdout += String(c)), true);
  process.stderr.write = (c) => ((stderr += String(c)), true);
  try {
    return { code: await fn(), stdout, stderr };
  } catch (err) {
    // The CLI's fail() throws; bin/sheaf turns that into exit code 1.
    return { code: 1, stdout, stderr: stderr + String(err?.message ?? err) };
  } finally {
    process.stdout.write = out;
    process.stderr.write = err;
  }
}

function claimsFor(seq, amountClaim, extra = {}) {
  const claims = {
    agent_id: { value: "agent://shopper-7", derived_from: "event.actor", ref: `seq:${seq}` },
    tool: { value: "mcp://shop/payment", derived_from: "event.tool", ref: `seq:${seq}` },
    merchant: { value: "northwind-outfitters.example", derived_from: "payload", ref: `pl_${seq}_args`, path: "$.merchant" },
    currency: { value: "USD", derived_from: "payload", ref: `pl_${seq}_args`, path: "$.currency" },
    ...extra,
  };
  if (amountClaim !== undefined) claims.amount_minor = amountClaim;
  return claims;
}

/**
 * A real local ledger: mandate (cap 15000 USD), delegation, consent, then ONE
 * recorder-signed payment whose arguments say `signedAmount`. The firewall
 * policy allows up to 50000 (policy and mandate are different documents).
 * The case file carries `claims` exactly as an author would write them; the
 * normal `sheaf local export` builds the bundle.
 */
async function exportLocalCase(dir, signedAmount, claims) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const name of ["mandate", "delegation", "consent"]) {
    const doc = JSON.parse(readFileSync(`test/fixtures/evidence/${name}.json`, "utf8"));
    if (doc.scope) {
      doc.scope.valid_until = "2027-11-11T16:30:00Z";
      doc.expires_at = "2027-11-11T16:30:00Z";
    }
    writeFileSync(join(dir, `${name}.json`), JSON.stringify(doc, null, 2));
  }
  assert.equal(JSON.parse(readFileSync(join(dir, "mandate.json"), "utf8")).scope.amount_max_minor, 15000);

  const policy = JSON.parse(readFileSync("test/fixtures/dispute-walking/policy.json", "utf8"));
  policy.rules[0].constraints[0].value = 50000;
  const policyHash = "sha256:" + hashCanonical(policy);
  const args = {
    merchant: "northwind-outfitters.example",
    amount_minor: signedAmount,
    currency: "USD",
    order_id: "order_s2_001",
    mandate_id: "mnd_demo_001",
    consent_id: "consent_demo_001",
  };
  const casePath = join(dir, "case.json");
  writeFileSync(
    casePath,
    JSON.stringify({
      case: {
        case_id: "CB-S2-001",
        card_network: "visa",
        reason_code: { schema: "2026 Visa Claims Resolution guide", value: "10.4", label: "Other fraud" },
        transaction: { reference: "txn_s2", amount_minor: 12900, currency: "USD", occurred_at: new Date().toISOString() },
        merchant: { id: "merchant_local", name: "Northwind Outfitters", url: "https://northwind-outfitters.example" },
        response_due_at: "2026-11-24T23:59:59Z",
        dispute_basis: { category: "friendly_fraud", asserted_by: "merchant", merchant_position: "S2 test." },
        created_at: new Date(Date.now() + 60_000).toISOString(),
      },
      subject: { from_seq: 4, to_seq: 4, disputed_event_seqs: [4], claims },
      evidence: {
        mandate: { seq: 1, document: "mandate.json" },
        delegation: { chain: [{ seq: 2, parent_seq: 1, document: "delegation.json" }] },
        consent: { seq: 3, document: "consent.json" },
      },
      payloads: [
        { seq: 4, kind: "tool_arguments", path: ".sheaf/payloads/000004-arguments.json" },
        { seq: 4, kind: "tool_result", path: ".sheaf/payloads/000004-result.json" },
      ],
    }, null, 2),
  );
  const chainDir = join(dir, ".sheaf");
  const ledger = new LocalLedger({
    recorderUrls: [],
    chainId: "s2-test",
    actor: "local-user",
    captureMethods: new Set(),
    logDebug: false,
    policy,
    policyHash,
    local: { chainDir, casePath, actor: "local-user" },
  });
  ledger.submit(
    {
      id: 1,
      method: "tools/call",
      params: { name: "mcp://shop/payment", arguments: args },
      startedAt: Date.now(),
      policy: { schema: "sheaf.policy/1", hash: policyHash, verdict: "ALLOW", reason_code: "allowed" },
    },
    { result: { status: "authorized" } },
  );
  await ledger.drain();

  // 1. The normal tool. `sheaf local export` self-checks with the verifier,
  //    so after S2 it refuses to write a bundle whose claims lie.
  const out = join(dir, "bundle.sheaf");
  const localExport = await capture(() =>
    runCli(["local", "export", "--chain-dir", chainDir, "--case", casePath, "--out", out]),
  );
  // 2. The attacker's path: the same prepared inputs through
  //    `sheaf dispute export` WITHOUT --self-check, which writes whatever the
  //    author asked for. This is the bundle a relying party would receive.
  const attackerOut = join(dir, "attacker.sheaf");
  const attackerExport = await capture(() =>
    runCli([
      "dispute", "export",
      "--archive", join(chainDir, "export-archive.jsonl"),
      "--case", join(chainDir, "export-case.json"),
      "--policy", join(chainDir, "policy.json"),
      "--out", attackerOut,
    ]),
  );
  assert.equal(attackerExport.code, 0, attackerExport.stdout + attackerExport.stderr);
  const bundle = JSON.parse(readFileSync(attackerOut, "utf8"));
  const trust = JSON.parse(readFileSync(join(chainDir, "trust.json"), "utf8"));
  const result = await verifyDisputeBundle(bundle, { trust });
  return { localExport, bundle, trust, result, text: formatDisputeVerification(result), dir };
}

async function verifyMutated(mutate) {
  const bundle = JSON.parse(readFileSync(WALKING, "utf8"));
  mutate(bundle);
  bundle.bundle_id = await computeDisputeBundleId(bundle);
  const result = await verifyDisputeBundle(bundle);
  return { result, text: formatDisputeVerification(result) };
}

const step = (result, n) => result.checks.find((c) => c.step === n);

// ------------------------------------------------------------------ tests ---

test("S2 vulnerability: understated subject.claims over a higher SIGNED payload now fails", async (t) => {
  const { localExport, bundle, result, text, dir } = await exportLocalCase("test/tmp-s2-understated", 20000, claimsFor(4, {
    value: 12900, derived_from: "payload", ref: "pl_4_args", path: "$.amount_minor",
  }));
  try {
    // The normal export tool now refuses to write it ...
    assert.notEqual(localExport.code, 0);
    assert.match(localExport.stderr, /code: CLAIM_MISMATCH/);
    // The signed payload really says 20000, above the mandate cap of 15000 ...
    const args = bundle.payloads.find((p) => p.event_ref.seq === 4 && p.kind === "tool_arguments");
    assert.equal(args.content.amount_minor, 20000);
    assert.equal(bundle.evidence.mandate.document.scope.amount_max_minor, 15000);
    // ... while the author's claim understates it.
    assert.equal(bundle.subject.claims.amount_minor.value, 12900);

    t.diagnostic("verifier output:\n" + text);
    assert.equal(result.valid, false);
    assert.equal(result.code, "CLAIM_MISMATCH");
    assert.equal(step(result, 7).ok, false);
    assert.match(
      result.reason,
      /^subject\.claims\.amount_minor states 12900 but the signed payload pl_4_args \$\.amount_minor is 20000$/,
    );
    assert.equal(step(result, 8).ok, null, "the mandate is never reported as covering it");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("S2: an honest claim of the over-cap amount fails MANDATE_SCOPE_MISMATCH on the signed value", async () => {
  const { result, dir } = await exportLocalCase("test/tmp-s2-honest", 20000, claimsFor(4, {
    value: 20000, derived_from: "payload", ref: "pl_4_args", path: "$.amount_minor",
  }));
  try {
    assert.equal(result.valid, false);
    assert.equal(result.code, "MANDATE_SCOPE_MISMATCH");
    assert.equal(result.reason, "signed amount 20000 exceeds the mandate cap amount_max_minor 15000");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("S2: omitting the amount claim when the mandate has a cap fails EVIDENCE_GAP", async () => {
  const { result, dir } = await exportLocalCase("test/tmp-s2-omitted", 20000, claimsFor(4, undefined));
  try {
    assert.equal(result.valid, false);
    assert.equal(result.code, "EVIDENCE_GAP");
    assert.match(result.reason, /amount is not derivable from the disputed event's signed payload/);
    assert.equal(step(result, 8).ok, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("S2: the honest in-cap case still verifies (no false positives)", async () => {
  const { localExport, result, dir } = await exportLocalCase("test/tmp-s2-ok", 12900, claimsFor(4, {
    value: 12900, derived_from: "payload", ref: "pl_4_args", path: "$.amount_minor",
  }));
  try {
    assert.equal(localExport.code, 0, localExport.stdout + localExport.stderr);
    assert.equal(result.valid, true, result.reason);
    assert.equal(step(result, 7).ok, true);
    assert.equal(step(result, 8).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("S2 hosted walking bundle: baseline unchanged", async () => {
  const { result } = await verifyMutated(() => {});
  assert.equal(result.valid, true);
  assert.equal(step(result, 8).ok, true);
  assert.deepEqual(result.evidence_gaps, []);
});

test("S2 hosted walking bundle: every way of lying about or dodging the amount fails", async () => {
  const cases = [
    ["understated claim", (b) => { b.subject.claims.amount_minor.value = 1; }, "CLAIM_MISMATCH"],
    ["overstated claim", (b) => { b.subject.claims.amount_minor.value = 99999999; }, "CLAIM_MISMATCH"],
    ["amount as a string", (b) => { b.subject.claims.amount_minor.value = "12900"; }, "CLAIM_MISMATCH"],
    ["amount/currency/merchant claims deleted", (b) => {
      delete b.subject.claims.amount_minor;
      delete b.subject.claims.currency;
      delete b.subject.claims.merchant;
    }, "EVIDENCE_GAP"],
    ["amount re-labelled as a case assertion", (b) => {
      b.subject.claims.amount_minor = { value: 12900, derived_from: "case" };
    }, "EVIDENCE_GAP"],
    ["amount borrowed from another event's payload", (b) => {
      b.subject.claims.amount_minor.ref = "pl_4_args";
    }, "EVIDENCE_GAP"],
    ["amount borrowed from the result payload", (b) => {
      b.subject.claims.amount_minor.ref = "pl_3_result";
    }, "EVIDENCE_GAP"],
    ["path that does not exist", (b) => { b.subject.claims.amount_minor.path = "$.total"; }, "EVIDENCE_GAP"],
    ["unsupported JSONPath (recursive descent)", (b) => {
      b.subject.claims.amount_minor.path = "$..amount_minor";
    }, "EVIDENCE_GAP"],
    ["prototype path", (b) => { b.subject.claims.amount_minor.path = "$.__proto__"; }, "EVIDENCE_GAP"],
    ["currency claim lies", (b) => { b.subject.claims.currency.value = "EUR"; }, "CLAIM_MISMATCH"],
    ["currency claim deleted", (b) => { delete b.subject.claims.currency; }, "EVIDENCE_GAP"],
    ["tool claim lies", (b) => { b.subject.claims.tool.value = "mcp://shop/refund"; }, "CLAIM_MISMATCH"],
    ["agent claim lies", (b) => { b.subject.claims.agent_id.value = "agent://other"; }, "CLAIM_MISMATCH"],
    ["merchant claim lies", (b) => { b.subject.claims.merchant.value = "evil.example"; }, "CLAIM_MISMATCH"],
  ];
  for (const [name, mutate, code] of cases) {
    const { result } = await verifyMutated(mutate);
    assert.equal(result.valid, false, `${name}: must not be valid`);
    assert.equal(result.code, code, `${name}: ${result.code} ${result.reason}`);
  }
});

test("S2: a merchant claim that is only the author's assertion is not checked and is reported as a gap", async () => {
  const { result } = await verifyMutated((b) => {
    b.subject.claims.merchant = { value: "https://northwind-outfitters.example", derived_from: "case" };
  });
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.complete, false);
  assert.ok(result.evidence_gaps.includes("merchant_scope"), result.evidence_gaps.join(","));
});
