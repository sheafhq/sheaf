// S1 regression tests: the recorder must never manufacture a principal's
// signature, and the verifier must never mistake a recorder signature for a
// principal authorisation. See docs/SAP-ARCHITECTURE.md §13.
//
// Numbering follows the §13.4 table. #6 (browser parity) lives in
// test/browser.test.mjs because it needs a browser.

import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  createPrivateKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";

import { LocalLedger } from "../packages/mcp-recorder/dist/local.js";
import { hashCanonical } from "../packages/mcp-recorder/dist/canonical.js";
import { runCli } from "../dist-cli/cli.js";
import {
  computeDisputeBundleId,
  defaultTrustStore,
  formatDisputeVerification,
  verifyDisputeBundle,
} from "../packages/verify/dist/index.js";
import { buildDisputeBundle } from "../.test-dist/dispute.js";
import { evidenceDocumentHash, stripDocumentSignature } from "../.test-dist/evidence.js";

// ---------------------------------------------------------------- helpers ---

async function capture(fn) {
  const out = process.stdout.write;
  const err = process.stderr.write;
  let stdout = "";
  let stderr = "";
  process.stdout.write = (c) => ((stdout += String(c)), true);
  process.stderr.write = (c) => ((stderr += String(c)), true);
  try {
    const code = await fn();
    return { code, stdout, stderr };
  } finally {
    process.stdout.write = out;
    process.stderr.write = err;
  }
}

function principalKeyPem(dir, name = "principal.pem") {
  const { privateKey } = generateKeyPairSync("ed25519");
  const path = join(dir, name);
  writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }));
  return path;
}

/** Sign a document with an arbitrary local key, the way the PRE-FIX code did
 *  with the ledger key. Used only to create adversarial inputs. */
async function signWithRawKey(doc, pkcs8Base64, keyId, publicKeyBase64) {
  const unsigned = stripDocumentSignature(doc);
  const digest = Buffer.from(await evidenceDocumentHash(unsigned), "hex");
  const key = createPrivateKey({
    key: Buffer.from(pkcs8Base64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  return {
    ...unsigned,
    document_signature: {
      alg: "Ed25519",
      key_id: keyId,
      public_key_base64: publicKeyBase64,
      signature_base64: sign(null, digest, key).toString("base64"),
    },
  };
}

/** A local chain with mandate/delegation/consent + one allowed tool call,
 *  mirroring test/local.test.mjs. Returns paths. */
async function makeLocalChain(dir) {
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
  const policy = JSON.parse(readFileSync("test/fixtures/dispute-walking/policy.json", "utf8"));
  const policyHash = "sha256:" + hashCanonical(policy);
  const args = {
    merchant: "northwind-outfitters.example",
    amount_minor: 12900,
    currency: "USD",
    order_id: "order_demo_001",
    mandate_id: "mnd_demo_001",
    consent_id: "consent_demo_001",
  };
  const casePath = join(dir, "case.json");
  writeFileSync(
    casePath,
    JSON.stringify({
      case: {
        case_id: "CB-S1-001",
        card_network: "visa",
        reason_code: { schema: "2026 Visa Claims Resolution guide", value: "10.4", label: "Other fraud" },
        transaction: { reference: "txn_s1", amount_minor: 12900, currency: "USD", occurred_at: new Date().toISOString() },
        merchant: { id: "merchant_local", name: "Northwind Outfitters", url: "https://northwind-outfitters.example" },
        response_due_at: "2026-11-24T23:59:59Z",
        dispute_basis: { category: "friendly_fraud", asserted_by: "merchant", merchant_position: "S1 test." },
        created_at: new Date(Date.now() + 60_000).toISOString(),
      },
      subject: {
        from_seq: 4,
        to_seq: 4,
        disputed_event_seqs: [4],
        claims: {
          agent_id: { value: "agent://shopper-7", derived_from: "event.actor", ref: "seq:4" },
          tool: { value: "mcp://shop/payment", derived_from: "event.tool", ref: "seq:4" },
          merchant: { value: args.merchant, derived_from: "payload", ref: "pl_4_args", path: "$.merchant" },
          amount_minor: { value: 12900, derived_from: "payload", ref: "pl_4_args", path: "$.amount_minor" },
          currency: { value: "USD", derived_from: "payload", ref: "pl_4_args", path: "$.currency" },
        },
      },
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
    chainId: "s1-test",
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
  const ledgerKeys = JSON.parse(readFileSync(join(chainDir, "local-keys.json"), "utf8"));
  return { dir, chainDir, casePath, ledgerKeys };
}

async function exportAndVerify({ dir, chainDir, casePath }) {
  const out = join(dir, "bundle.sheaf");
  const exported = await capture(() =>
    runCli(["local", "export", "--chain-dir", chainDir, "--case", casePath, "--out", out]),
  );
  if (exported.code !== 0) return { exported };
  const bundle = JSON.parse(readFileSync(out, "utf8"));
  const trust = JSON.parse(readFileSync(join(chainDir, "trust.json"), "utf8"));
  const result = await verifyDisputeBundle(bundle, { trust });
  return { exported, bundle, result, text: formatDisputeVerification(result) };
}

const DOCS = ["mandate", "delegation", "consent"];

// ------------------------------------------------------------------ tests ---

test("S1-1 unsigned inputs: local export never signs with the ledger key", async () => {
  const chain = await makeLocalChain("test/tmp-s1-1");
  try {
    const { exported, bundle, result, text } = await exportAndVerify(chain);
    assert.equal(exported.code, 0, exported.stdout + exported.stderr);

    for (const [name, file] of [["mandate", "mandate"], ["delegation", "delegation-0"], ["consent", "consent"]]) {
      const doc = JSON.parse(readFileSync(join(chain.chainDir, "documents", `${file}.json`), "utf8"));
      assert.equal(doc.document_signature, undefined, `${name} must stay unsigned`);
    }
    const prepared = JSON.parse(readFileSync(join(chain.chainDir, "export-case.json"), "utf8"));
    assert.deepEqual(prepared.evidence.delegation.root.attestation, { basis: "recorder_observed" });

    assert.equal(bundle.evidence.mandate.document_signature, null);
    assert.equal(bundle.evidence.mandate.authorization_basis, "recorder_observed");
    assert.equal(result.valid, true);
    assert.equal(result.complete, false);
    for (const gap of ["mandate_signature", "delegation_signature", "delegation_root", "consent_signature"]) {
      assert.ok(result.evidence_gaps.includes(gap), `gap ${gap}`);
    }
    assert.equal(result.warnings, undefined, "unsigned is a gap, not a recorder-signature warning");
    assert.equal(result.authorisation, "absent");
    assert.match(text, /^VALID \(partial\)\nauthorisation: absent — /);
    assert.doesNotMatch(text, /warning:/);
  } finally {
    rmSync(chain.dir, { recursive: true, force: true });
  }
});

test("S1-2 + S1-4 principal-signed inputs are preserved byte-for-byte and verify complete", async () => {
  const chain = await makeLocalChain("test/tmp-s1-2");
  try {
    const keyPath = principalKeyPem(chain.dir);
    for (const name of DOCS) {
      const signed = await capture(() =>
        runCli([
          "local", "sign-document", join(chain.dir, `${name}.json`),
          "--key", keyPath, "--key-id", "payer-key-1", "--chain-dir", chain.chainDir,
        ]),
      );
      assert.equal(signed.code, 0, signed.stderr);
      assert.match(signed.stdout, /^SIGNED /m);
    }
    const inputs = Object.fromEntries(
      DOCS.map((n) => [n, readFileSync(join(chain.dir, `${n}.json`), "utf8")]),
    );

    const { exported, bundle, result, text } = await exportAndVerify(chain);
    assert.equal(exported.code, 0, exported.stdout + exported.stderr);

    for (const [name, file] of [["mandate", "mandate"], ["delegation", "delegation-0"], ["consent", "consent"]]) {
      const copied = JSON.parse(readFileSync(join(chain.chainDir, "documents", `${file}.json`), "utf8"));
      assert.deepEqual(copied, JSON.parse(inputs[name]), `${name} copied unchanged`);
      assert.notEqual(copied.document_signature.public_key_base64, chain.ledgerKeys.public_key_base64);
    }
    const root = bundle.evidence.delegation.root.attestation;
    assert.ok(["principal_signature", "policy_signature"].includes(root.basis));
    assert.equal(root.key_id, "payer-key-1");
    assert.notEqual(root.public_key_base64, chain.ledgerKeys.public_key_base64);

    assert.equal(result.valid, true);
    assert.equal(result.complete, true, JSON.stringify(result.evidence_gaps));
    assert.equal(result.warnings, undefined);
    assert.match(text, /^VALID \(complete\)/m);
    // Complete evidence, but the principal key is self-asserted (unrecognised):
    // it must not be presented as an authenticated principal.
    assert.equal(result.authorisation, "unauthenticated");
    assert.match(text, /^authorisation: unauthenticated — /m);
    assert.ok(result.signatures.every((s) => s.key_class === "unrecognised" && !s.principal_authenticated));
  } finally {
    rmSync(chain.dir, { recursive: true, force: true });
  }
});

test("S1-3 sign-document refuses the local ledger (recorder) key", async () => {
  const chain = await makeLocalChain("test/tmp-s1-3");
  try {
    const ledgerPem = join(chain.dir, "ledger.pem");
    writeFileSync(
      ledgerPem,
      createPrivateKey({
        key: Buffer.from(chain.ledgerKeys.private_key_pkcs8_base64, "base64"),
        format: "der",
        type: "pkcs8",
      }).export({ format: "pem", type: "pkcs8" }),
    );
    const target = join(chain.dir, "mandate.json");
    const before = readFileSync(target, "utf8");
    const refused = await capture(() =>
      runCli([
        "local", "sign-document", target,
        "--key", ledgerPem, "--key-id", "sneaky", "--chain-dir", chain.chainDir,
      ]),
    );
    assert.equal(refused.code, 1);
    assert.match(refused.stderr, /SIGN_REFUSED SIGNING_KEY_IS_RECORDER_KEY/);
    assert.equal(readFileSync(target, "utf8"), before, "document untouched");
  } finally {
    rmSync(chain.dir, { recursive: true, force: true });
  }
});

test("S1-5 legacy bundle from the pre-fix code: integrity valid, authorisation downgraded", async () => {
  const bundle = JSON.parse(readFileSync("test/fixtures/s1/legacy-recorder-signed.sheaf", "utf8"));
  const trust = JSON.parse(readFileSync("test/fixtures/s1/legacy-recorder-signed.trust.json", "utf8"));
  const ledgerKey = trust.recorder_keys[0].public_key_base64;
  // The fixture really is the buggy artifact:
  assert.equal(bundle.evidence.mandate.document.document_signature.public_key_base64, ledgerKey);
  assert.equal(bundle.evidence.delegation.root.attestation.basis, "principal_signature");

  const result = await verifyDisputeBundle(bundle, { trust });
  const text = formatDisputeVerification(result);

  assert.equal(result.valid, true, "integrity is preserved");
  assert.equal(result.complete, false, "never complete on recorder signatures");
  for (const gap of ["mandate_signature", "delegation_signature", "delegation_root", "consent_signature"]) {
    assert.ok(result.evidence_gaps.includes(gap), `gap ${gap}`);
  }
  const sections = (result.warnings ?? []).map((w) => w.section);
  assert.ok(result.warnings.every((w) => w.code === "RECORDER_SIGNED_NOT_PRINCIPAL"));
  assert.ok(sections.includes("mandate"));
  assert.ok(sections.includes("consent"));
  assert.ok(sections.some((s) => s.startsWith("delegation ")));
  assert.ok(sections.some((s) => s.startsWith("delegation root")));
  assert.match(text, /^VALID \(partial\)/m);
  assert.doesNotMatch(text, /^VALID \(complete\)/m);
  assert.match(text, /^authorisation: recorder-attested only/m);
  assert.match(text, /^warning: RECORDER_SIGNED_NOT_PRINCIPAL \[mandate\]/m);
});

test("S1-7 hosted walking fixtures (distinct principal key): no false positives", async () => {
  for (const file of ["bundle.sheaf", "bundle-policy.sheaf"]) {
    const bundle = JSON.parse(readFileSync(`test/fixtures/dispute-walking/${file}`, "utf8"));
    const result = await verifyDisputeBundle(bundle, {});
    assert.equal(result.warnings, undefined, `${file}: no recorder-signature warnings`);
    assert.equal(result.authorisation, "unauthenticated", `${file}: unrecognised keys are never authenticated`);
    assert.doesNotMatch(formatDisputeVerification(result), /warning:/);
  }
});

test("S1-8 a document signed by a PINNED recorder key is not a principal signature", async () => {
  const bundle = JSON.parse(readFileSync("test/fixtures/dispute-walking/bundle.sheaf", "utf8"));
  const signer = bundle.evidence.mandate.document.document_signature.public_key_base64;
  const base = defaultTrustStore();
  // Pretend the hosted recorder's keyring also contains the mandate signer's key.
  const trust = {
    ...base,
    recorder_keys: [
      ...base.recorder_keys,
      { key_id: "pinned-test-recorder", public_key_base64: signer, active_from: "2020-01-01T00:00:00Z", active_until: null },
    ],
  };
  const before = await verifyDisputeBundle(bundle, {});
  const after = await verifyDisputeBundle(bundle, { trust });
  assert.equal(after.valid, before.valid, "integrity verdict unchanged");
  assert.ok(after.warnings.some((w) => w.section === "mandate"));
  assert.ok(after.evidence_gaps.includes("mandate_signature"));
  assert.equal(after.complete, false);
});

test("S1-10 local export refuses recorder-signed or tampered documents", async () => {
  // (a) a document signed with the ledger key (what the old code produced)
  const a = await makeLocalChain("test/tmp-s1-10a");
  try {
    const path = join(a.dir, "mandate.json");
    const doc = JSON.parse(readFileSync(path, "utf8"));
    const forged = await signWithRawKey(
      doc, a.ledgerKeys.private_key_pkcs8_base64, a.ledgerKeys.key_id, a.ledgerKeys.public_key_base64,
    );
    writeFileSync(path, JSON.stringify(forged, null, 2));
    const res = await exportAndVerify(a);
    assert.equal(res.exported.code, 1);
    assert.match(res.exported.stderr, /EXPORT_REFUSED RECORDER_SIGNED_NOT_PRINCIPAL/);
  } finally {
    rmSync(a.dir, { recursive: true, force: true });
  }

  // (b) a principal-signed document edited after signing
  const b = await makeLocalChain("test/tmp-s1-10b");
  try {
    const keyPath = principalKeyPem(b.dir);
    const path = join(b.dir, "consent.json");
    const signed = await capture(() =>
      runCli(["local", "sign-document", path, "--key", keyPath, "--key-id", "payer-key-1", "--chain-dir", b.chainDir]),
    );
    assert.equal(signed.code, 0, signed.stderr);
    const doc = JSON.parse(readFileSync(path, "utf8"));
    doc.method = doc.method === "merchant_signature" ? "payer_signature" : "merchant_signature";
    writeFileSync(path, JSON.stringify(doc, null, 2));
    const res = await exportAndVerify(b);
    assert.equal(res.exported.code, 1);
    assert.match(res.exported.stderr, /EXPORT_REFUSED DOCUMENT_SIGNATURE_INVALID/);
  } finally {
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("S1-11 bundle builder never infers or accepts a principal claim on a recorder signature", async () => {
  const legacy = JSON.parse(readFileSync("test/fixtures/s1/legacy-recorder-signed.sheaf", "utf8"));
  const disclosures = {
    version: "sheaf-disclosure/1",
    chain_id: legacy.subject.chain_id,
    from_seq: 0,
    to_seq: 4,
    recorder: legacy.recorder,
    disclosures: legacy.disclosures,
    anchor: legacy.anchor,
    before_ref: null,
    after_ref: null,
    warnings: [],
  };
  const caseInput = {
    ...legacy.case,
    subject: {
      chain_id: legacy.subject.chain_id,
      from_seq: legacy.subject.from_seq,
      to_seq: legacy.subject.to_seq,
      disputed_event_seqs: legacy.subject.disputed_event_seqs,
      claims: {},
    },
  };
  const evidenceFor = (basis) => ({
    mandate: {
      status: "included",
      event_ref: legacy.evidence.mandate.event_ref,
      document: legacy.evidence.mandate.document,
      ...(basis ? { authorization_basis: basis } : {}),
    },
    delegation: { status: "absent" },
    consent: { status: "absent" },
  });

  // Default inference: a recorder-key signature is only a recorder observation.
  const built = await buildDisputeBundle(caseInput, disclosures, evidenceFor(undefined), legacy.anchor, []);
  assert.equal(built.evidence.mandate.authorization_basis, "recorder_observed");

  // Explicitly claiming principal_signature on it is refused.
  await assert.rejects(
    () => buildDisputeBundle(caseInput, disclosures, evidenceFor("principal_signature"), legacy.anchor, []),
    (err) => err.code === "RECORDER_SIGNED_NOT_PRINCIPAL",
  );

  // An explicit delegation root claiming principal_signature with the recorder key is refused.
  const link = legacy.evidence.delegation.chain[0];
  await assert.rejects(
    () =>
      buildDisputeBundle(
        caseInput,
        disclosures,
        {
          mandate: { status: "absent" },
          delegation: {
            status: "included",
            root: legacy.evidence.delegation.root,
            chain: [{ event_ref: link.event_ref, parent_event_ref: link.parent_event_ref, document: link.document }],
          },
          consent: { status: "absent" },
        },
        legacy.anchor,
        [],
      ),
    (err) => err.code === "RECORDER_SIGNED_NOT_PRINCIPAL",
  );
});

test("S1 bundle_id still covers the evidence (downgrade is not a bundle change)", async () => {
  const bundle = JSON.parse(readFileSync("test/fixtures/s1/legacy-recorder-signed.sheaf", "utf8"));
  assert.equal(await computeDisputeBundleId(bundle), bundle.bundle_id);
});
