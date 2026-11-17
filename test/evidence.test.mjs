// Build #2: evidence event layer.
//
// Coverage:
//   - pre-change arca/1 envelope (no kind) still hashes and verifies
//   - pre-change sheaf-bundle/1 still verifies
//   - all three document schemas round-trip through JCS -> SHA-256 -> event
//   - mandate/delegation/consent can be recorded against one chain
//   - EVIDENCE_DOC_HASH_MISMATCH fires on a mismatched document
//   - optional Ed25519 document signatures verify

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

import {
  EVIDENCE_SCHEMAS,
  buildEvidenceSubmission,
  canonicalEvidenceDocument,
  evidenceDocumentHash,
  signEvidenceDocument,
  stripDocumentSignature,
  validateEvidenceDocument,
} from "../.test-dist/evidence.js";
import { canonicalize, hashCanonical } from "../.test-dist/canonical.js";
import {
  verify as verifyReceipt,
  verifyEd25519,
  verifyEvidenceDocument,
} from "../packages/verify/dist/index.js";

const { subtle } = webcrypto;
const CHAIN_ID = "evidence-test-1";
const ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const ZERO_HASH = "0".repeat(64);

function fixtureJson(relative) {
  return JSON.parse(
    readFileSync(new URL(relative, import.meta.url), "utf8"),
  );
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
  const message = new TextEncoder().encode(canonicalize(core));
  const signature = new Uint8Array(
    await subtle.sign("Ed25519", privateKey, message),
  );
  return Buffer.from(signature).toString("base64");
}

async function recordSubmission(submission, recorderKey) {
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

test("golden: pre-change arca/1 envelope without kind verifies unchanged", async () => {
  const golden = fixtureJson(
    "./fixtures/arca1-no-kind.smoke-test-1-0.json",
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(golden.envelope.event, "kind"),
    false,
  );

  const core = {
    v: golden.envelope.v,
    event: golden.envelope.event,
    chain: golden.envelope.chain,
  };
  assert.equal(await hashCanonical(core), golden.envelope_hash);

  const ok = await verifyEd25519(
    golden.recorder_public_key_base64,
    golden.envelope.signatures.recorder,
    new TextEncoder().encode(canonicalize(core)),
  );
  assert.equal(ok, true);
});

test("golden: pre-change sheaf-bundle/1 still verifies", async () => {
  const golden = fixtureJson(
    "./fixtures/sheaf-bundle-1.smoke-test-1-0.json",
  );
  assert.equal(golden.version, "sheaf-bundle/1");
  assert.equal(Object.prototype.hasOwnProperty.call(golden.envelope.event, "kind"), false);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}"));
    assert.equal(body.method, "eth_getTransactionByHash");
    assert.equal(body.params[0], golden.anchor.tx_hash);
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          from: ANCHORER,
          to: ANCHORER,
          input:
            "0x41524341" +
            "0000000000000000" +
            golden.anchor.merkle_root,
          blockNumber: "0x" + BigInt(golden.anchor.block).toString(16),
          hash: golden.anchor.tx_hash,
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  try {
    const result = await verifyReceipt(
      {
        envelope: golden.envelope,
        inclusion_proof: {
          leaf: golden.envelope_hash,
          leaf_index: golden.anchor.leaf_index,
          merkle_root: golden.anchor.merkle_root,
          siblings: golden.anchor.siblings,
        },
        anchor_tx_hash: golden.anchor.tx_hash,
      },
      {
        base_rpc: "https://rpc.invalid",
        recorder_public_key_base64: golden.issuer.public_key_base64,
        expected_anchorer_address: ANCHORER,
      },
    );
    assert.equal(result.valid, true, JSON.stringify(result));
    assert.equal(result.checks.recorder_signature_verifies, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("schema: three document schemas are strict JSON and validate fixtures", () => {
  const schemaFiles = [
    "sheaf.mandate-document-1.schema.json",
    "sheaf.delegation-document-1.schema.json",
    "sheaf.consent-document-1.schema.json",
  ];
  function assertStrictObjects(node, path) {
    if (Array.isArray(node)) {
      node.forEach((child, idx) => assertStrictObjects(child, `${path}[${idx}]`));
      return;
    }
    if (!node || typeof node !== "object") return;
    if (node.type === "object") {
      assert.equal(
        node.additionalProperties,
        false,
        `${path}: object schemas must set additionalProperties:false`,
      );
    }
    for (const [key, value] of Object.entries(node)) {
      assertStrictObjects(value, `${path}.${key}`);
    }
  }

  for (const file of schemaFiles) {
    const schema = fixtureJson(`../schemas/${file}`);
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.additionalProperties, false);
    assert.ok(Array.isArray(schema.required) && schema.required.length > 0);
    assertStrictObjects(schema, file);
  }

  for (const kind of ["mandate", "delegation", "consent"]) {
    const doc = fixtureJson(`./fixtures/evidence/${kind}.json`);
    assert.deepEqual(validateEvidenceDocument(doc), []);
  }
});

test("round-trip: canonicalize -> hash -> embed -> document hash matches inputs_hash", async () => {
  const recorderKey = await makeKey();
  for (const kind of ["mandate", "delegation", "consent"]) {
    const doc = fixtureJson(`./fixtures/evidence/${kind}.json`);
    const unsigned = stripDocumentSignature(doc);
    assert.equal(canonicalEvidenceDocument(doc), canonicalize(unsigned));
    const hash = await evidenceDocumentHash(doc);
    assert.match(hash, /^[0-9a-f]{64}$/);

    const submission = await buildEvidenceSubmission(doc, {
      chain: { chain_id: CHAIN_ID, seq: 0, prev_hash: null },
      ts: doc.issued_at ?? doc.consented_at,
    });
    assert.equal(submission.event.kind, kind);
    assert.equal(submission.event.inputs_hash, `sha256:${hash}`);

    const recorded = await recordSubmission(submission, recorderKey);
    const checked = await verifyEvidenceDocument(
      recorded.envelope,
      doc,
    );
    assert.equal(checked.valid, true, JSON.stringify(checked));
    assert.equal(checked.checks.document_hash_matches_inputs_hash, true);
    assert.equal(checked.document_hash, hash);
  }
});

test("record: mandate, delegation, and consent form one hash-linked chain", async () => {
  const recorderKey = await makeKey();
  const mandate = fixtureJson("./fixtures/evidence/mandate.json");
  const delegation = fixtureJson("./fixtures/evidence/delegation.json");
  const consent = fixtureJson("./fixtures/evidence/consent.json");

  const specs = [
    { kind: "mandate", doc: mandate, ts: mandate.issued_at },
    { kind: "delegation", doc: delegation, ts: delegation.issued_at },
    { kind: "consent", doc: consent, ts: consent.consented_at },
  ];

  let prevHash = null;
  const recorded = [];
  for (let seq = 0; seq < specs.length; seq++) {
    const spec = specs[seq];
    const submission = await buildEvidenceSubmission(spec.doc, {
      chain: { chain_id: CHAIN_ID, seq, prev_hash: prevHash },
      ts: spec.ts,
      authority:
        seq === 0 ? null : `sheaf://${CHAIN_ID}/${seq - 1}`,
    });
    const row = await recordSubmission(submission, recorderKey);
    recorded.push(row);
    prevHash = row.envelope_hash;
  }

  assert.deepEqual(
    recorded.map((r) => r.envelope.event.kind),
    ["mandate", "delegation", "consent"],
  );
  assert.equal(recorded[1].envelope.chain.prev_hash, recorded[0].envelope_hash);
  assert.equal(recorded[2].envelope.chain.prev_hash, recorded[1].envelope_hash);

  const docs = [mandate, delegation, consent];
  for (let i = 0; i < recorded.length; i++) {
    const checked = await verifyEvidenceDocument(recorded[i].envelope, docs[i]);
    assert.equal(checked.valid, true, JSON.stringify(checked));
  }
});

test("EVIDENCE_DOC_HASH_MISMATCH fires on a mismatched document hash", async () => {
  const recorderKey = await makeKey();
  const doc = fixtureJson("./fixtures/evidence/mandate.json");
  const submission = await buildEvidenceSubmission(doc, {
    chain: { chain_id: CHAIN_ID, seq: 0, prev_hash: null },
    ts: doc.issued_at,
  });
  submission.event.inputs_hash = `sha256:${ZERO_HASH}`;
  const recorded = await recordSubmission(submission, recorderKey);

  const checked = await verifyEvidenceDocument(recorded.envelope, doc);
  assert.equal(checked.valid, false);
  assert.equal(checked.code, "EVIDENCE_DOC_HASH_MISMATCH");
  assert.equal(checked.checks.document_hash_matches_inputs_hash, false);
});

test("document_signature: optional Ed25519 signature over the unsigned hash", async () => {
  const recorderKey = await makeKey();
  const principalKey = await makeKey();
  const doc = fixtureJson("./fixtures/evidence/mandate.json");

  const signed = await signEvidenceDocument(doc, {
    private_key_pkcs8_base64: principalKey.privateKeyPkcs8Base64,
    key_id: "principal-demo-1",
    public_key_base64: principalKey.publicKeyBase64,
  });
  assert.deepEqual(validateEvidenceDocument(signed), []);

  const signedHash = await evidenceDocumentHash(signed);
  const unsignedHash = await evidenceDocumentHash(doc);
  assert.equal(signedHash, unsignedHash);

  const submission = await buildEvidenceSubmission(signed, {
    chain: { chain_id: CHAIN_ID, seq: 0, prev_hash: null },
    ts: doc.issued_at,
  });
  const recorded = await recordSubmission(submission, recorderKey);

  const checked = await verifyEvidenceDocument(recorded.envelope, signed, {
    require_document_signature: true,
  });
  assert.equal(checked.valid, true, JSON.stringify(checked));
  assert.equal(checked.checks.document_signature_verifies, true);

  const unsigned = await verifyEvidenceDocument(recorded.envelope, doc);
  assert.equal(unsigned.valid, true);
  assert.equal(unsigned.checks.document_signature_verifies, null);

  const missing = await verifyEvidenceDocument(recorded.envelope, doc, {
    require_document_signature: true,
  });
  assert.equal(missing.valid, false);
  assert.equal(missing.code, "EVIDENCE_DOC_SIGNATURE_MISSING");

  const tampered = structuredClone(signed);
  tampered.document_signature.signature_base64 = Buffer.from(
    new Uint8Array(64),
  ).toString("base64");
  const bad = await verifyEvidenceDocument(recorded.envelope, tampered);
  assert.equal(bad.valid, false);
  assert.equal(bad.code, "EVIDENCE_DOC_SIGNATURE_INVALID");
});

test("strict validation rejects unknown and missing document fields", () => {
  const doc = fixtureJson("./fixtures/evidence/mandate.json");
  const extra = { ...doc, unexpected: true };
  assert.ok(
    validateEvidenceDocument(extra).some((e) => e.includes("unexpected field")),
  );

  const missing = { ...doc };
  delete missing.mandate_id;
  assert.ok(
    validateEvidenceDocument(missing).some((e) =>
      e.includes("mandate_id"),
    ),
  );

  const wrongSchema = { ...doc, schema: "sheaf.mandate-document/2" };
  assert.ok(
    validateEvidenceDocument(wrongSchema).some((e) =>
      e.includes("document.schema"),
    ),
  );
});

test("kind absent means tool_call and is not an evidence event", async () => {
  const golden = fixtureJson(
    "./fixtures/arca1-no-kind.smoke-test-1-0.json",
  );
  const checked = await verifyEvidenceDocument(
    golden.envelope,
    fixtureJson("./fixtures/evidence/mandate.json"),
  );
  assert.equal(checked.valid, false);
  assert.equal(checked.code, "NOT_EVIDENCE_EVENT");
});
