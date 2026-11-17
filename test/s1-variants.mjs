// S1 security-review variants: deterministic adversarial bundles derived from
// the frozen legacy fixture. Shared by test/s1-review.test.mjs (Node) and
// test/browser.test.mjs (browser parity), so both run the exact same inputs.
//
// Keys are derived from fixed seeds, so every signature (Ed25519 is
// deterministic) and every bundle_id is identical on every run.
//
// Each variant carries its own verifier options: `trust` (recorder keys) and
// optionally `trusted_signers` (relying-party signer pins).

import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import {
  computeDisputeBundleId,
  evidenceDocumentHash,
  stripDocumentSignature,
} from "../packages/verify/dist/index.js";

const FIXTURE = "test/fixtures/s1/legacy-recorder-signed.sheaf";
const TRUST = "test/fixtures/s1/legacy-recorder-signed.trust.json";

export function keyFromSeed(byte) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { privateKey, publicKeyBase64: Buffer.from(spki).subarray(-32).toString("base64") };
}

export const KEYS = {
  principal: keyFromSeed(0x01),
  policy: keyFromSeed(0x02),
  unknown: keyFromSeed(0x03),
};

// Weak / adversarial Ed25519 material (see test/s1-review.test.mjs for the
// full vector set and the measured native behaviour).
export const WEAK = {
  identity: Buffer.from("01" + "00".repeat(31), "hex"),
  identityNegZero: Buffer.from("01" + "00".repeat(30) + "80", "hex"),
  identityYplusP: Buffer.from("ee" + "ff".repeat(30) + "7f", "hex"),
  order2: Buffer.from("ec" + "ff".repeat(30) + "7f", "hex"),
  order4: Buffer.alloc(32),
  order8a: Buffer.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "hex"),
  order8b: Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex"),
};
/** R = identity, S = 0: verifies under the identity key for EVERY message in
 *  native WebCrypto (measured), i.e. a signature that needs no private key. */
export const UNIVERSAL_SIGNATURE = Buffer.concat([WEAK.identity, Buffer.alloc(32)]);
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

export async function signDoc(document, key, keyId) {
  const unsigned = stripDocumentSignature(document);
  const digest = Buffer.from(await evidenceDocumentHash(unsigned), "hex");
  return {
    ...unsigned,
    document_signature: {
      alg: "Ed25519",
      key_id: keyId,
      public_key_base64: key.publicKeyBase64,
      signature_base64: sign(null, digest, key.privateKey).toString("base64"),
    },
  };
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function flipPadBits(k) {
  const i = k.length - 2;
  const v = B64.indexOf(k[i]);
  return k.slice(0, i) + B64[(v & ~3) | ((v & 3) ^ 1)] + k.slice(i + 1);
}

function sections(bundle) {
  return [
    ["mandate", bundle.evidence.mandate],
    ...bundle.evidence.delegation.chain.map((l, i) => [`delegation-${i}`, l]),
    ["consent", bundle.evidence.consent],
  ];
}

function put(holder, document) {
  holder.document = document;
  if ("document_signature" in holder) holder.document_signature = document.document_signature ?? null;
}

function rootFrom(document, basis = "principal_signature") {
  const s = document.document_signature;
  return { basis, key_id: s.key_id, public_key_base64: s.public_key_base64, signature_base64: s.signature_base64 };
}

async function signAll(b, key, keyId) {
  for (const [, holder] of sections(b)) put(holder, await signDoc(holder.document, key, keyId));
}

function setRawSignature(b, publicKey, signature) {
  for (const [, h] of sections(b)) {
    h.document = {
      ...stripDocumentSignature(h.document),
      document_signature: {
        alg: "Ed25519",
        key_id: "no-private-key",
        public_key_base64: Buffer.from(publicKey).toString("base64"),
        signature_base64: Buffer.from(signature).toString("base64"),
      },
    };
    if ("document_signature" in h) h.document_signature = h.document.document_signature;
  }
  b.evidence.delegation.root.attestation = rootFrom(b.evidence.mandate.document);
}

/** A relying-party pin for the principal key, bound to the legacy fixture's payer. */
export function principalPin(overrides = {}) {
  return {
    key_id: "payer-key-1",
    public_key_base64: KEYS.principal.publicKeyBase64,
    party_id: "payer_demo_001",
    roles: ["mandate", "delegation", "consent"],
    active_from: "2026-01-01T00:00:00Z",
    active_until: null,
    ...overrides,
  };
}

/**
 * Returns [{ name, bundle, opts, expect }]. `expect`:
 *   valid, complete, authorisation, warnings (multiset of codes), code (when invalid).
 */
export async function buildVariants() {
  const legacy = JSON.parse(readFileSync(FIXTURE, "utf8"));
  const trust = JSON.parse(readFileSync(TRUST, "utf8"));
  const recorderKey = trust.recorder_keys[0].public_key_base64;
  const variants = [];
  const add = async (name, mutate, expect, extraOpts = {}) => {
    const b = structuredClone(legacy);
    await mutate(b);
    b.bundle_id = await computeDisputeBundleId(b);
    variants.push({ name, bundle: b, opts: { trust, ...extraOpts }, expect });
  };
  const R4 = Array(4).fill("RECORDER_SIGNED_NOT_PRINCIPAL");
  const INVALID = (code = "EVIDENCE_DOC_SIGNATURE_INVALID") => ({ valid: false, complete: false, authorisation: "not_evaluated", code });
  const principalAll = async (b) => {
    await signAll(b, KEYS.principal, "payer-key-1");
    b.evidence.delegation.root.attestation = rootFrom(b.evidence.mandate.document);
  };

  // ---- key material, not key_id or spelling ------------------------------------
  await add("legacy as produced by the pre-fix code", () => {}, { valid: true, complete: false, authorisation: "recorder_attested", warnings: R4 });
  await add("recorder key_id renamed to a principal-looking id", (b) => {
    for (const [, h] of sections(b)) h.document.document_signature.key_id = "acme-cfo-principal-key";
    b.evidence.delegation.root.attestation.key_id = "acme-cfo-principal-key";
  }, { valid: true, complete: false, authorisation: "recorder_attested", warnings: R4 });
  await add("recorder key_id set to the real principal's key_id", (b) => {
    for (const [, h] of sections(b)) h.document.document_signature.key_id = "payer-key-1";
  }, { valid: true, complete: false, authorisation: "recorder_attested", warnings: R4 });
  for (const [label, respell] of [
    ["without = padding", (k) => k.replace(/=+$/, "")],
    ["with non-zero padding bits", flipPadBits],
    ["with embedded whitespace", (k) => k.slice(0, 10) + " " + k.slice(10)],
  ]) {
    await add(`recorder key re-spelled ${label}`, (b) => {
      for (const [, h] of sections(b)) h.document.document_signature.public_key_base64 = respell(recorderKey);
      b.evidence.delegation.root.attestation.public_key_base64 = respell(recorderKey);
    }, INVALID());
  }

  // ---- multiple / mixed / unknown signatures ------------------------------------
  await add("all documents signed by an UNRECOGNISED principal key", principalAll,
    { valid: true, complete: true, authorisation: "unauthenticated", warnings: [] });
  await add("document_signature is an array [principal, recorder]", async (b) => {
    const p = await signDoc(b.evidence.mandate.document, KEYS.principal, "payer-key-1");
    b.evidence.mandate.document.document_signature = [p.document_signature, b.evidence.mandate.document.document_signature];
  }, INVALID());
  await add("recorder signature + extra principal co_signature field", async (b) => {
    const p = await signDoc(b.evidence.mandate.document, KEYS.principal, "payer-key-1");
    b.evidence.mandate.document.document_signature.co_signatures = [p.document_signature];
  }, { valid: true, complete: false, authorisation: "recorder_attested", warnings: R4 });
  await add("extra top-level additional_signatures field (changes the document hash)", async (b) => {
    const p = await signDoc(b.evidence.mandate.document, KEYS.principal, "payer-key-1");
    b.evidence.mandate.document.additional_signatures = [p.document_signature];
  }, INVALID("EVIDENCE_DOC_HASH_MISMATCH"));
  await add("mixed: principal mandate, POLICY-key delegation, UNKNOWN-key consent", async (b) => {
    put(b.evidence.mandate, await signDoc(b.evidence.mandate.document, KEYS.principal, "payer-key-1"));
    put(b.evidence.delegation.chain[0], await signDoc(b.evidence.delegation.chain[0].document, KEYS.policy, "policy-key-1"));
    put(b.evidence.consent, await signDoc(b.evidence.consent.document, KEYS.unknown, "unknown-key-1"));
    b.evidence.delegation.root.attestation = rootFrom(b.evidence.mandate.document);
  }, { valid: true, complete: true, authorisation: "unauthenticated", warnings: [] });
  await add("mixed: principal mandate, RECORDER delegation, unknown consent", async (b) => {
    put(b.evidence.mandate, await signDoc(b.evidence.mandate.document, KEYS.principal, "payer-key-1"));
    put(b.evidence.consent, await signDoc(b.evidence.consent.document, KEYS.unknown, "unknown-key-1"));
    b.evidence.delegation.root.attestation = rootFrom(b.evidence.mandate.document);
  }, { valid: true, complete: false, authorisation: "recorder_attested", warnings: ["RECORDER_SIGNED_NOT_PRINCIPAL"] });
  await add("all unsigned; root FORGED as principal_signature with an unknown key", async (b) => {
    for (const [, h] of sections(b)) put(h, stripDocumentSignature(h.document));
    const u = await signDoc(b.evidence.mandate.document, KEYS.unknown, "unknown-key-1");
    b.evidence.delegation.root.attestation = rootFrom(u);
  }, { valid: true, complete: false, authorisation: "absent", warnings: ["ROOT_ATTESTATION_UNVERIFIED"] });
  await add("all principal-signed; root claims a DIFFERENT (unknown) key", async (b) => {
    await signAll(b, KEYS.principal, "payer-key-1");
    const u = await signDoc(b.evidence.mandate.document, KEYS.unknown, "unknown-key-1");
    b.evidence.delegation.root.attestation = rootFrom(u);
  }, { valid: true, complete: false, authorisation: "unauthenticated", warnings: ["ROOT_ATTESTATION_UNVERIFIED"] });
  await add("all principal-signed; root reuses the mandate key with the CONSENT's signature", async (b) => {
    await signAll(b, KEYS.principal, "payer-key-1");
    b.evidence.delegation.root.attestation = {
      ...rootFrom(b.evidence.mandate.document),
      signature_base64: b.evidence.consent.document.document_signature.signature_base64,
    };
  }, { valid: true, complete: false, authorisation: "unauthenticated", warnings: ["ROOT_ATTESTATION_UNVERIFIED"] });
  await add("self-generated key labelled 'acme-root' signs everything", async (b) => {
    await signAll(b, keyFromSeed(0x41), "acme-root");
    b.evidence.delegation.root.attestation = rootFrom(b.evidence.mandate.document);
  }, { valid: true, complete: true, authorisation: "unauthenticated", warnings: [] });

  // ---- strict Ed25519: keyless / weak / malleated signatures ---------------------------
  await add("KEYLESS: identity public key + universal signature on every document",
    (b) => setRawSignature(b, WEAK.identity, UNIVERSAL_SIGNATURE), INVALID());
  await add("KEYLESS: identity key in NEGATIVE-ZERO spelling + universal signature",
    (b) => setRawSignature(b, WEAK.identityNegZero, UNIVERSAL_SIGNATURE), INVALID());
  await add("KEYLESS: identity key in y = p + 1 spelling + universal signature",
    (b) => setRawSignature(b, WEAK.identityYplusP, UNIVERSAL_SIGNATURE), INVALID());
  await add("order-8 torsion public key + universal signature",
    (b) => setRawSignature(b, WEAK.order8a, UNIVERSAL_SIGNATURE), INVALID());
  await add("principal signature malleated to S + L", async (b) => {
    await principalAll(b);
    const sig = Buffer.from(b.evidence.mandate.document.document_signature.signature_base64, "base64");
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) + BigInt(sig[i]);
    s += L;
    for (let i = 32; i < 64; i++) { sig[i] = Number(s & 0xffn); s >>= 8n; }
    b.evidence.mandate.document.document_signature.signature_base64 = sig.toString("base64");
    if (b.evidence.mandate.document_signature) b.evidence.mandate.document_signature = b.evidence.mandate.document.document_signature;
  }, INVALID());
  await add("principal signature with R replaced by a small-order point", async (b) => {
    await principalAll(b);
    const sig = Buffer.from(b.evidence.mandate.document.document_signature.signature_base64, "base64");
    WEAK.order8a.copy(sig, 0);
    b.evidence.mandate.document.document_signature.signature_base64 = sig.toString("base64");
    if (b.evidence.mandate.document_signature) b.evidence.mandate.document_signature = b.evidence.mandate.document.document_signature;
  }, INVALID());

  // ---- relying-party signer pins: the only route to "verified" -------------------------
  await add("PINNED principal key for payer_demo_001, all roles", principalAll,
    { valid: true, complete: true, authorisation: "verified", warnings: [] },
    { trusted_signers: [principalPin()] });
  await add("pinned key bound to the WRONG party", principalAll,
    { valid: true, complete: true, authorisation: "unauthenticated", warnings: [] },
    { trusted_signers: [principalPin({ party_id: "someone_else" })] });
  await add("pinned key only for the mandate role", principalAll,
    { valid: true, complete: true, authorisation: "unauthenticated", warnings: [] },
    { trusted_signers: [principalPin({ roles: ["mandate"] })] });
  await add("pinned key whose window ENDED before the events", principalAll,
    { valid: true, complete: true, authorisation: "unauthenticated", warnings: [] },
    { trusted_signers: [principalPin({ active_until: "2026-01-02T00:00:00Z" })] });
  await add("pinned principal key but root attestation unbacked", async (b) => {
    await signAll(b, KEYS.principal, "payer-key-1");
    const u = await signDoc(b.evidence.mandate.document, KEYS.unknown, "unknown-key-1");
    b.evidence.delegation.root.attestation = rootFrom(u);
  }, { valid: true, complete: false, authorisation: "unauthenticated", warnings: ["ROOT_ATTESTATION_UNVERIFIED"] },
    { trusted_signers: [principalPin()] });
  await add("the RECORDER key pinned as a 'trusted signer' (misconfiguration)", () => {},
    { valid: true, complete: false, authorisation: "recorder_attested", warnings: [...R4, "TRUSTED_SIGNER_IS_RECORDER"] },
    { trusted_signers: [principalPin({ public_key_base64: recorderKey })] });
  await add("a WEAK (identity) key pinned as a trusted signer", principalAll,
    { valid: true, complete: true, authorisation: "unauthenticated", warnings: ["TRUSTED_SIGNER_INVALID"] },
    { trusted_signers: [principalPin({ public_key_base64: WEAK.identity.toString("base64") })] });

  return variants;
}

/** Writes each variant (+ its trust and signer files) to `dir`, for CLI runs. */
export function variantFiles(dir, variants, writeFileSync, join) {
  return variants.map((v, i) => {
    const id = String(i).padStart(2, "0");
    const path = join(dir, `variant-${id}.sheaf`);
    const trustPath = join(dir, `variant-${id}.trust.json`);
    writeFileSync(path, JSON.stringify(v.bundle));
    writeFileSync(trustPath, JSON.stringify(v.opts.trust));
    let signersPath = null;
    if (v.opts.trusted_signers) {
      signersPath = join(dir, `variant-${id}.signers.json`);
      writeFileSync(signersPath, JSON.stringify({ schema: "sheaf.trusted-signers/1", signers: v.opts.trusted_signers }));
    }
    return { ...v, path, trustPath, signersPath };
  });
}

/** CLI argv for a variant file set. */
export function cliArgs(v) {
  return [
    "dist-cli/cli.js", "dispute", "verify", v.path,
    "--offline", "--allow-unconfirmed-anchor", "--trust", v.trustPath,
    ...(v.signersPath ? ["--signers", v.signersPath] : []),
  ];
}
