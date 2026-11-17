// S1 security review (2026-11-17).
//
//  A. Signature classification depends only on public-key MATERIAL (not
//     key_id, not base64 spelling), and extra/mixed signatures or forged root
//     attestations can never upgrade anything.
//  B. Terminology: cryptographically valid ≠ recognised recorder ≠ unrecognised
//     ≠ authenticated principal ≠ verified authorisation. Without
//     relying-party signer pins, authorisation is NEVER "verified".
//  C. Strict Ed25519: small-order keys, non-canonical points, small-order R and
//     S >= L are rejected regardless of the native WebCrypto backend.
//  D. Deterministic; the CLI binary prints exactly what the library formats.

import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";

import {
  computeDisputeBundleId,
  decodeCanonicalBase64,
  decodeEd25519Point,
  formatDisputeVerification,
  isSmallOrderEd25519,
  keyFingerprint,
  strictEd25519Reason,
  verifyDisputeBundle,
  verifyEd25519,
} from "../packages/verify/dist/index.js";
import {
  KEYS,
  L,
  UNIVERSAL_SIGNATURE,
  WEAK,
  buildVariants,
  cliArgs,
  keyFromSeed,
  signDoc,
  variantFiles,
} from "./s1-variants.mjs";

const variants = await buildVariants();
const run = (v) => verifyDisputeBundle(v.bundle, v.opts);

// ---- A + B: every variant ------------------------------------------------------

for (const v of variants) {
  test(`variant: ${v.name}`, async () => {
    const r = await run(v);
    assert.equal(r.valid, v.expect.valid, JSON.stringify({ code: r.code, reason: r.reason }));
    assert.equal(r.complete, v.expect.complete, JSON.stringify(r.evidence_gaps));
    assert.equal(r.authorisation, v.expect.authorisation);
    if (!v.expect.valid) {
      assert.equal(r.code, v.expect.code);
      return;
    }
    assert.deepEqual((r.warnings ?? []).map((w) => w.code).sort(), [...v.expect.warnings].sort());
  });
}

test("B: authorisation is NEVER 'verified' without a valid relying-party pin", async () => {
  for (const v of variants) {
    const r = await run(v);
    const unpinned = await verifyDisputeBundle(v.bundle, { trust: v.opts.trust });
    assert.notEqual(unpinned.authorisation, "verified", `${v.name}: verified without pins`);
    if (r.authorisation === "verified") {
      assert.ok(v.opts.trusted_signers?.length, v.name);
      assert.ok(r.signatures.length > 0 && r.signatures.every((s) => s.principal_authenticated), v.name);
      assert.ok(r.signatures.every((s) => s.key_class === "trusted_signer"), v.name);
    }
  }
});

test("B: per-signature facts keep the five notions distinct", async () => {
  const byName = Object.fromEntries(await Promise.all(variants.map(async (v) => [v.name, await run(v)])));
  const legacy = byName["legacy as produced by the pre-fix code"];
  assert.ok(legacy.signatures.every((s) => s.cryptographically_valid && s.key_class === "recognised_recorder" && !s.principal_authenticated));
  const unrecognised = byName["all documents signed by an UNRECOGNISED principal key"];
  assert.ok(unrecognised.signatures.every((s) => s.cryptographically_valid && s.key_class === "unrecognised" && !s.principal_authenticated));
  assert.equal(unrecognised.complete, true, "evidence completeness is unchanged for historical-style bundles");
  assert.equal(unrecognised.authorisation, "unauthenticated");
  const wrongParty = byName["pinned key bound to the WRONG party"];
  assert.ok(wrongParty.signatures.every((s) => s.key_class === "trusted_signer" && !s.principal_authenticated));
  const pinned = byName["PINNED principal key for payer_demo_001, all roles"];
  assert.ok(pinned.signatures.every((s) => s.key_class === "trusted_signer" && s.principal_authenticated && s.expected_party === "payer_demo_001"));
  assert.equal(pinned.authorisation, "verified");
  const unsigned = byName["all unsigned; root FORGED as principal_signature with an unknown key"];
  assert.ok(unsigned.signatures.every((s) => s.key_class === null && !s.cryptographically_valid));
});

test("A: no variant with a recorder signature, unbacked root, or keyless signature is complete", async () => {
  for (const v of variants) {
    const r = await run(v);
    if ((r.warnings ?? []).some((w) => w.code === "RECORDER_SIGNED_NOT_PRINCIPAL" || w.code === "ROOT_ATTESTATION_UNVERIFIED")) {
      assert.equal(r.complete, false, v.name);
    }
    if (v.name.startsWith("KEYLESS")) assert.equal(r.valid, false, v.name);
  }
});

// ---- D: determinism and CLI == library -------------------------------------------

test("D: repeated runs, reversed trust order, reordered JSON give identical output", async () => {
  const reverseKeys = (x) =>
    Array.isArray(x)
      ? x.map(reverseKeys)
      : x && typeof x === "object"
        ? Object.fromEntries(Object.keys(x).reverse().map((k) => [k, reverseKeys(x[k])]))
        : x;
  for (const v of variants) {
    const base = formatDisputeVerification(await run(v));
    for (let i = 0; i < 3; i++) {
      assert.equal(formatDisputeVerification(await verifyDisputeBundle(structuredClone(v.bundle), v.opts)), base, `${v.name}: run ${i}`);
    }
    const reversedTrust = { ...v.opts, trust: { ...v.opts.trust, recorder_keys: [...v.opts.trust.recorder_keys].reverse() } };
    assert.equal(formatDisputeVerification(await verifyDisputeBundle(v.bundle, reversedTrust)), base, `${v.name}: trust order`);
    assert.equal(formatDisputeVerification(await verifyDisputeBundle(reverseKeys(v.bundle), v.opts)), base, `${v.name}: key order`);
  }
});

test("D: the CLI binary prints exactly what the library formats, for every variant", async () => {
  const dir = "test/tmp-s1-review";
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  try {
    for (const v of variantFiles(dir, variants, writeFileSync, join)) {
      const out = spawnSync(process.execPath, cliArgs(v), { encoding: "utf8" });
      assert.equal(out.stdout, formatDisputeVerification(await run(v)), v.name);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("D: --require-verified-authorisation fails closed unless authorisation is verified", async () => {
  const dir = "test/tmp-s1-review-require";
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  try {
    for (const v of variantFiles(dir, variants, writeFileSync, join)) {
      if (!v.expect.valid) continue;
      const out = spawnSync(process.execPath, [...cliArgs(v), "--require-verified-authorisation"], { encoding: "utf8" });
      assert.equal(out.status, v.expect.authorisation === "verified" ? 0 : 1, v.name);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- wording -----------------------------------------------------------------

test("B: report wording never presents an unrecognised key as an authenticated principal", async () => {
  for (const v of variants) {
    const text = formatDisputeVerification(await run(v));
    const lines = text.split("\n");
    assert.match(lines[1], /^authorisation: /, `${v.name}: authorisation must be line 2`);
    if (!v.opts.trusted_signers) {
      assert.doesNotMatch(text, /AUTHENTICATED|^authorisation: verified/m, v.name);
    }
    for (const line of lines.filter((l) => l.startsWith("signature ["))) {
      if (/key unrecognised|key recognised recorder/.test(line)) assert.match(line, /principal not authenticated/, line);
    }
    if (/^VALID \(complete\)/m.test(text) && !v.opts.trusted_signers) {
      assert.match(text, /^authorisation: unauthenticated — /m, `${v.name}: complete must state unauthenticated`);
    }
  }
});

test("self-generated keys: two unrelated keys get the identical verdict; neither is authenticated", async () => {
  const self = variants.find((v) => v.name.startsWith("self-generated key"));
  const attacker = generateKeyPairSync("ed25519");
  const key = {
    privateKey: attacker.privateKey,
    publicKeyBase64: attacker.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
  };
  const forged = structuredClone(self.bundle);
  for (const holder of [forged.evidence.mandate, forged.evidence.delegation.chain[0], forged.evidence.consent]) {
    holder.document = await signDoc(holder.document, key, "acme-root");
    if ("document_signature" in holder) holder.document_signature = holder.document.document_signature;
  }
  const s = forged.evidence.mandate.document.document_signature;
  forged.evidence.delegation.root.attestation = { basis: "principal_signature", key_id: s.key_id, public_key_base64: s.public_key_base64, signature_base64: s.signature_base64 };
  forged.bundle_id = await computeDisputeBundleId(forged);
  const a = await run(self);
  const b = await verifyDisputeBundle(forged, self.opts);
  for (const r of [a, b]) {
    assert.equal(r.complete, true);
    assert.equal(r.authorisation, "unauthenticated");
    assert.ok(r.signatures.every((x) => x.key_class === "unrecognised" && !x.principal_authenticated));
  }
});

// ---- C: strict Ed25519 ---------------------------------------------------------

const MSG = new TextEncoder().encode("sheaf strict ed25519 vector");
function honest() {
  const k = keyFromSeed(0x07);
  const sig = sign(null, MSG, k.privateKey);
  return { pub: Buffer.from(k.publicKeyBase64, "base64"), sig };
}
function withS(sig, s) {
  const out = Buffer.from(sig);
  let n = s;
  for (let i = 32; i < 64; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
const sOf = (sig) => { let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) + BigInt(sig[i]); return s; };
const b64 = (x) => Buffer.from(x).toString("base64");

test("C: honest signatures pass strict verification", async () => {
  const { pub, sig } = honest();
  assert.equal(strictEd25519Reason(pub, sig), null);
  assert.equal(await verifyEd25519(b64(pub), b64(sig), MSG), true);
  // 64 random honest keys: never small order, always canonical.
  for (let i = 0; i < 64; i++) {
    const pk = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const p = decodeEd25519Point(pk);
    assert.ok(p, "honest key decodes");
    assert.equal(isSmallOrderEd25519(p), false);
  }
});

test("C: small-order points are detected by computation (8·P = identity)", () => {
  for (const [name, enc] of Object.entries({ identity: WEAK.identity, order2: WEAK.order2, order4: WEAK.order4, order8a: WEAK.order8a, order8b: WEAK.order8b })) {
    const p = decodeEd25519Point(enc);
    assert.ok(p, `${name} is a valid curve point`);
    assert.equal(isSmallOrderEd25519(p), true, `${name} is small order`);
  }
});

test("C: decoding never mutates its input (Buffer#slice is a view)", () => {
  const input = Buffer.from(WEAK.identityNegZero);
  const before = input.toString("hex");
  decodeEd25519Point(input);
  strictEd25519Reason(input, UNIVERSAL_SIGNATURE);
  assert.equal(input.toString("hex"), before);
});

test("C: non-canonical encodings are rejected at decoding", () => {
  assert.equal(decodeEd25519Point(WEAK.identityNegZero), null, "negative zero");
  assert.equal(decodeEd25519Point(WEAK.identityYplusP), null, "y = p + 1");
  const yEqualsP = Buffer.from("ed" + "ff".repeat(30) + "7f", "hex");
  assert.equal(decodeEd25519Point(yEqualsP), null, "y = p");
  assert.equal(decodeCanonicalBase64(b64(WEAK.identity).replace(/=+$/, ""), 32), null, "unpadded base64");
  assert.equal(keyFingerprint(b64(WEAK.identity).replace(/=+$/, "")), keyFingerprint(b64(WEAK.identity)));
});

test("C: strict profile rejects every weak / malleated case with a stable reason", async () => {
  const { pub, sig } = honest();
  const cases = [
    ["identity key + universal sig", WEAK.identity, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_SMALL_ORDER"],
    ["negative-zero identity + universal sig", WEAK.identityNegZero, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_NON_CANONICAL_OR_INVALID"],
    ["y=p+1 identity + universal sig", WEAK.identityYplusP, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_NON_CANONICAL_OR_INVALID"],
    ["order-2 key", WEAK.order2, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_SMALL_ORDER"],
    ["order-4 key", WEAK.order4, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_SMALL_ORDER"],
    ["order-8 key a", WEAK.order8a, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_SMALL_ORDER"],
    ["order-8 key b", WEAK.order8b, UNIVERSAL_SIGNATURE, "PUBLIC_KEY_SMALL_ORDER"],
    ["S + L", pub, withS(sig, sOf(sig) + L), "SIGNATURE_S_NOT_REDUCED"],
    ["S = L", pub, withS(sig, L), "SIGNATURE_S_NOT_REDUCED"],
    ["S = 2^256 - 1", pub, withS(sig, 2n ** 256n - 1n), "SIGNATURE_S_NOT_REDUCED"],
    ["R = identity", pub, Buffer.concat([WEAK.identity, sig.subarray(32)]), "SIGNATURE_R_SMALL_ORDER"],
    ["R = order-8 point", pub, Buffer.concat([WEAK.order8a, sig.subarray(32)]), "SIGNATURE_R_SMALL_ORDER"],
    ["R non-canonical (negative zero)", pub, Buffer.concat([WEAK.identityNegZero, sig.subarray(32)]), "SIGNATURE_R_NON_CANONICAL_OR_INVALID"],
    ["truncated signature", pub, sig.subarray(0, 63), "SIGNATURE_LENGTH"],
    ["31-byte key", pub.subarray(0, 31), sig, "PUBLIC_KEY_LENGTH"],
  ];
  for (const [name, A, S, reason] of cases) {
    assert.equal(strictEd25519Reason(A, S), reason, name);
    if (A.length === 32) assert.equal(await verifyEd25519(b64(A), b64(S), MSG), false, `${name}: verifyEd25519`);
  }
  // The keyless signature must be rejected for every message.
  for (let i = 0; i < 32; i++) {
    const m = new TextEncoder().encode("any message " + i);
    assert.equal(await verifyEd25519(b64(WEAK.identity), b64(UNIVERSAL_SIGNATURE), m), false);
  }
});

test("C (diagnostic): measured behaviour of the native WebCrypto backend", async (t) => {
  // Not asserted: this records what the platform does underneath the strict
  // profile, so a backend change is visible in the test log.
  const subtle = globalThis.crypto.subtle;
  const spki = (raw) => Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const native = async (A, S, m) => {
    try {
      const key = await subtle.importKey("spki", spki(A), { name: "Ed25519" }, false, ["verify"]);
      return await subtle.verify("Ed25519", key, S, m);
    } catch (e) {
      return `error:${e?.name}`;
    }
  };
  const { pub, sig } = honest();
  t.diagnostic(`runtime node ${process.version} openssl ${process.versions.openssl}`);
  t.diagnostic(`native: identity key + universal sig -> ${await native(WEAK.identity, UNIVERSAL_SIGNATURE, MSG)}`);
  t.diagnostic(`native: negative-zero identity + universal sig -> ${await native(WEAK.identityNegZero, UNIVERSAL_SIGNATURE, MSG)}`);
  t.diagnostic(`native: S + L -> ${await native(pub, withS(sig, sOf(sig) + L), MSG)}`);
  t.diagnostic(`strict (this library): identity key + universal sig -> ${await verifyEd25519(b64(WEAK.identity), b64(UNIVERSAL_SIGNATURE), MSG)}`);
});
