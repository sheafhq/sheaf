// SAP Phase 2: identity (docs/SAP-ARCHITECTURE.md §5.1, §8.5).
//
// Scope, as approved 2026-11-18:
//   1. sheaf.identity/1 inceptions for roots and non-roots. A root inception
//      must carry signatures from >= threshold of its recovery keys.
//   2. A relying-party pin file of ROOT sids (sheaf.identity-pins/1).
//   3. resolveKey(sid, key_id, at) for inceptions only. Any key event on the
//      path fails closed (key lifecycle lands in Phase 6).
//   4. Fail-closed codes: UNKNOWN_IDENTITY, UNTRUSTED_ROOT, KEY_NOT_VALID,
//      INVALID_SIGNATURE (+ INVALID_IDENTITY_DOCUMENT, INVALID_PIN_FILE,
//      UNVERIFIED_KEY_STATE for malformed input and key events).
// Revocation is not verified before Phase 6: every success reports
// revocation: "UNVERIFIED_REVOCATION_STATE".
//
// Pure: no I/O, no clock, no randomness. Time is always an input (`at`).
//
// Rules beyond the §5.1 text, chosen fail-closed (see README):
//   - Every key in `keys` must sign the inception (proof of possession).
//     Otherwise an identity could list SOMEONE ELSE's public key, and that
//     party's signatures would be attributed to it.
//   - A non-root is signed by its controller's signing key AND by its own
//     keys (proof of possession).
//   - Inline public keys are never consulted: callers pass (sid, key_id) and
//     the key comes only from the verified inception.

import {
  canonicalize,
  decodeCanonicalBase64,
  sha256Hex,
  strictEd25519Reason,
  verifyEd25519,
} from "./crypto.js";

export const IDENTITY_SCHEMA = "sheaf.identity/1";
export const IDENTITY_PINS_SCHEMA = "sheaf.identity-pins/1";
export const KEY_EVENT_SCHEMA = "sheaf.key-event/1";

/** Longest controller chain (agent → … → root) resolveKey will walk. */
export const MAX_CONTROLLER_DEPTH = 8;

export type IdentityType = "organisation" | "human" | "agent" | "service";

export type IdentityKey = { key_id: string; alg: "Ed25519"; public_key: string };

export type IdentitySigner = { key_id: string; identity?: string };

export type IdentityDocument = {
  schema: typeof IDENTITY_SCHEMA;
  type: IdentityType;
  handle: string;
  display_name: string;
  controller: string | null;
  keys: IdentityKey[];
  next_key_digest?: string;
  recovery?: { threshold: number; keys: IdentityKey[] };
  created_at: string;
  nonce: string;
  signers: IdentitySigner[];
  signatures: string[];
};

export type IdentityPins = {
  schema: typeof IDENTITY_PINS_SCHEMA;
  pins: { sid: string; label?: string }[];
};

export type IdentityErrorCode =
  | "UNKNOWN_IDENTITY"
  | "UNTRUSTED_ROOT"
  | "KEY_NOT_VALID"
  | "INVALID_SIGNATURE"
  | "INVALID_IDENTITY_DOCUMENT"
  | "INVALID_PIN_FILE"
  | "UNVERIFIED_KEY_STATE";

export type ResolveFailure = { ok: false; code: IdentityErrorCode; reason: string };

export type ResolvedKey = {
  ok: true;
  sid: string;
  key_id: string;
  /** Canonical base64 of the 32-byte Ed25519 key, from the verified inception. */
  public_key: string;
  root_sid: string;
  /** sid of the identity first, then each controller up to the pinned root. */
  path: string[];
  key_state: "INCEPTION_ONLY";
  revocation: "UNVERIFIED_REVOCATION_STATE";
  assumptions: string[];
};

export type ResolveInput = {
  sid: string;
  key_id: string;
  /** RFC 3339 UTC time the key is claimed to have been used. */
  at: string;
  /** Identity documents available to the verifier (any order; duplicates ok). */
  identities: unknown[];
  /** The relying party's own pin file. Never taken from a bundle. */
  pins: unknown;
  /** Key events presented with the evidence. Phase 2 cannot evaluate them. */
  key_events?: unknown[];
  /** Pinned recorder keys (base64). A recorder key can never be an identity key. */
  recorder_keys?: string[];
};

export const ASSUMPTIONS: readonly string[] = [
  "the relying party's pinned root sids belong to the intended organisations (bound out of band)",
  "key state is inception-only: key events (rotation, recovery, identity revocation) are not evaluated before SAP Phase 6, and any presented key event fails closed",
  "revocation is not verified before SAP Phase 6 (UNVERIFIED_REVOCATION_STATE)",
  "created_at is self-asserted by the identity's signers",
];

// ---------------------------------------------------------------- helpers ---

const SID_RE = /^sid:[0-9a-f]{64}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const KEY_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const TYPES: ReadonlySet<string> = new Set(["organisation", "human", "agent", "service"]);
const ROOT_KEYS = ["schema", "type", "handle", "display_name", "controller", "keys", "next_key_digest", "recovery", "created_at", "nonce", "signers", "signatures"];
const MAX_KEYS = 8;
const MAX_RECOVERY_KEYS = 16;

const fail = (code: IdentityErrorCode, reason: string): ResolveFailure => ({ ok: false, code, reason });

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function parseRfc3339Utc(value: unknown): number | null {
  if (typeof value !== "string" || !RFC3339_UTC_RE.test(value)) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? t : null;
}

/** `sha256:<hex>` of the raw 32 public-key bytes (the next_key_digest form). */
export async function keyDigest(publicKeyBase64: string): Promise<string | null> {
  const raw = decodeCanonicalBase64(publicKeyBase64, 32);
  return raw ? `sha256:${await sha256Hex(raw)}` : null;
}

/** Hex SHA-256 of JCS(document − signature − signatures): the signed message. */
export async function identityDocHash(doc: Record<string, unknown>): Promise<string> {
  const body: Record<string, unknown> = { ...doc };
  delete body.signature;
  delete body.signatures;
  return sha256Hex(canonicalize(body));
}

/** The self-certifying identity id: `sid:<doc_hash>`. */
export async function identitySid(doc: Record<string, unknown>): Promise<string> {
  return `sid:${await identityDocHash(doc)}`;
}

// ------------------------------------------------------------- validation ---

function validateKey(k: unknown, where: string, errors: string[]): void {
  if (!isObject(k)) {
    errors.push(`${where}: object required`);
    return;
  }
  const extra = Object.keys(k).filter((x) => !["key_id", "alg", "public_key"].includes(x));
  if (extra.length) errors.push(`${where}: unknown field(s) ${extra.sort().join(", ")}`);
  if (typeof k.key_id !== "string" || !KEY_ID_RE.test(k.key_id)) errors.push(`${where}.key_id: 1-64 of [A-Za-z0-9._:-] required`);
  if (k.alg !== "Ed25519") errors.push(`${where}.alg: must be "Ed25519"`);
  const raw = decodeCanonicalBase64(k.public_key, 32);
  if (!raw) {
    errors.push(`${where}.public_key: canonical base64 of 32 bytes required`);
    return;
  }
  // A valid signature is needed to run the full strict check; reuse it with a
  // dummy well-formed signature only for the key-related reasons.
  const reason = strictEd25519Reason(raw, DUMMY_SIGNATURE);
  if (reason === "PUBLIC_KEY_NON_CANONICAL_OR_INVALID" || reason === "PUBLIC_KEY_SMALL_ORDER" || reason === "PUBLIC_KEY_LENGTH") {
    errors.push(`${where}.public_key: rejected by strict Ed25519 (${reason})`);
  }
}

// R = the Ed25519 base point (canonical, prime order), S = 0. Used only so
// strictEd25519Reason reaches its public-key checks; never verified.
const DUMMY_SIGNATURE = (() => {
  const s = new Uint8Array(64);
  s[0] = 0x58;
  for (let i = 1; i < 32; i++) s[i] = 0x66;
  return s;
})();

/**
 * Structural + semantic validation of one inception (no signatures checked).
 * Returns a list of errors; empty means well-formed.
 */
export function validateIdentityDocument(doc: unknown, recorderKeys: string[] = []): string[] {
  const errors: string[] = [];
  if (!isObject(doc)) return ["identity: object required"];
  const extra = Object.keys(doc).filter((k) => !ROOT_KEYS.includes(k));
  if (extra.length) errors.push(`identity: unknown field(s) ${extra.sort().join(", ")}`);
  if (doc.schema !== IDENTITY_SCHEMA) errors.push(`identity.schema: must be "${IDENTITY_SCHEMA}"`);
  if (typeof doc.type !== "string" || !TYPES.has(doc.type)) errors.push("identity.type: organisation | human | agent | service");
  for (const f of ["handle", "display_name"]) {
    const v = doc[f];
    if (typeof v !== "string" || v.length < 1 || v.length > 256) errors.push(`identity.${f}: string of 1-256 characters required`);
  }
  if (parseRfc3339Utc(doc.created_at) === null) errors.push("identity.created_at: RFC 3339 UTC (…Z) required");
  if (!decodeCanonicalBase64(doc.nonce, 16)) errors.push("identity.nonce: canonical base64 of 16 bytes required");

  const isRoot = doc.controller === null;
  if (!isRoot && !(typeof doc.controller === "string" && SID_RE.test(doc.controller))) {
    errors.push("identity.controller: null (root) or sid:<64 hex> required");
  }

  if (!Array.isArray(doc.keys) || doc.keys.length < 1 || doc.keys.length > MAX_KEYS) {
    errors.push(`identity.keys: 1-${MAX_KEYS} keys required`);
  } else {
    doc.keys.forEach((k, i) => validateKey(k, `identity.keys[${i}]`, errors));
  }

  if (isRoot) {
    if (typeof doc.next_key_digest !== "string" || !DIGEST_RE.test(doc.next_key_digest)) {
      errors.push("identity.next_key_digest: required for a root, sha256:<64 hex>");
    }
    const rec = doc.recovery;
    if (!isObject(rec)) {
      errors.push("identity.recovery: required for a root");
    } else {
      const rextra = Object.keys(rec).filter((k) => !["threshold", "keys"].includes(k));
      if (rextra.length) errors.push(`identity.recovery: unknown field(s) ${rextra.sort().join(", ")}`);
      if (!Array.isArray(rec.keys) || rec.keys.length < 1 || rec.keys.length > MAX_RECOVERY_KEYS) {
        errors.push(`identity.recovery.keys: 1-${MAX_RECOVERY_KEYS} keys required`);
      } else {
        rec.keys.forEach((k, i) => validateKey(k, `identity.recovery.keys[${i}]`, errors));
        if (!Number.isInteger(rec.threshold) || (rec.threshold as number) < 1 || (rec.threshold as number) > rec.keys.length) {
          errors.push("identity.recovery.threshold: integer from 1 to the number of recovery keys required");
        }
      }
    }
  } else {
    if ("recovery" in doc) errors.push("identity.recovery: not allowed on a non-root (its controller is its recovery path)");
    if ("next_key_digest" in doc && !(typeof doc.next_key_digest === "string" && DIGEST_RE.test(doc.next_key_digest))) {
      errors.push("identity.next_key_digest: sha256:<64 hex>");
    }
  }

  // Distinct key ids and key bytes across signing + recovery keys; never a
  // recorder key (S1: a recorder key must never stand in for a principal).
  const all: IdentityKey[] = [
    ...(Array.isArray(doc.keys) ? (doc.keys as IdentityKey[]) : []),
    ...(isObject(doc.recovery) && Array.isArray(doc.recovery.keys) ? (doc.recovery.keys as IdentityKey[]) : []),
  ].filter(isObject) as IdentityKey[];
  const ids = new Set<string>();
  const bytes = new Set<string>();
  const recorder = new Set(
    recorderKeys.map((k) => decodeCanonicalBase64(k, 32)).filter((b): b is Uint8Array => !!b).map(hex),
  );
  for (const k of all) {
    if (ids.has(k.key_id)) errors.push(`identity: duplicate key_id ${String(k.key_id)}`);
    ids.add(k.key_id);
    const raw = decodeCanonicalBase64(k.public_key, 32);
    if (!raw) continue;
    const h = hex(raw);
    if (bytes.has(h)) errors.push(`identity: the same public key appears twice (key_id ${String(k.key_id)})`);
    bytes.add(h);
    if (recorder.has(h)) errors.push(`identity: key_id ${String(k.key_id)} is a pinned recorder key`);
  }

  // signers ↔ signatures
  if (!Array.isArray(doc.signers) || !Array.isArray(doc.signatures) || doc.signers.length !== doc.signatures.length || doc.signers.length === 0) {
    errors.push("identity.signers / identity.signatures: non-empty arrays of equal length required");
  } else {
    const seen = new Set<string>();
    doc.signers.forEach((s, i) => {
      if (!isObject(s)) {
        errors.push(`identity.signers[${i}]: object required`);
        return;
      }
      const sx = Object.keys(s).filter((k) => !["key_id", "identity"].includes(k));
      if (sx.length) errors.push(`identity.signers[${i}]: unknown field(s) ${sx.sort().join(", ")}`);
      if (typeof s.key_id !== "string" || !KEY_ID_RE.test(s.key_id)) errors.push(`identity.signers[${i}].key_id: invalid`);
      if ("identity" in s && !(typeof s.identity === "string" && SID_RE.test(s.identity))) {
        errors.push(`identity.signers[${i}].identity: sid:<64 hex> required when present`);
      }
      const key = `${String(s.identity ?? "self")}#${String(s.key_id)}`;
      if (seen.has(key)) errors.push(`identity.signers[${i}]: duplicate signer`);
      seen.add(key);
    });
    doc.signatures.forEach((sig, i) => {
      if (!decodeCanonicalBase64(sig, 64)) errors.push(`identity.signatures[${i}]: canonical base64 of 64 bytes required`);
    });
  }
  return errors;
}

/** Validate a relying-party pin file. Returns errors; empty means valid. */
export function validateIdentityPins(pins: unknown): string[] {
  if (!isObject(pins)) return ["pins: object required"];
  const errors: string[] = [];
  const extra = Object.keys(pins).filter((k) => !["schema", "pins"].includes(k));
  if (extra.length) errors.push(`pins: unknown field(s) ${extra.sort().join(", ")}`);
  if (pins.schema !== IDENTITY_PINS_SCHEMA) errors.push(`pins.schema: must be "${IDENTITY_PINS_SCHEMA}"`);
  if (!Array.isArray(pins.pins) || pins.pins.length === 0) {
    errors.push("pins.pins: non-empty array required");
    return errors;
  }
  const seen = new Set<string>();
  pins.pins.forEach((p, i) => {
    if (!isObject(p)) {
      errors.push(`pins.pins[${i}]: object required`);
      return;
    }
    const px = Object.keys(p).filter((k) => !["sid", "label"].includes(k));
    if (px.length) errors.push(`pins.pins[${i}]: unknown field(s) ${px.sort().join(", ")}`);
    if (typeof p.sid !== "string" || !SID_RE.test(p.sid)) errors.push(`pins.pins[${i}].sid: sid:<64 hex> required`);
    else if (seen.has(p.sid)) errors.push(`pins.pins[${i}].sid: duplicate`);
    else seen.add(p.sid);
    if ("label" in p && (typeof p.label !== "string" || p.label.length > 256)) errors.push(`pins.pins[${i}].label: string up to 256 characters`);
  });
  return errors;
}

// ----------------------------------------------------------- verification ---

type Indexed = { sid: string; doc: IdentityDocument };

async function verifySig(publicKey: string, signature: string, digestHex: string): Promise<boolean> {
  try {
    return await verifyEd25519(publicKey, signature, hexToBytes(digestHex));
  } catch {
    return false;
  }
}

/**
 * Verify one inception's own signatures. `controller` is the already-verified
 * controller document for a non-root (null for a root).
 */
async function verifyInceptionSignatures(
  item: Indexed,
  controller: Indexed | null,
): Promise<ResolveFailure | null> {
  const { doc, sid } = item;
  const digest = sid.slice("sid:".length);

  // Pre-rotation must commit to a NEW key: a next_key_digest that matches a
  // key already in the document would let that key "rotate" to itself.
  if (doc.next_key_digest !== undefined) {
    for (const k of [...doc.keys, ...(doc.recovery?.keys ?? [])]) {
      if ((await keyDigest(k.public_key)) === doc.next_key_digest) {
        return fail("INVALID_IDENTITY_DOCUMENT", `${sid}: next_key_digest commits to existing key ${k.key_id}`);
      }
    }
  }
  const own = new Map(doc.keys.map((k) => [k.key_id, k]));
  const recovery = new Map((doc.recovery?.keys ?? []).map((k) => [k.key_id, k]));
  const signedOwn = new Set<string>();
  const signedRecovery = new Set<string>();
  let controllerSigned = false;

  for (let i = 0; i < doc.signers.length; i++) {
    const s = doc.signers[i]!;
    const sig = doc.signatures[i]!;
    let key: IdentityKey | undefined;
    if (s.identity !== undefined) {
      if (!controller || s.identity !== controller.sid) {
        return fail("INVALID_SIGNATURE", `${sid}: signer ${s.identity}#${s.key_id} is not this identity's controller`);
      }
      key = controller.doc.keys.find((k) => k.key_id === s.key_id);
      if (!key) {
        return fail("KEY_NOT_VALID", `${sid}: controller key ${s.key_id} is not a signing key of ${controller.sid}`);
      }
    } else {
      key = own.get(s.key_id) ?? recovery.get(s.key_id);
      if (!key) return fail("INVALID_SIGNATURE", `${sid}: signer key_id ${s.key_id} is not a key of this identity`);
    }
    if (!(await verifySig(key.public_key, sig, digest))) {
      return fail("INVALID_SIGNATURE", `${sid}: signature by ${s.identity ? `${s.identity}#` : ""}${s.key_id} does not verify (strict Ed25519)`);
    }
    if (s.identity !== undefined) controllerSigned = true;
    else if (own.has(s.key_id)) signedOwn.add(s.key_id);
    else signedRecovery.add(s.key_id);
  }

  for (const k of doc.keys) {
    if (!signedOwn.has(k.key_id)) {
      return fail("INVALID_SIGNATURE", `${sid}: signing key ${k.key_id} did not sign the inception (proof of possession required)`);
    }
  }
  if (doc.controller === null) {
    const threshold = doc.recovery!.threshold;
    if (signedRecovery.size < threshold) {
      return fail(
        "INVALID_SIGNATURE",
        `${sid}: root inception has ${signedRecovery.size} valid recovery signature(s); ${threshold} required`,
      );
    }
  } else if (!controllerSigned) {
    return fail("INVALID_SIGNATURE", `${sid}: non-root inception is not signed by its controller ${doc.controller}`);
  }
  return null;
}

function keyEventIdentity(ev: unknown): string | null {
  return isObject(ev) && typeof ev.identity === "string" ? ev.identity : null;
}

/**
 * Resolve the Ed25519 key that `sid` may use under `key_id` at time `at`,
 * walking controllers up to a root the relying party pinned.
 *
 * Fails closed with a single code. On success the key comes ONLY from a
 * verified inception; nothing else in the evidence can introduce a key.
 */
export async function resolveKey(input: ResolveInput): Promise<ResolvedKey | ResolveFailure> {
  const pinErrors = validateIdentityPins(input.pins);
  if (pinErrors.length) return fail("INVALID_PIN_FILE", pinErrors.join("; "));
  const pinned = new Set((input.pins as IdentityPins).pins.map((p) => p.sid));

  if (typeof input.sid !== "string" || !SID_RE.test(input.sid)) {
    return fail("UNKNOWN_IDENTITY", `"${String(input.sid)}" is not a sid`);
  }
  const at = parseRfc3339Utc(input.at);
  if (at === null) return fail("KEY_NOT_VALID", "`at` must be an RFC 3339 UTC time");

  // Index the supplied identities by their computed sid. A document is only
  // ever found under the hash of its own content.
  const recorderKeys = input.recorder_keys ?? [];
  const bySid = new Map<string, unknown>();
  for (const doc of Array.isArray(input.identities) ? input.identities : []) {
    if (!isObject(doc)) continue;
    let sid: string;
    try {
      sid = await identitySid(doc);
    } catch {
      continue;
    }
    if (!bySid.has(sid)) bySid.set(sid, doc);
  }

  // Walk target → controller → … → root.
  const chain: Indexed[] = [];
  let current = input.sid;
  for (;;) {
    if (chain.some((c) => c.sid === current)) return fail("UNTRUSTED_ROOT", `controller cycle at ${current}`);
    if (chain.length >= MAX_CONTROLLER_DEPTH) {
      return fail("UNTRUSTED_ROOT", `controller chain longer than ${MAX_CONTROLLER_DEPTH} without reaching a root`);
    }
    const raw = bySid.get(current);
    if (raw === undefined) {
      return fail(
        "UNKNOWN_IDENTITY",
        chain.length === 0
          ? `no supplied identity document hashes to ${current}`
          : `controller ${current} of ${chain[chain.length - 1]!.sid} was not supplied`,
      );
    }
    const errors = validateIdentityDocument(raw, recorderKeys);
    if (errors.length) return fail("INVALID_IDENTITY_DOCUMENT", `${current}: ${errors.join("; ")}`);
    const doc = raw as IdentityDocument;
    chain.push({ sid: current, doc });
    if (doc.controller === null) break;
    current = doc.controller;
  }
  const root = chain[chain.length - 1]!;
  if (!pinned.has(root.sid)) {
    return fail(
      "UNTRUSTED_ROOT",
      chain.length === 1
        ? `${root.sid} is a root but is not in the relying party's pins`
        : `${input.sid} resolves to root ${root.sid}, which is not in the relying party's pins`,
    );
  }
  // Pinning a non-root has no effect: trust always comes from the root at the
  // end of the controller chain.

  // Phase 2 cannot evaluate key events. Anything that could change key state
  // for an identity on the path fails closed, as does an unattributable event.
  const pathSids = new Set(chain.map((c) => c.sid));
  for (const ev of input.key_events ?? []) {
    const who = keyEventIdentity(ev);
    if (who === null || pathSids.has(who)) {
      return fail(
        "UNVERIFIED_KEY_STATE",
        who === null
          ? "a key event without a valid identity was presented; key events are not supported before SAP Phase 6"
          : `a key event for ${who} was presented; key events are not supported before SAP Phase 6`,
      );
    }
  }

  // Verify signatures root-first, so each controller is verified before it
  // vouches for its child.
  for (let i = chain.length - 1; i >= 0; i--) {
    const item = chain[i]!;
    const controller = i + 1 < chain.length ? chain[i + 1]! : null;
    if (controller) {
      // The controller's key must have existed when the child was created.
      if (parseRfc3339Utc(item.doc.created_at)! < parseRfc3339Utc(controller.doc.created_at)!) {
        return fail("KEY_NOT_VALID", `${item.sid} was created before its controller ${controller.sid}`);
      }
    }
    const failure = await verifyInceptionSignatures(item, controller);
    if (failure) return failure;
  }

  const target = chain[0]!;
  const key = target.doc.keys.find((k) => k.key_id === input.key_id);
  if (!key) {
    const isRecovery = (target.doc.recovery?.keys ?? []).some((k) => k.key_id === input.key_id);
    return fail(
      "KEY_NOT_VALID",
      isRecovery
        ? `${input.key_id} is a recovery key of ${target.sid}; recovery keys cannot sign ordinary documents`
        : `${input.key_id} is not a signing key of ${target.sid}`,
    );
  }
  if (at < parseRfc3339Utc(target.doc.created_at)!) {
    return fail("KEY_NOT_VALID", `${input.key_id} of ${target.sid} did not exist yet at ${input.at}`);
  }

  return {
    ok: true,
    sid: target.sid,
    key_id: key.key_id,
    public_key: key.public_key,
    root_sid: root.sid,
    path: chain.map((c) => c.sid),
    key_state: "INCEPTION_ONLY",
    revocation: "UNVERIFIED_REVOCATION_STATE",
    assumptions: [...ASSUMPTIONS],
  };
}

/**
 * Verify an Ed25519 signature over a 32-byte document digest, made by
 * (sid, key_id) at `at`. The public key is resolved from the identity log;
 * there is deliberately no way to pass one in.
 */
export async function verifyIdentitySignature(
  input: ResolveInput & { digest_hex: string; signature: string },
): Promise<ResolvedKey | ResolveFailure> {
  if (typeof input.digest_hex !== "string" || !/^[0-9a-f]{64}$/.test(input.digest_hex)) {
    return fail("INVALID_SIGNATURE", "digest_hex must be 64 lowercase hex characters");
  }
  if (!decodeCanonicalBase64(input.signature, 64)) {
    return fail("INVALID_SIGNATURE", "signature must be canonical base64 of 64 bytes");
  }
  const resolved = await resolveKey(input);
  if (!resolved.ok) return resolved;
  if (!(await verifySig(resolved.public_key, input.signature, input.digest_hex))) {
    return fail("INVALID_SIGNATURE", `signature by ${resolved.sid}#${resolved.key_id} does not verify (strict Ed25519)`);
  }
  return resolved;
}
