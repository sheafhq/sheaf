// Ed25519 signature verification using WebCrypto. Works in Node 18+, modern
// browsers, and Cloudflare Workers runtime.

const SPKI_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * Strict base64: standard alphabet, mandatory padding, no whitespace, and the
 * string must be the unique canonical encoding of its bytes (zero padding
 * bits). Returns null otherwise, or if the decoded length differs.
 *
 * Why: atob() and Buffer are lenient. They accept missing padding, embedded
 * whitespace and non-zero padding bits, so ONE key has many string spellings
 * that all verify. Comparing key strings is therefore unsafe (S1 review,
 * 2026-11-17: a re-spelled recorder key passed as a principal key).
 */
export function decodeCanonicalBase64(
  value: unknown,
  expectedLength: number,
): Uint8Array | null {
  if (typeof value !== "string" || value.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  let bytes: Uint8Array;
  try {
    bytes = b64decode(value);
  } catch {
    return null;
  }
  if (bytes.length !== expectedLength) return null;
  return b64encode(bytes) === value ? bytes : null;
}

// ---- Strict Ed25519 (S1 review, 2026-11-17) ------------------------------------
//
// Measured behaviour of the NATIVE WebCrypto Ed25519 verify that this library
// calls (Node 22 / OpenSSL 3.5.9, Node 24 / OpenSSL 3.5.5, Edge 157):
//   - enforces S < L (S+L and S=L malleations are rejected), but
//   - ACCEPTS small-order public keys: the identity key (also in its
//     negative-zero and y = p + 1 spellings) and order-8 torsion keys verify
//     the keyless "universal" signature R = identity, S = 0. For the identity
//     key that signature verifies for EVERY message: a signature that needs no
//     private key at all.
// So every signature is first checked against a strict profile (the
// libsodium rule set), identically in every runtime:
//   A and R: canonical encoding (y < p, no negative zero), on the curve,
//            and not of small order;  S < L.

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const fmod = (a: bigint): bigint => ((a % P) + P) % P;
function powMod(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = fmod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}
const inv = (a: bigint): bigint => powMod(a, P - 2n);
const D = fmod(-121665n * inv(121666n));
const SQRT_M1 = powMod(2n, (P - 1n) / 4n);

function leToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

type EdPoint = { x: bigint; y: bigint };

/** RFC 8032 §5.1.3 point decoding, strict. Returns null for y ≥ p, points not
 *  on the curve, and the non-canonical "negative zero" (x = 0, sign bit set). */
export function decodeEd25519Point(raw: Uint8Array): EdPoint | null {
  if (raw.length !== 32) return null;
  const sign = (raw[31]! >> 7) & 1;
  // Explicit copy: Buffer#slice returns a VIEW, and clearing the sign bit on
  // a view would mutate the caller's bytes.
  const yBytes = new Uint8Array(raw);
  yBytes[31] = yBytes[31]! & 0x7f;
  const y = leToBigInt(yBytes);
  if (y >= P) return null;
  const y2 = (y * y) % P;
  const uOverV = fmod(fmod(y2 - 1n) * inv(fmod(D * y2 + 1n)));
  let x = powMod(uOverV, (P + 3n) / 8n);
  const x2 = (x * x) % P;
  if (x2 !== uOverV) {
    if (x2 === fmod(-uOverV)) x = (x * SQRT_M1) % P;
    else return null; // not on the curve
  }
  if (x === 0n && sign === 1) return null; // negative zero
  if (Number(x & 1n) !== sign) x = fmod(-x);
  return { x, y };
}

function addPoints(a: EdPoint, b: EdPoint): EdPoint {
  // Complete twisted Edwards addition, a = -1.
  const xx = (a.x * b.x) % P;
  const yy = (a.y * b.y) % P;
  const dxxyy = (((D * xx) % P) * yy) % P;
  return {
    x: fmod((a.x * b.y + a.y * b.x) * inv(fmod(1n + dxxyy))),
    y: fmod((yy + xx) * inv(fmod(1n - dxxyy))),
  };
}

/** Small order ⇔ [8]P is the identity. Computed, not looked up. */
export function isSmallOrderEd25519(point: EdPoint): boolean {
  let q = point;
  for (let i = 0; i < 3; i++) q = addPoints(q, q);
  return q.x === 0n && q.y === 1n;
}

/** Canonical encoding of a point on the curve (y < p, no negative zero). */
export function isCanonicalEd25519Point(raw: Uint8Array): boolean {
  return decodeEd25519Point(raw) !== null;
}

/**
 * Strict-profile pre-check. Returns null when (A, signature) passes, otherwise
 * a stable reason code. Independent of the WebCrypto backend.
 */
export function strictEd25519Reason(
  rawPublicKey: Uint8Array,
  rawSignature: Uint8Array,
): string | null {
  if (rawPublicKey.length !== 32) return "PUBLIC_KEY_LENGTH";
  const A = decodeEd25519Point(rawPublicKey);
  if (!A) return "PUBLIC_KEY_NON_CANONICAL_OR_INVALID";
  if (isSmallOrderEd25519(A)) return "PUBLIC_KEY_SMALL_ORDER";
  if (rawSignature.length !== 64) return "SIGNATURE_LENGTH";
  const R = decodeEd25519Point(rawSignature.subarray(0, 32));
  if (!R) return "SIGNATURE_R_NON_CANONICAL_OR_INVALID";
  if (isSmallOrderEd25519(R)) return "SIGNATURE_R_SMALL_ORDER";
  if (leToBigInt(rawSignature.subarray(32)) >= L) return "SIGNATURE_S_NOT_REDUCED";
  return null;
}

/**
 * Canonical identity of an Ed25519 public key for comparisons: lowercase hex
 * of the raw 32 bytes, decoded LENIENTLY so that every spelling of the same
 * key maps to the same value. Returns null for anything that is not 32 bytes.
 * Never compare key strings directly; compare keyFingerprint() values.
 */
export function keyFingerprint(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let bytes: Uint8Array;
  try {
    bytes = b64decode(value);
  } catch {
    return null;
  }
  if (bytes.length !== 32) return null;
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyEd25519(
  publicKeyBase64: string,
  signatureBase64: string,
  message: Uint8Array,
): Promise<boolean> {
  const rawPub = b64decode(publicKeyBase64);
  if (rawPub.length !== 32)
    throw new Error("Ed25519 public key must be 32 bytes");
  // Strict profile first: the native backends accept small-order keys and
  // keyless "universal" signatures (see above). Never let them decide alone.
  let rawSig: Uint8Array;
  try {
    rawSig = b64decode(signatureBase64);
  } catch {
    return false;
  }
  if (strictEd25519Reason(rawPub, rawSig) !== null) return false;
  const spki = new Uint8Array(SPKI_ED25519_PREFIX.length + rawPub.length);
  spki.set(SPKI_ED25519_PREFIX, 0);
  spki.set(rawPub, SPKI_ED25519_PREFIX.length);

  // Cast to bypass type gap (WebCrypto types don't always declare Ed25519).
  const subtle = crypto.subtle as unknown as {
    importKey(
      f: string,
      k: Uint8Array,
      a: { name: string },
      e: boolean,
      u: string[],
    ): Promise<CryptoKey>;
    verify(
      a: string,
      k: CryptoKey,
      sig: ArrayBuffer,
      data: ArrayBuffer,
    ): Promise<boolean>;
  };
  const key = await subtle.importKey(
    "spki",
    spki,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return subtle.verify(
    "Ed25519",
    key,
    rawSig.buffer as ArrayBuffer,
    message.buffer as ArrayBuffer,
  );
}
