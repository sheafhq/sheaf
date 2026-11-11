// CDP x402 facilitator JWT auth + payer extraction, ported from goldencalf.
// The CDP facilitator requires a per-request Bearer JWT (Ed25519) with a
// method+path-scoped `uris` claim. GET /supported vs POST /verify|/settle:
// the claim must match the facilitator's actual method, or CDP returns 401.

export type SheafX402Env = {
  PAYOUT_ADDRESS: string;
  NETWORK: string;
  FACILITATOR_URL: string;
  CDP_API_KEY_NAME?: string;
  CDP_API_KEY_SECRET?: string;
};

const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

function b64urlEncode(bytes: Uint8Array | string): string {
  const s = typeof bytes === "string" ? bytes : String.fromCharCode(...bytes);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let cachedCdpKey: Promise<CryptoKey> | undefined;
function importCdpKey(secretB64: string): Promise<CryptoKey> {
  if (cachedCdpKey) return cachedCdpKey;
  const raw = b64decode(secretB64);
  const seed = raw.slice(0, 32);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  const subtle = crypto.subtle as unknown as {
    importKey(
      f: string,
      k: Uint8Array,
      a: { name: string },
      e: boolean,
      u: string[],
    ): Promise<CryptoKey>;
  };
  cachedCdpKey = subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
    "sign",
  ]);
  return cachedCdpKey;
}

async function signCdpJwt(
  keyName: string,
  key: CryptoKey,
  path: "verify" | "settle" | "supported",
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = Array.from(nonceBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const header = { alg: "EdDSA", kid: keyName, typ: "JWT", nonce };
  const method = path === "supported" ? "GET" : "POST";
  const claims = {
    sub: keyName,
    iss: "cdp",
    nbf: now,
    exp: now + 120,
    uris: [`${method} api.cdp.coinbase.com/platform/v2/x402/${path}`],
  };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(claims));
  const signingInput = `${h}.${p}`;
  const subtle = crypto.subtle as unknown as {
    sign(a: string, k: CryptoKey, d: ArrayBuffer): Promise<ArrayBuffer>;
  };
  const sigBuf = await subtle.sign(
    "Ed25519",
    key,
    new TextEncoder().encode(signingInput).buffer as ArrayBuffer,
  );
  const sig = b64urlEncode(new Uint8Array(sigBuf));
  return `${h}.${p}.${sig}`;
}

export function buildCreateAuthHeaders(env: SheafX402Env) {
  return async () => {
    if (!env.CDP_API_KEY_NAME || !env.CDP_API_KEY_SECRET) return {};
    const key = await importCdpKey(env.CDP_API_KEY_SECRET);
    const name = env.CDP_API_KEY_NAME;
    const [v, s, sup] = await Promise.all([
      signCdpJwt(name, key, "verify"),
      signCdpJwt(name, key, "settle"),
      signCdpJwt(name, key, "supported"),
    ]);
    return {
      verify: { Authorization: `Bearer ${v}` },
      settle: { Authorization: `Bearer ${s}` },
      supported: { Authorization: `Bearer ${sup}` },
    };
  };
}

// Pull the paying wallet from the x402 signed payment header. Tries both
// modern (PAYMENT-SIGNATURE) and legacy (X-PAYMENT) header names.
export function extractPayer(headerValue: string | undefined | null): string | null {
  if (!headerValue) return null;
  try {
    const json = JSON.parse(
      atob(headerValue.replace(/-/g, "+").replace(/_/g, "/")),
    );
    const from =
      json?.payload?.authorization?.from ??
      json?.authorization?.from ??
      json?.from ??
      null;
    return typeof from === "string" ? from : null;
  } catch {
    return null;
  }
}
