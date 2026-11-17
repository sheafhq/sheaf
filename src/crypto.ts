// Ed25519 key import + sign for CF Workers. The runtime supports Ed25519 in
// crypto.subtle; the TS types shipped with @cloudflare/workers-types don't
// yet declare it, so we cast via unknown to bypass the type check.

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

let cachedKey: Promise<CryptoKey> | undefined;
export function importRecorderKey(pkcs8B64: string): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  const pkcs8 = b64decode(pkcs8B64);
  const subtle = crypto.subtle as unknown as {
    importKey(
      f: string,
      k: Uint8Array,
      a: { name: string },
      e: boolean,
      u: string[],
    ): Promise<CryptoKey>;
  };
  cachedKey = subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  return cachedKey;
}

export async function signEd25519(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array> {
  const subtle = crypto.subtle as unknown as {
    sign(a: string, k: CryptoKey, d: ArrayBuffer): Promise<ArrayBuffer>;
  };
  const sig = await subtle.sign("Ed25519", key, data.buffer as ArrayBuffer);
  return new Uint8Array(sig);
}

/** Verify an Ed25519 signature from a raw 32-byte public key. */
export async function verifyEd25519(
  publicKeyBase64: string,
  data: Uint8Array,
  signatureBase64: string,
): Promise<boolean> {
  try {
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
        s: Uint8Array,
        d: ArrayBuffer,
      ): Promise<boolean>;
    };
    const key = await subtle.importKey(
      "raw",
      b64decode(publicKeyBase64),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await subtle.verify(
      "Ed25519",
      key,
      b64decode(signatureBase64),
      data.buffer as ArrayBuffer,
    );
  } catch {
    return false;
  }
}
