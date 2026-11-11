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

export async function verifyEd25519(
  publicKeyBase64: string,
  signatureBase64: string,
  message: Uint8Array,
): Promise<boolean> {
  const rawPub = b64decode(publicKeyBase64);
  if (rawPub.length !== 32)
    throw new Error("Ed25519 public key must be 32 bytes");
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
  const sig = b64decode(signatureBase64);
  return subtle.verify(
    "Ed25519",
    key,
    sig.buffer as ArrayBuffer,
    message.buffer as ArrayBuffer,
  );
}
