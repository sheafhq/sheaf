// Sheaf recorder public key (Ed25519). Published at /.well-known/sheaf-public-key.
//
// On rotation: generate a new keypair via scripts/gen-recorder-key.mjs, bump
// KEY_ID + ACTIVE_KEY_ID, add the new entry to KEY_RING, update wrangler
// secret RECORDER_PRIVATE_KEY, and leave the old entries in KEY_RING so
// historical receipts remain verifiable.

export type PublicKey = {
  key_id: string;
  algorithm: "Ed25519";
  public_key_base64: string;
  active_from: string; // ISO8601
  active_until: string | null;
};

export const ACTIVE_KEY_ID = "sheaf-ed25519-2026-11-09";

export const KEY_RING: PublicKey[] = [
  {
    key_id: "sheaf-ed25519-2026-11-09",
    algorithm: "Ed25519",
    public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
    active_from: "2026-11-09T00:00:00Z",
    active_until: null,
  },
];

export function activeKey(): PublicKey {
  const k = KEY_RING.find((k) => k.key_id === ACTIVE_KEY_ID);
  if (!k) throw new Error("ACTIVE_KEY_ID not in KEY_RING");
  return k;
}
