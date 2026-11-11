import { canonicalize, sha256Hex } from "./canonical.js";
import type { Envelope } from "./types.js";

// The "envelope hash" is the sha256 of the canonicalized envelope WITHOUT
// signatures. This is what the NEXT envelope's chain.prev_hash references.
// Signatures sign over the same subtree (v + event + chain), so the hash and
// the signature cover identical bytes.
export async function envelopeHash(
  envelope: Omit<Envelope, "signatures">,
): Promise<string> {
  return sha256Hex(canonicalize(envelope));
}

// What the recorder signs: the canonical (v, event, chain) subtree.
export function signingInput(
  envelope: Omit<Envelope, "signatures">,
): Uint8Array {
  return new TextEncoder().encode(canonicalize(envelope));
}
