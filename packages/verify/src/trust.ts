// Pinned trust store for dispute-mode verification.
//
// The canonical, human-auditable copies live in:
//   trust/recorder-keys.json
//   trust/base-anchorers.json
//
// This module is the runtime copy because it must work in browsers and
// Cloudflare Workers without JSON-import support. `test/disclosures.test.mjs`
// asserts that these constants and the JSON files do not drift.
//
// Dispute mode must never fetch a key from the bundle's `public_key_url`.
// These values are release artifacts; updating them requires a new verifier
// release, which is the point.

import { sha256Hex } from "./canonical.js";
import type {
  PinnedAnchorer,
  PinnedRecorderKey,
  TrustStore,
} from "./types.js";

export const PINNED_RECORDER_KEYS: PinnedRecorderKey[] = [
  {
    key_id: "sheaf-ed25519-2026-11-09",
    public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
    active_from: "2026-11-09T00:00:00Z",
    active_until: null,
  },
];

export const PINNED_ANCHORERS: PinnedAnchorer[] = [
  {
    network: "eip155:8453",
    address: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
    active_from: "2026-11-09T00:00:00Z",
    active_until: null,
  },
];

export function defaultTrustStore(): TrustStore {
  return {
    recorder_keys: PINNED_RECORDER_KEYS.map((k) => ({ ...k })),
    anchorers: PINNED_ANCHORERS.map((a) => ({ ...a })),
  };
}

export function isRecorderKeyActive(
  key: PinnedRecorderKey,
  timestamp: string,
): boolean {
  const at = Date.parse(timestamp);
  const from = Date.parse(key.active_from);
  if (!Number.isFinite(at) || !Number.isFinite(from)) return false;
  if (at < from) return false;
  if (key.active_until === null) return true;
  const until = Date.parse(key.active_until);
  return Number.isFinite(until) && at < until;
}

export function isAnchorerActive(
  anchorer: PinnedAnchorer,
  timestamp: string,
): boolean {
  const at = Date.parse(timestamp);
  if (!Number.isFinite(at)) return false;
  if (anchorer.active_from) {
    const from = Date.parse(anchorer.active_from);
    if (!Number.isFinite(from) || at < from) return false;
  }
  if (anchorer.active_until) {
    const until = Date.parse(anchorer.active_until);
    if (!Number.isFinite(until) || at >= until) return false;
  }
  return true;
}

export function findRecorderKey(
  trust: TrustStore,
  keyId: string,
): PinnedRecorderKey | null {
  return trust.recorder_keys.find((k) => k.key_id === keyId) ?? null;
}

export function findAnchorer(
  trust: TrustStore,
  network: string,
  address: string,
): PinnedAnchorer | null {
  const wanted = address.toLowerCase();
  return (
    trust.anchorers.find(
      (a) => a.network === network && a.address.toLowerCase() === wanted,
    ) ?? null
  );
}

/** SHA-256 fingerprint of the raw 32-byte Ed25519 public key, for out-of-band
 *  comparison with the published key. */
export async function publicKeyFingerprint(
  publicKeyBase64: string,
): Promise<string> {
  const bin = atob(publicKeyBase64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return `sha256:${await sha256Hex(bytes)}`;
}
