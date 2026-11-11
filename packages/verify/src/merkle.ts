// Merkle inclusion verifier. Does not build trees — only checks that a given
// leaf + siblings reproduces a given root.

import { sha256Hex } from "./canonical.js";

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function hashPair(left: string, right: string): Promise<string> {
  const buf = new Uint8Array(64);
  buf.set(hexToBytes(left), 0);
  buf.set(hexToBytes(right), 32);
  return sha256Hex(buf);
}

export type Sibling = { hash: string; side: "left" | "right" };

export async function computeRootFromProof(
  leaf: string,
  siblings: Sibling[],
): Promise<string> {
  let acc = leaf;
  for (const { hash, side } of siblings) {
    acc = side === "left" ? await hashPair(hash, acc) : await hashPair(acc, hash);
  }
  return acc;
}
