import { sha256Hex } from "./canonical.js";

// Binary Merkle tree over sha256-hex leaves.
// Conventions:
//  - Leaves are already sha256 hex strings (the envelope_hash we store).
//  - Internal node = sha256(concat(left, right)) over the RAW BYTES of the
//    two child hashes (not the hex ASCII). This matches Bitcoin / most L2 conventions.
//  - Odd nodes at a level are duplicated (hash paired with itself).
//  - A tree with 0 leaves has root = 32 zero bytes (hex of 64 zeros).

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

export const EMPTY_ROOT =
  "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Build a Merkle tree and return the root + every level (bottom-up).
 * levels[0] is the leaves; levels[levels.length-1] is a single-element array
 * containing the root.
 */
export async function buildMerkleTree(leaves: string[]): Promise<{
  root: string;
  levels: string[][];
}> {
  if (leaves.length === 0) return { root: EMPTY_ROOT, levels: [[]] };
  const levels: string[][] = [leaves.slice()];
  let current = leaves.slice();
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]!;
      const right = i + 1 < current.length ? current[i + 1]! : left;
      next.push(await hashPair(left, right));
    }
    levels.push(next);
    current = next;
  }
  return { root: current[0]!, levels };
}

export type InclusionProof = {
  leaf: string;
  leaf_index: number;
  root: string;
  siblings: Array<{ hash: string; side: "left" | "right" }>;
};

/**
 * Generate a Merkle inclusion proof for leaf at the given index.
 * siblings[0] is at the leaf level; siblings[last] is at the level just
 * below the root. Each sibling records whether it was on the left or right.
 */
export function inclusionProof(
  levels: string[][],
  leafIndex: number,
): Omit<InclusionProof, "leaf" | "root"> {
  const siblings: Array<{ hash: string; side: "left" | "right" }> = [];
  let idx = leafIndex;
  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level]!;
    const isRightChild = idx % 2 === 1;
    const siblingIdx = isRightChild ? idx - 1 : idx + 1;
    // Sibling may be a duplicated-self at odd boundary
    const sibling =
      siblingIdx < nodes.length ? nodes[siblingIdx]! : nodes[idx]!;
    siblings.push({
      hash: sibling,
      side: isRightChild ? "left" : "right",
    });
    idx = Math.floor(idx / 2);
  }
  return { leaf_index: leafIndex, siblings };
}

/**
 * Re-compute the root from a leaf and its inclusion proof. Used by the
 * verifier and by the recorder's own self-check after building a tree.
 */
export async function verifyInclusion(proof: InclusionProof): Promise<boolean> {
  let acc = proof.leaf;
  for (const { hash, side } of proof.siblings) {
    acc = side === "left" ? await hashPair(hash, acc) : await hashPair(acc, hash);
  }
  return acc === proof.root;
}
