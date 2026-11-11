// Assemble a self-contained Sheaf bundle: full signed envelope + Merkle
// inclusion proof + anchor tx reference + issuer identity. The bundle is the
// shippable artifact — anyone with the bundle + a Base RPC + the published
// recorder public key can verify it offline via @sheafhq/verify. Never
// contains private data beyond what the submitter already signed.

import { buildMerkleTree, inclusionProof } from "./merkle.js";
import { ACTIVE_KEY_ID, activeKey } from "./keys.js";

type DbRow = Record<string, unknown>;
type Db = {
  prepare(query: string): {
    bind(...args: unknown[]): {
      all(): Promise<{ results: DbRow[] }>;
      first(): Promise<DbRow | null>;
    };
  };
};

export const BUNDLE_VERSION = "sheaf-bundle/1";

export type BundleBuildResult =
  | { ok: true; bundle: unknown }
  | { ok: false; status: 404 | 409 | 500; error: string; detail?: unknown };

export async function buildBundle(
  db: Db,
  issuer: string,
  publicKeyUrl: string,
  chainId: string,
  seq: number,
): Promise<BundleBuildResult> {
  const event = (await db
    .prepare(
      "SELECT envelope_json, envelope_hash, epoch_id, epoch_leaf_idx FROM events WHERE chain_id = ? AND seq = ?",
    )
    .bind(chainId, seq)
    .first()) as
    | {
        envelope_json: string;
        envelope_hash: string;
        epoch_id: number | null;
        epoch_leaf_idx: number | null;
      }
    | null;

  if (!event) {
    return { ok: false, status: 404, error: `no event at ${chainId}/${seq}` };
  }

  if (event.epoch_id === null || event.epoch_leaf_idx === null) {
    return {
      ok: false,
      status: 409,
      error:
        "event not yet anchored; bundle is only available after the containing epoch is sealed and submitted to Base",
      detail: {
        chain_id: chainId,
        seq,
        envelope_hash: event.envelope_hash,
        guidance:
          "Un-anchored events are already signed and chained; the /bundle endpoint waits for the Merkle root to be committed on-chain so the artifact is independently verifiable. Try again after the next epoch anchor.",
      },
    };
  }

  const epoch = (await db
    .prepare(
      "SELECT merkle_root, event_count, anchor_tx_hash, anchor_block, sealed_at, anchor_submitted_at FROM epochs WHERE epoch_id = ?",
    )
    .bind(event.epoch_id)
    .first()) as
    | {
        merkle_root: string;
        event_count: number;
        anchor_tx_hash: string | null;
        anchor_block: number | null;
        sealed_at: number;
        anchor_submitted_at: number | null;
      }
    | null;

  if (!epoch) {
    return {
      ok: false,
      status: 500,
      error: `internal: epoch ${event.epoch_id} referenced by event not found`,
    };
  }

  const leafRows = await db
    .prepare(
      "SELECT envelope_hash FROM events WHERE epoch_id = ? ORDER BY epoch_leaf_idx",
    )
    .bind(event.epoch_id)
    .all();
  const leaves = (leafRows.results as Array<{ envelope_hash: string }>).map(
    (r) => r.envelope_hash,
  );
  const { root, levels } = await buildMerkleTree(leaves);
  if (root !== epoch.merkle_root) {
    return {
      ok: false,
      status: 500,
      error: "internal: rebuilt Merkle root does not match stored root",
      detail: { stored: epoch.merkle_root, rebuilt: root },
    };
  }

  const proof = inclusionProof(levels, event.epoch_leaf_idx);
  const envelope = JSON.parse(event.envelope_json) as unknown;

  const bundle = {
    version: BUNDLE_VERSION,
    envelope,
    envelope_hash: event.envelope_hash,
    chain: {
      chain_id: chainId,
      seq,
    },
    anchor: {
      epoch_id: event.epoch_id,
      leaf_index: event.epoch_leaf_idx,
      merkle_root: epoch.merkle_root,
      siblings: proof.siblings,
      tx_hash: epoch.anchor_tx_hash,
      block: epoch.anchor_block,
      network: "eip155:8453",
      explorer: epoch.anchor_tx_hash
        ? `https://basescan.org/tx/${epoch.anchor_tx_hash}`
        : null,
    },
    issuer: {
      name: issuer,
      key_id: ACTIVE_KEY_ID,
      public_key_base64: activeKey().public_key_base64,
      public_key_url: publicKeyUrl,
    },
    verification: {
      lib: "@sheafhq/verify",
      cmd: "npx -y @sheafhq/verify <save-this-bundle.json>",
      docs: "https://github.com/sheafhq/sheaf#verify",
      note:
        "Hash leaf+siblings bottom-up (siblings[i].side tells you left/right). Result must equal anchor.merkle_root. Then check the Base tx: tx.from == tx.to == issuer anchorer address, tx.input starts with 0x41524341, bytes 12..44 of tx.input equal merkle_root. Verify envelope signature with issuer.public_key_base64.",
    },
  };

  return { ok: true, bundle };
}
