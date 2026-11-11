// Tool implementations. Each returns either a plain object (serialized to
// JSON text content for the MCP response) or throws, in which case the
// server translates it to an MCP error response.
//
// All three tools are READ-only against the Sheaf recorder. No wallet, no
// settlement, no mutation. Safe to expose to any agent.

import { verify } from "@sheafhq/verify";

export type ToolContext = {
  recorderUrl: string;
  baseRpc: string;
};

type ChainHead = {
  chain_id: string;
  head_seq: number;
  head_hash: string;
  event_count: number;
  created_at: number;
  updated_at: number;
};

type ProofResponse = {
  chain_id: string;
  seq: number;
  epoch_id: number;
  leaf: string;
  leaf_index: number;
  merkle_root: string;
  siblings: Array<{ hash: string; side: "left" | "right" }>;
  anchor: {
    tx_hash: string | null;
    block: number | null;
    submitted_at: number | null;
    explorer: string | null;
  };
  verification_note: string;
};

export async function chainHead(
  ctx: ToolContext,
  args: { chain_id: string },
): Promise<unknown> {
  if (!args.chain_id || typeof args.chain_id !== "string") {
    throw new Error("chain_id (string) is required");
  }
  const url = `${ctx.recorderUrl}/chains/${encodeURIComponent(args.chain_id)}/head`;
  const r = await fetch(url);
  if (r.status === 404) {
    return {
      chain_id: args.chain_id,
      head: null,
      note: "No events have been recorded on this chain yet.",
    };
  }
  if (!r.ok) {
    throw new Error(`recorder returned HTTP ${r.status}`);
  }
  const body = (await r.json()) as ChainHead;
  return {
    chain_id: body.chain_id,
    head_seq: body.head_seq,
    head_hash: body.head_hash,
    event_count: body.event_count,
    created_at_unix: body.created_at,
    updated_at_unix: body.updated_at,
    source_url: url,
  };
}

export async function getProofFor(
  ctx: ToolContext,
  args: { chain_id: string; seq: number },
): Promise<unknown> {
  if (!args.chain_id || typeof args.chain_id !== "string") {
    throw new Error("chain_id (string) is required");
  }
  if (!Number.isInteger(args.seq) || args.seq < 0) {
    throw new Error("seq (non-negative integer) is required");
  }
  // First find out which epoch the event is in.
  const evUrl = `${ctx.recorderUrl}/events/${encodeURIComponent(args.chain_id)}/${args.seq}`;
  const evRes = await fetch(evUrl);
  if (evRes.status === 404) {
    throw new Error(`no event at ${args.chain_id}/${args.seq}`);
  }
  if (!evRes.ok) {
    throw new Error(`recorder returned HTTP ${evRes.status} on event lookup`);
  }
  const ev = (await evRes.json()) as {
    envelope: unknown;
    envelope_hash: string;
    epoch_id: number | null;
    epoch_leaf_idx: number | null;
  };
  if (ev.epoch_id === null) {
    return {
      status: "not_yet_anchored",
      chain_id: args.chain_id,
      seq: args.seq,
      envelope_hash: ev.envelope_hash,
      note:
        "Event is signed and chained but not yet included in an on-chain anchor. Call again after the next epoch anchor to get a Merkle inclusion proof.",
    };
  }
  const proofUrl = `${ctx.recorderUrl}/epoch/${ev.epoch_id}/proof/${encodeURIComponent(args.chain_id)}/${args.seq}`;
  const proofRes = await fetch(proofUrl);
  if (!proofRes.ok) {
    throw new Error(`recorder returned HTTP ${proofRes.status} on proof fetch`);
  }
  const proof = (await proofRes.json()) as ProofResponse;
  return {
    status: "anchored",
    chain_id: proof.chain_id,
    seq: proof.seq,
    epoch_id: proof.epoch_id,
    leaf: proof.leaf,
    leaf_index: proof.leaf_index,
    merkle_root: proof.merkle_root,
    siblings: proof.siblings,
    anchor: proof.anchor,
    verification_note: proof.verification_note,
    source_url: proofUrl,
  };
}

type SheafPublicKey = {
  issuer: string;
  active_key_id: string;
  keys: Array<{ key_id: string; public_key_base64: string }>;
};

export async function verifyBundle(
  ctx: ToolContext,
  args: {
    bundle: unknown;
    anchorer_address?: string;
  },
): Promise<unknown> {
  if (!args.bundle || typeof args.bundle !== "object") {
    throw new Error("bundle (object) is required");
  }
  // Accept both sheaf-bundle/1 (paid /bundle endpoint) and the legacy
  // {envelope, inclusion_proof, anchor_tx_hash} shape used by the free
  // compose-it-yourself pattern.
  type BundleShape = {
    version?: string;
    envelope?: unknown;
    envelope_hash?: string;
    anchor?: {
      tx_hash?: string;
      merkle_root?: string;
      leaf_index?: number;
      siblings?: Array<{ hash: string; side: "left" | "right" }>;
    };
    issuer?: { public_key_base64?: string };
    inclusion_proof?: {
      leaf: string;
      leaf_index: number;
      merkle_root: string;
      siblings: Array<{ hash: string; side: "left" | "right" }>;
    };
    anchor_tx_hash?: string;
  };
  const b = args.bundle as BundleShape;

  // Normalize both shapes to the one @sheafhq/verify expects.
  let verifyInput: {
    envelope: unknown;
    inclusion_proof: {
      leaf: string;
      leaf_index: number;
      merkle_root: string;
      siblings: Array<{ hash: string; side: "left" | "right" }>;
    };
    anchor_tx_hash: string;
  };
  if (b.version === "sheaf-bundle/1" && b.envelope && b.anchor && b.envelope_hash) {
    verifyInput = {
      envelope: b.envelope,
      inclusion_proof: {
        leaf: b.envelope_hash,
        leaf_index: b.anchor.leaf_index ?? 0,
        merkle_root: b.anchor.merkle_root ?? "",
        siblings: b.anchor.siblings ?? [],
      },
      anchor_tx_hash: b.anchor.tx_hash ?? "",
    };
  } else if (b.envelope && b.inclusion_proof && b.anchor_tx_hash) {
    verifyInput = {
      envelope: b.envelope,
      inclusion_proof: b.inclusion_proof,
      anchor_tx_hash: b.anchor_tx_hash,
    };
  } else {
    throw new Error(
      "bundle shape not recognized; expected sheaf-bundle/1 or legacy {envelope, inclusion_proof, anchor_tx_hash}",
    );
  }

  // Pull recorder public key. Prefer the key embedded in the bundle so the
  // verification is self-contained; fall back to /.well-known if missing.
  let recorderKey = b.issuer?.public_key_base64 ?? "";
  if (!recorderKey) {
    const r = await fetch(`${ctx.recorderUrl}/.well-known/sheaf-public-key`);
    if (!r.ok) {
      throw new Error(
        `could not fetch recorder public key: HTTP ${r.status}`,
      );
    }
    const pk = (await r.json()) as SheafPublicKey;
    const active = pk.keys.find((k) => k.key_id === pk.active_key_id);
    if (!active) throw new Error("recorder public key not found in keyring");
    recorderKey = active.public_key_base64;
  }

  // Anchorer address: caller may override; else default to the canonical
  // sheaf-recorder anchorer. (Kept hardcoded here rather than exposing it
  // as another remote fetch — any mismatch means the caller is verifying
  // against the wrong issuer, which is itself a useful failure mode.)
  const anchorer =
    args.anchorer_address ?? "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";

  const result = await verify(verifyInput as never, {
    base_rpc: ctx.baseRpc,
    recorder_public_key_base64: recorderKey,
    expected_anchorer_address: anchorer,
  });
  return {
    valid: result.valid,
    checks: result.checks,
    reason: result.reason,
    anchor_block: result.anchor_block,
    recorder: ctx.recorderUrl,
    anchorer_checked: anchorer,
  };
}
