// Sheaf event envelope types — see ARCHITECTURE.md.

export type EventResult = "ok" | "error" | "timeout" | "cancelled";

export type EventBody = {
  intent: string;
  actor: string;
  authority: string | null;
  tool: string;
  inputs_hash: string; // sha256:hex
  outputs_hash: string | null;
  result: EventResult;
  ts: string; // ISO8601 UTC
};

export type ChainRef = {
  chain_id: string;
  seq: number;
  prev_hash: string | null; // null only for seq=0
};

export type Signatures = {
  actor: string | null; // base64 Ed25519
  recorder: string; // base64 Ed25519 (set by Sheaf)
};

export type Envelope = {
  v: "arca/1";
  event: EventBody;
  chain: ChainRef;
  signatures: Signatures;
};

// Shape posted by the client. Recorder signs it to produce a full Envelope.
export type UnsignedSubmission = {
  v: "arca/1";
  event: EventBody;
  chain: ChainRef;
  signatures: Pick<Signatures, "actor">;
};

export type SubmissionReceipt = {
  ok: true;
  chain_id: string;
  seq: number;
  envelope_hash: string;
  envelope: Envelope;
};

export type ChainHead = {
  chain_id: string;
  head_seq: number;
  head_hash: string;
  event_count: number;
  created_at: number;
  updated_at: number;
} | null;
