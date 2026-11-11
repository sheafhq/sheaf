// Minimal copies of the main repo's envelope types, enough for verification.

export type EventResult = "ok" | "error" | "timeout" | "cancelled";

export type EventBody = {
  intent: string;
  actor: string;
  authority: string | null;
  tool: string;
  inputs_hash: string;
  outputs_hash: string | null;
  result: EventResult;
  ts: string;
};

export type ChainRef = {
  chain_id: string;
  seq: number;
  prev_hash: string | null;
};

export type Signatures = {
  actor: string | null;
  recorder: string;
};

export type Envelope = {
  v: "arca/1";
  event: EventBody;
  chain: ChainRef;
  signatures: Signatures;
};

export type InclusionProof = {
  leaf: string;
  leaf_index: number;
  merkle_root: string;
  siblings: Array<{ hash: string; side: "left" | "right" }>;
};

export type ReceiptBundle = {
  envelope: Envelope;
  inclusion_proof: InclusionProof;
  anchor_tx_hash: string;
  // Optional: previous envelope to also verify the chain link
  prev_envelope?: Envelope;
};

export type VerifyOptions = {
  base_rpc: string;
  recorder_public_key_base64: string;
  // The authorized anchorer address. Receipts anchored by a different
  // signer are rejected. Case-insensitive match.
  expected_anchorer_address: string;
};

export type VerifyResult = {
  valid: boolean;
  checks: {
    anchor_on_chain: boolean;
    anchor_from_authorized_wallet: boolean;
    merkle_root_matches_on_chain: boolean;
    inclusion_proof_reproduces_root: boolean;
    envelope_hash_matches_leaf: boolean;
    recorder_signature_verifies: boolean;
    chain_prev_hash_matches: boolean | null; // null if prev_envelope not provided
  };
  anchor_block?: number;
  reason?: string; // populated when !valid
};
