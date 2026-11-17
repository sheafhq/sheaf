// Minimal copies of the main repo's envelope types, enough for verification.

export type EventResult = "ok" | "error" | "timeout" | "cancelled" | "blocked";

/** Optional control-event discriminator. Absent means "tool_call". */
export type EventKind =
  | "tool_call"
  | "mandate"
  | "delegation"
  | "consent"
  | "policy";

export type EventPolicy = {
  schema: "sheaf.policy/1";
  hash: string;
  verdict: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
  reason_code: string;
};

export type EventBody = {
  kind?: EventKind;
  policy?: EventPolicy;
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

export type Sibling = {
  hash: string;
  side: "left" | "right";
};

export type InclusionProof = {
  leaf: string;
  leaf_index: number;
  merkle_root: string;
  siblings: Sibling[];
};

export type ReceiptBundle = {
  envelope: Envelope;
  inclusion_proof: InclusionProof;
  anchor_tx_hash: string;
  // Optional: previous envelope to also verify the chain link
  prev_envelope?: Envelope;
};

// --- Selective disclosure (build #1) --------------------------------------
// A disclosure set is the generic primitive output: selected envelopes plus
// one Merkle inclusion proof each, the anchor epochs those proofs land in, and
// the adjacent boundary refs. It deliberately knows nothing about disputes.

export type DisclosureEventRef = {
  chain_id: string;
  seq: number;
};

export type DisclosureRecorder = {
  name: string;
  key_id: string;
  public_key_base64: string;
  public_key_url: string;
};

export type DisclosureProof = {
  type: "merkle-inclusion/v1";
  siblings: Sibling[];
  root: string;
};

export type DisclosureEvent = {
  event_ref: DisclosureEventRef;
  envelope: Envelope;
  envelope_hash: string;
  epoch_id: number;
  leaf_index: number;
  proof: DisclosureProof;
};

export type DisclosureAnchorEpoch = {
  epoch_id: number;
  merkle_root: string;
  tx_hash: string;
  block_number: number | null;
  block_hash: string | null;
  calldata: string;
  explorer: string | null;
};

export type DisclosureSet = {
  version: "sheaf-disclosure/1";
  chain_id: string;
  from_seq: number;
  to_seq: number;
  recorder: DisclosureRecorder;
  disclosures: DisclosureEvent[];
  anchor: {
    /** `local` is an offline Merkle commitment, not a Base transaction. */
    mode?: "base" | "local";
    network: string;
    anchorer: string;
    epochs: DisclosureAnchorEpoch[];
  };
  before_ref: DisclosureEventRef | null;
  after_ref: DisclosureEventRef | null;
  warnings?: string[];
};

// Pinned trust. These are release artifacts, not values fetched from a bundle.
export type PinnedRecorderKey = {
  key_id: string;
  public_key_base64: string;
  active_from: string;
  active_until: string | null;
};

export type PinnedAnchorer = {
  network: string;
  address: string;
  active_from?: string;
  active_until?: string | null;
};

export type TrustStore = {
  recorder_keys: PinnedRecorderKey[];
  anchorers: PinnedAnchorer[];
};

export type VerifyDisclosuresOptions = {
  /** Dispute mode is a deliberate opt-in. Legacy `verify()` behavior is not
   *  changed; callers must ask for the pinned-trust path. */
  mode: "dispute";
  /** If omitted, the verifier's shipped pinned trust store is used. */
  trust?: TrustStore;
  /** If omitted, verification is integrity-only and reports `anchor_tx_on_chain: null`. */
  base_rpc?: string;
  expected_network?: string;
  max_events?: number;
};

export type VerifyDisclosuresResult = {
  valid: boolean;
  anchor_confirmed: boolean;
  code?: string;
  reason?: string;
  failed_event_ref?: DisclosureEventRef;
  disclosures_checked: number;
  checks: {
    schema_supported: boolean;
    chain_id_consistent: boolean;
    selection_contiguous: boolean;
    before_link: boolean | null;
    after_link: boolean | null;
    chain_links: boolean;
    envelope_hash_matches_leaf: boolean;
    recorder_key_known: boolean;
    recorder_key_matches: boolean;
    recorder_key_active: boolean;
    recorder_signature_verifies: boolean;
    merkle_inclusion_proof: boolean;
    anchor_epoch_present: boolean;
    anchor_calldata_matches_root: boolean;
    anchor_tx_on_chain: boolean | null;
    anchor_from_authorized_anchorer: boolean | null;
  };
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
