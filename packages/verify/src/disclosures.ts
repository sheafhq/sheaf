// Dispute-mode selective-disclosure verification.
//
// This is deliberately separate from `verify()` so the existing sheaf-bundle/1
// path is unchanged. Dispute mode is opt-in and uses a pinned trust store:
//   - unknown recorder key id   -> UNKNOWN_RECORDER_KEY
//   - bundle key != pinned key  -> RECORDER_KEY_MISMATCH
//   - unknown anchorer address  -> UNKNOWN_ANCHORER
//
// It never fetches `recorder.public_key_url`. The only network call it can make
// is `opts.base_rpc` (a Base JSON-RPC endpoint), and only when provided.

import { canonicalize, hashCanonical } from "./canonical.js";
import { computeRootFromProof } from "./merkle.js";
import { verifyEd25519 } from "./signature.js";
import { fetchAnchorTx, fetchChainId } from "./anchor.js";
import {
  defaultTrustStore,
  findAnchorer,
  findRecorderKey,
  isAnchorerActive,
  isRecorderKeyActive,
} from "./trust.js";
import type {
  DisclosureEvent,
  DisclosureSet,
  Envelope,
  Sibling,
  VerifyDisclosuresOptions,
  VerifyDisclosuresResult,
} from "./types.js";

type Checks = VerifyDisclosuresResult["checks"];

function freshChecks(): Checks {
  return {
    schema_supported: false,
    chain_id_consistent: false,
    selection_contiguous: false,
    before_link: null,
    after_link: null,
    chain_links: false,
    envelope_hash_matches_leaf: false,
    recorder_key_known: false,
    recorder_key_matches: false,
    recorder_key_active: false,
    recorder_signature_verifies: false,
    merkle_inclusion_proof: false,
    anchor_epoch_present: false,
    anchor_calldata_matches_root: false,
    anchor_tx_on_chain: null,
    anchor_from_authorized_anchorer: null,
  };
}

function normalizeHash(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value
    .trim()
    .replace(/^sha256:/i, "")
    .replace(/^0x/i, "")
    .toLowerCase();
  return /^[0-9a-f]{64}$/.test(clean) ? clean : null;
}

function envelopeCore(envelope: Envelope): {
  v: "arca/1";
  event: Envelope["event"];
  chain: Envelope["chain"];
} {
  return { v: envelope.v, event: envelope.event, chain: envelope.chain };
}

function eventRefString(ref: { chain_id: string; seq: number }): string {
  return `${ref.chain_id}/${ref.seq}`;
}

function decodeAnchorCalldata(
  calldata: unknown,
): { epochId: number; root: string } | null {
  if (typeof calldata !== "string") return null;
  const hex = calldata.replace(/^0x/i, "").toLowerCase();
  if (hex.length !== 88) return null; // 44 bytes
  if (!hex.startsWith("41524341")) return null; // "ARCA"
  const epochHex = hex.slice(8, 24);
  const root = hex.slice(24);
  if (!/^[0-9a-f]{16}$/.test(epochHex)) return null;
  if (!/^[0-9a-f]{64}$/.test(root)) return null;
  return { epochId: Number(BigInt("0x" + epochHex)), root };
}

function sortBySeq(events: DisclosureEvent[]): DisclosureEvent[] {
  return [...events].sort((a, b) => a.envelope.chain.seq - b.envelope.chain.seq);
}

/**
 * Verify a selective-disclosure set with pinned trust.
 *
 * `valid` means every local cryptographic check passed and, when an RPC was
 * supplied, every anchor tx matched. `anchor_confirmed` is false in offline
 * mode even when the integrity checks pass.
 */
export async function verifyDisclosures(
  set: DisclosureSet,
  opts: VerifyDisclosuresOptions,
): Promise<VerifyDisclosuresResult> {
  const checks = freshChecks();
  const disclosures = Array.isArray(set?.disclosures) ? set.disclosures : [];
  const checked = disclosures.length;

  function invalid(
    code: string,
    reason: string,
    failedEventRef?: { chain_id: string; seq: number },
  ): VerifyDisclosuresResult {
    return {
      valid: false,
      anchor_confirmed: false,
      code,
      reason,
      ...(failedEventRef ? { failed_event_ref: failedEventRef } : {}),
      disclosures_checked: checked,
      checks: { ...checks },
    };
  }

  // 0. Explicit opt-in. Legacy verify() behavior is untouched.
  if (!opts || opts.mode !== "dispute") {
    return invalid(
      "DISPUTE_MODE_REQUIRED",
      'dispute mode requires { mode: "dispute" }; sheaf-bundle/1 verification is unchanged',
    );
  }

  if (!set || typeof set !== "object") {
    return invalid("INVALID_DISCLOSURE_SET", "disclosure set must be an object");
  }

  // 1. Schema and basic shape.
  if (set.version !== "sheaf-disclosure/1") {
    return invalid(
      "UNSUPPORTED_SCHEMA",
      `unsupported disclosure schema: ${String(set.version)}`,
    );
  }
  if (
    !set.chain_id ||
    !Number.isInteger(set.from_seq) ||
    !Number.isInteger(set.to_seq) ||
    set.from_seq < 0 ||
    set.to_seq < set.from_seq
  ) {
    return invalid("INVALID_DISCLOSURE_SET", "invalid chain_id or seq range");
  }
  if (disclosures.length === 0) {
    return invalid(
      "INVALID_DISCLOSURE_SET",
      "disclosure set contains no disclosures",
    );
  }
  const maxEvents = opts.max_events ?? 50;
  if (set.to_seq - set.from_seq + 1 > maxEvents) {
    return invalid(
      "RANGE_TOO_LARGE",
      `range has ${set.to_seq - set.from_seq + 1} events; maximum is ${maxEvents}`,
    );
  }
  if (
    !set.recorder ||
    typeof set.recorder.key_id !== "string" ||
    typeof set.recorder.public_key_base64 !== "string"
  ) {
    return invalid(
      "RECORDER_KEY_MISMATCH",
      "disclosure set is missing recorder key metadata",
    );
  }
  if (
    !set.anchor ||
    typeof set.anchor.network !== "string" ||
    typeof set.anchor.anchorer !== "string" ||
    !Array.isArray(set.anchor.epochs)
  ) {
    return invalid("INVALID_DISCLOSURE_SET", "invalid anchor block");
  }
  checks.schema_supported = true;

  // 2. Chain identity on every ref and envelope.
  for (const disclosure of disclosures) {
    if (
      !disclosure.event_ref ||
      disclosure.event_ref.chain_id !== set.chain_id ||
      !disclosure.envelope ||
      disclosure.envelope.chain.chain_id !== set.chain_id ||
      disclosure.event_ref.seq !== disclosure.envelope.chain.seq
    ) {
      return invalid(
        "CHAIN_ID_MISMATCH",
        "disclosure event_ref/envelope does not match the set chain_id",
        disclosure.event_ref,
      );
    }
  }
  checks.chain_id_consistent = true;

  // 3. Pinned recorder key: known id and exact key match. This happens before
  // signatures so a swapped-key bundle fails as RECORDER_KEY_MISMATCH.
  const trust = opts.trust ?? defaultTrustStore();
  if (!Array.isArray(trust.recorder_keys) || !Array.isArray(trust.anchorers)) {
    return invalid(
      "INVALID_TRUST_STORE",
      "pinned trust store must contain recorder_keys[] and anchorers[]",
    );
  }
  const pinnedKey = findRecorderKey(trust, set.recorder.key_id);
  if (!pinnedKey) {
    return invalid(
      "UNKNOWN_RECORDER_KEY",
      `recorder key id "${set.recorder.key_id}" is not in the pinned trust store`,
    );
  }
  checks.recorder_key_known = true;

  if (
    pinnedKey.public_key_base64.trim() !== set.recorder.public_key_base64.trim()
  ) {
    return invalid(
      "RECORDER_KEY_MISMATCH",
      `bundle recorder key does not match pinned key "${set.recorder.key_id}"`,
    );
  }
  checks.recorder_key_matches = true;

  // 4. Pinned anchorer and network. These are trust decisions, not just
  // consistency checks; fail closed before touching the proof.
  const expectedNetwork = opts.expected_network ?? "eip155:8453";
  if (set.anchor.network !== expectedNetwork) {
    return invalid(
      "UNSUPPORTED_NETWORK",
      `anchor network ${set.anchor.network} is not ${expectedNetwork}`,
    );
  }
  const pinnedAnchorer = findAnchorer(
    trust,
    set.anchor.network,
    set.anchor.anchorer,
  );
  if (!pinnedAnchorer) {
    return invalid(
      "UNKNOWN_ANCHORER",
      `anchorer ${set.anchor.anchorer} is not in the pinned trust store for ${set.anchor.network}`,
    );
  }
  // The anchor is created after the events. Use the latest event timestamp as
  // the lower bound for the anchorer's active window; an online verifier can
  // additionally check the block timestamp when that field is available.
  const latestTs = disclosures
    .map((d) => d.envelope.event.ts)
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0]!;
  if (!isAnchorerActive(pinnedAnchorer, latestTs)) {
    return invalid(
      "ANCHORER_NOT_ACTIVE",
      `anchorer ${set.anchor.anchorer} was not active at or after ${latestTs}`,
    );
  }

  // 5. Selection: every seq in [from,to], no duplicates, only the adjacent
  // boundary disclosures outside it.
  const bySeq = new Map<number, DisclosureEvent>();
  for (const disclosure of disclosures) {
    const seq = disclosure.envelope.chain.seq;
    if (bySeq.has(seq)) {
      return invalid(
        "DUPLICATE_DISCLOSURE",
        `seq ${seq} appears more than once`,
        disclosure.event_ref,
      );
    }
    bySeq.set(seq, disclosure);
  }

  for (let seq = set.from_seq; seq <= set.to_seq; seq++) {
    if (!bySeq.has(seq)) {
      return invalid(
        "MISSING_DISCLOSURE",
        `disclosure window is missing seq ${seq}`,
      );
    }
  }

  const allowed = new Set<number>();
  for (let seq = set.from_seq; seq <= set.to_seq; seq++) allowed.add(seq);
  if (set.before_ref) {
    if (
      set.before_ref.chain_id !== set.chain_id ||
      set.before_ref.seq !== set.from_seq - 1
    ) {
      return invalid(
        "INVALID_BOUNDARY_REF",
        "before_ref must be the immediately preceding seq on the same chain",
        set.before_ref,
      );
    }
    allowed.add(set.before_ref.seq);
    if (!bySeq.has(set.before_ref.seq)) {
      return invalid(
        "INVALID_BOUNDARY_REF",
        `before_ref ${eventRefString(set.before_ref)} is not disclosed`,
        set.before_ref,
      );
    }
  }
  if (set.after_ref) {
    if (
      set.after_ref.chain_id !== set.chain_id ||
      set.after_ref.seq !== set.to_seq + 1
    ) {
      return invalid(
        "INVALID_BOUNDARY_REF",
        "after_ref must be the immediately following seq on the same chain",
        set.after_ref,
      );
    }
    allowed.add(set.after_ref.seq);
    if (!bySeq.has(set.after_ref.seq)) {
      return invalid(
        "INVALID_BOUNDARY_REF",
        `after_ref ${eventRefString(set.after_ref)} is not disclosed`,
        set.after_ref,
      );
    }
  }
  for (const disclosure of disclosures) {
    if (!allowed.has(disclosure.envelope.chain.seq)) {
      return invalid(
        "UNEXPECTED_DISCLOSURE",
        `seq ${disclosure.envelope.chain.seq} is outside the window and boundaries`,
        disclosure.event_ref,
      );
    }
  }
  checks.selection_contiguous = true;

  const ordered = sortBySeq(disclosures);
  const firstRange = bySeq.get(set.from_seq)!;
  const lastRange = bySeq.get(set.to_seq)!;

  // 6. Hash and proof checks.
  checks.envelope_hash_matches_leaf = true;
  checks.merkle_inclusion_proof = true;
  checks.anchor_epoch_present = true;
  checks.anchor_calldata_matches_root = true;

  const epochById = new Map<
    number,
    { root: string; tx_hash: string; calldata: string }
  >();
  for (const epoch of set.anchor.epochs) {
    if (
      !Number.isInteger(epoch.epoch_id) ||
      typeof epoch.tx_hash !== "string" ||
      typeof epoch.calldata !== "string"
    ) {
      return invalid("INVALID_ANCHOR_EPOCH", "anchor epoch is malformed");
    }
    if (epochById.has(epoch.epoch_id)) {
      return invalid(
        "DUPLICATE_EPOCH",
        `anchor epoch ${epoch.epoch_id} appears more than once`,
      );
    }
    const root = normalizeHash(epoch.merkle_root);
    if (!root) {
      return invalid(
        "INVALID_ANCHOR_EPOCH",
        `anchor epoch ${epoch.epoch_id} has an invalid merkle_root`,
      );
    }
    const decoded = decodeAnchorCalldata(epoch.calldata);
    if (
      !decoded ||
      decoded.epochId !== epoch.epoch_id ||
      decoded.root !== root
    ) {
      checks.anchor_calldata_matches_root = false;
      return invalid(
        "ANCHOR_CALLDATA_MISMATCH",
        `anchor calldata does not encode epoch ${epoch.epoch_id} and its root`,
      );
    }
    epochById.set(epoch.epoch_id, {
      root,
      tx_hash: epoch.tx_hash,
      calldata: epoch.calldata,
    });
  }

  for (const disclosure of ordered) {
    const leaf = normalizeHash(disclosure.envelope_hash);
    if (!leaf) {
      checks.envelope_hash_matches_leaf = false;
      return invalid(
        "INVALID_ENVELOPE_HASH",
        `seq ${disclosure.envelope.chain.seq} has an invalid envelope_hash`,
        disclosure.event_ref,
      );
    }
    let computed: string;
    try {
      computed = await hashCanonical(envelopeCore(disclosure.envelope));
    } catch (err) {
      checks.envelope_hash_matches_leaf = false;
      return invalid(
        "INVALID_ENVELOPE",
        `seq ${disclosure.envelope.chain.seq} could not be canonicalized: ${(err as Error).message}`,
        disclosure.event_ref,
      );
    }
    if (computed !== leaf) {
      checks.envelope_hash_matches_leaf = false;
      return invalid(
        "ENVELOPE_HASH_MISMATCH",
        `seq ${disclosure.envelope.chain.seq} envelope hash does not match its leaf`,
        disclosure.event_ref,
      );
    }

    const proofRoot = normalizeHash(disclosure.proof?.root);
    const siblings = disclosure.proof?.siblings;
    if (!proofRoot || !Array.isArray(siblings)) {
      checks.merkle_inclusion_proof = false;
      return invalid(
        "INVALID_PROOF",
        `seq ${disclosure.envelope.chain.seq} has a malformed proof`,
        disclosure.event_ref,
      );
    }
    if (disclosure.proof.type !== "merkle-inclusion/v1") {
      checks.merkle_inclusion_proof = false;
      return invalid(
        "UNSUPPORTED_PROOF_TYPE",
        `seq ${disclosure.envelope.chain.seq} uses proof type ${String(disclosure.proof.type)}`,
        disclosure.event_ref,
      );
    }

    const anchorEpoch = epochById.get(disclosure.epoch_id);
    if (!anchorEpoch) {
      checks.anchor_epoch_present = false;
      return invalid(
        "ANCHOR_EPOCH_MISSING",
        `seq ${disclosure.envelope.chain.seq} references epoch ${disclosure.epoch_id}, which is not in anchor.epochs`,
        disclosure.event_ref,
      );
    }
    if (proofRoot !== anchorEpoch.root) {
      checks.merkle_inclusion_proof = false;
      return invalid(
        "MERKLE_ROOT_MISMATCH",
        `seq ${disclosure.envelope.chain.seq} proof root does not match anchor epoch ${disclosure.epoch_id}`,
        disclosure.event_ref,
      );
    }

    let computedRoot: string;
    try {
      computedRoot = await computeRootFromProof(leaf, siblings as Sibling[]);
    } catch (err) {
      checks.merkle_inclusion_proof = false;
      return invalid(
        "MERKLE_PROOF_INVALID",
        `seq ${disclosure.envelope.chain.seq} proof could not be evaluated: ${(err as Error).message}`,
        disclosure.event_ref,
      );
    }
    if (computedRoot !== proofRoot) {
      checks.merkle_inclusion_proof = false;
      return invalid(
        "MERKLE_PROOF_INVALID",
        `seq ${disclosure.envelope.chain.seq} proof does not reproduce its root`,
        disclosure.event_ref,
      );
    }
  }

  // 7. Recorder signatures under the pinned key. The key's active window must
  // cover each event timestamp.
  for (const disclosure of ordered) {
    if (!isRecorderKeyActive(pinnedKey, disclosure.envelope.event.ts)) {
      checks.recorder_key_active = false;
      return invalid(
        "RECORDER_KEY_NOT_ACTIVE",
        `pinned key "${pinnedKey.key_id}" was not active at ${disclosure.envelope.event.ts}`,
        disclosure.event_ref,
      );
    }
  }
  checks.recorder_key_active = true;

  for (const disclosure of ordered) {
    let ok = false;
    try {
      const signingInput = new TextEncoder().encode(
        canonicalize(envelopeCore(disclosure.envelope)),
      );
      ok = await verifyEd25519(
        pinnedKey.public_key_base64,
        disclosure.envelope.signatures.recorder,
        signingInput,
      );
    } catch {
      ok = false;
    }
    if (!ok) {
      checks.recorder_signature_verifies = false;
      return invalid(
        "RECORDER_SIGNATURE_INVALID",
        `seq ${disclosure.envelope.chain.seq} recorder signature did not verify under the pinned key`,
        disclosure.event_ref,
      );
    }
  }
  checks.recorder_signature_verifies = true;

  // 8. Chain links, including the optional bidirectional boundaries.
  checks.chain_links = true;
  for (let i = 1; i < ordered.length; i++) {
    const prev = ordered[i - 1]!;
    const next = ordered[i]!;
    const prevSeq = prev.envelope.chain.seq;
    const nextSeq = next.envelope.chain.seq;
    if (nextSeq !== prevSeq + 1) {
      checks.chain_links = false;
      return invalid(
        "CHAIN_LINK_GAP",
        `disclosed seqs ${prevSeq} and ${nextSeq} are not adjacent`,
        next.event_ref,
      );
    }
    const prevHash = normalizeHash(next.envelope.chain.prev_hash);
    const expected = await hashCanonical(envelopeCore(prev.envelope));
    if (!prevHash || prevHash !== expected) {
      checks.chain_links = false;
      return invalid(
        "CHAIN_LINK_MISMATCH",
        `seq ${nextSeq} prev_hash does not match seq ${prevSeq}`,
        next.event_ref,
      );
    }
  }

  // seq=0 must have a null prev_hash; seq>0 with no disclosed predecessor is
  // allowed only when there is no before_ref (partial boundary).
  const lowest = ordered[0]!;
  if (lowest.envelope.chain.seq === 0 && lowest.envelope.chain.prev_hash !== null) {
    checks.chain_links = false;
    return invalid(
      "CHAIN_LINK_MISMATCH",
      "seq 0 must have prev_hash=null",
      lowest.event_ref,
    );
  }

  if (set.before_ref) {
    const before = bySeq.get(set.before_ref.seq)!;
    const expected = await hashCanonical(envelopeCore(before.envelope));
    const actual = normalizeHash(firstRange.envelope.chain.prev_hash);
    if (!actual || actual !== expected) {
      checks.before_link = false;
      checks.chain_links = false;
      return invalid(
        "BEFORE_LINK_MISMATCH",
        `before_ref seq ${set.before_ref.seq} does not link to seq ${set.from_seq}`,
        firstRange.event_ref,
      );
    }
    checks.before_link = true;
  }

  if (set.after_ref) {
    const after = bySeq.get(set.after_ref.seq)!;
    const expected = await hashCanonical(envelopeCore(lastRange.envelope));
    const actual = normalizeHash(after.envelope.chain.prev_hash);
    if (!actual || actual !== expected) {
      checks.after_link = false;
      checks.chain_links = false;
      return invalid(
        "AFTER_LINK_MISMATCH",
        `after_ref seq ${set.after_ref.seq} does not link to seq ${set.to_seq}`,
        after.event_ref,
      );
    }
    checks.after_link = true;
  }

  // 9. Optional on-chain confirmation. Offline mode leaves these null and
  // still returns valid integrity checks.
  let anchorConfirmed = false;
  if (opts.base_rpc) {
    const expectedChainId = expectedNetwork.startsWith("eip155:")
      ? Number(expectedNetwork.slice("eip155:".length))
      : NaN;
    if (!Number.isSafeInteger(expectedChainId) || expectedChainId < 0) {
      return invalid(
        "UNSUPPORTED_NETWORK",
        `cannot derive an EVM chain id from ${expectedNetwork}`,
      );
    }
    let rpcChainId: number;
    try {
      rpcChainId = await fetchChainId(opts.base_rpc);
    } catch (err) {
      return invalid(
        "ANCHOR_RPC_UNREACHABLE",
        `could not read chain id from Base RPC: ${(err as Error).message}`,
      );
    }
    if (rpcChainId !== expectedChainId) {
      return invalid(
        "WRONG_CHAIN",
        `RPC reports chain id ${rpcChainId}; expected ${expectedChainId}`,
      );
    }

    checks.anchor_tx_on_chain = true;
    checks.anchor_from_authorized_anchorer = true;
    for (const epoch of set.anchor.epochs) {
      let anchor: Awaited<ReturnType<typeof fetchAnchorTx>>;
      try {
        anchor = await fetchAnchorTx(opts.base_rpc, epoch.tx_hash);
      } catch (err) {
        checks.anchor_tx_on_chain = false;
        return invalid(
          "ANCHOR_TX_UNREACHABLE",
          `could not fetch anchor tx ${epoch.tx_hash}: ${(err as Error).message}`,
        );
      }
      const expectedAddress = pinnedAnchorer.address.toLowerCase();
      if (
        anchor.from !== expectedAddress ||
        anchor.to !== expectedAddress
      ) {
        checks.anchor_from_authorized_anchorer = false;
        return invalid(
          "ANCHOR_FROM_UNAUTHORIZED",
          `anchor tx ${epoch.tx_hash} from/to is ${anchor.from}/${anchor.to}; expected ${expectedAddress}`,
        );
      }
      const root = normalizeHash(epoch.merkle_root);
      if (
        anchor.tx_hash.toLowerCase() !== epoch.tx_hash.toLowerCase() ||
        anchor.epoch_id !== epoch.epoch_id ||
        anchor.merkle_root !== root ||
        (epoch.block_number !== null &&
          anchor.block_number !== epoch.block_number)
      ) {
        checks.anchor_tx_on_chain = false;
        return invalid(
          "ANCHOR_TX_MISMATCH",
          `anchor tx ${epoch.tx_hash} does not match epoch ${epoch.epoch_id} and its root`,
        );
      }
    }
    anchorConfirmed = true;
  }

  const allChecksPass = Object.values(checks).every(
    (value) => value === true || value === null,
  );
  if (!allChecksPass) {
    return invalid("CHECK_FAILED", "one or more disclosure checks failed");
  }

  return {
    valid: true,
    anchor_confirmed: anchorConfirmed,
    disclosures_checked: checked,
    checks: { ...checks },
  };
}
