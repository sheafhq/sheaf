import { canonicalize, hashCanonical, sha256Hex } from "./canonical.js";
import { computeRootFromProof } from "./merkle.js";
import { verifyEd25519 } from "./signature.js";
import { fetchAnchorTx } from "./anchor.js";
import type {
  Envelope,
  ReceiptBundle,
  VerifyOptions,
  VerifyResult,
} from "./types.js";

export * from "./types.js";
export { canonicalize, sha256Hex, hashCanonical } from "./canonical.js";
export { computeRootFromProof } from "./merkle.js";
export { verifyEd25519 } from "./signature.js";
export { fetchAnchorTx } from "./anchor.js";

/**
 * Verify an Sheaf receipt bundle. Returns `{ valid, checks, reason? }` with a
 * per-check breakdown so callers can see exactly which invariant failed.
 *
 * Checks performed:
 *   1. Anchor tx exists on Base, calldata decodes correctly.
 *   2. Anchor tx `from` == `to` == `expected_anchorer_address`.
 *   3. Merkle root in the inclusion proof equals the one encoded in the anchor tx.
 *   4. (leaf, siblings) reproduces the Merkle root.
 *   5. Hash of the envelope (minus signatures) equals the leaf.
 *   6. Recorder Ed25519 signature verifies over canonical(v,event,chain).
 *   7. (optional) envelope.chain.prev_hash equals hash(prev_envelope).
 */
export async function verify(
  bundle: ReceiptBundle,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const checks: VerifyResult["checks"] = {
    anchor_on_chain: false,
    anchor_from_authorized_wallet: false,
    merkle_root_matches_on_chain: false,
    inclusion_proof_reproduces_root: false,
    envelope_hash_matches_leaf: false,
    recorder_signature_verifies: false,
    chain_prev_hash_matches: null,
  };

  // 1-2. Fetch anchor tx.
  let anchor: Awaited<ReturnType<typeof fetchAnchorTx>>;
  try {
    anchor = await fetchAnchorTx(opts.base_rpc, bundle.anchor_tx_hash);
    checks.anchor_on_chain = true;
  } catch (err) {
    return {
      valid: false,
      checks,
      reason: `anchor tx fetch failed: ${(err as Error).message}`,
    };
  }
  const expected = opts.expected_anchorer_address.toLowerCase();
  if (anchor.from !== expected || anchor.to !== expected) {
    return {
      valid: false,
      checks,
      reason: `anchor tx from/to is ${anchor.from}/${anchor.to}; expected ${expected} for both`,
    };
  }
  checks.anchor_from_authorized_wallet = true;

  // 3. Root in inclusion proof must match the on-chain root.
  if (
    bundle.inclusion_proof.merkle_root.toLowerCase() !==
    anchor.merkle_root.toLowerCase()
  ) {
    return {
      valid: false,
      checks,
      reason: `inclusion_proof.merkle_root (${bundle.inclusion_proof.merkle_root}) does not match on-chain root (${anchor.merkle_root})`,
    };
  }
  checks.merkle_root_matches_on_chain = true;

  // 4. (leaf, siblings) must reproduce the root.
  const rootFromProof = await computeRootFromProof(
    bundle.inclusion_proof.leaf,
    bundle.inclusion_proof.siblings,
  );
  if (rootFromProof.toLowerCase() !== anchor.merkle_root.toLowerCase()) {
    return {
      valid: false,
      checks,
      reason: `inclusion proof does not reproduce root (got ${rootFromProof}, expected ${anchor.merkle_root})`,
    };
  }
  checks.inclusion_proof_reproduces_root = true;

  // 5. Hash of envelope (minus signatures) must equal the leaf.
  const envelopeNoSigs = {
    v: bundle.envelope.v,
    event: bundle.envelope.event,
    chain: bundle.envelope.chain,
  };
  const envelopeHash = await hashCanonical(envelopeNoSigs);
  if (envelopeHash !== bundle.inclusion_proof.leaf) {
    return {
      valid: false,
      checks,
      reason: `envelope hash (${envelopeHash}) does not match leaf (${bundle.inclusion_proof.leaf})`,
    };
  }
  checks.envelope_hash_matches_leaf = true;

  // 6. Recorder Ed25519 signature must verify.
  const signingInput = new TextEncoder().encode(canonicalize(envelopeNoSigs));
  const sigOk = await verifyEd25519(
    opts.recorder_public_key_base64,
    bundle.envelope.signatures.recorder,
    signingInput,
  );
  if (!sigOk) {
    return {
      valid: false,
      checks,
      reason: "recorder signature did not verify under the provided public key",
    };
  }
  checks.recorder_signature_verifies = true;

  // 7. If prev_envelope is supplied, chain.prev_hash must equal its hash.
  if (bundle.prev_envelope) {
    const prevNoSigs = {
      v: bundle.prev_envelope.v,
      event: bundle.prev_envelope.event,
      chain: bundle.prev_envelope.chain,
    };
    const prevHash = await hashCanonical(prevNoSigs);
    if (bundle.envelope.chain.prev_hash !== prevHash) {
      return {
        valid: false,
        checks: { ...checks, chain_prev_hash_matches: false },
        reason: `chain.prev_hash (${bundle.envelope.chain.prev_hash}) does not match hash of prev_envelope (${prevHash})`,
      };
    }
    checks.chain_prev_hash_matches = true;
  }

  return {
    valid: true,
    checks,
    anchor_block: anchor.block_number,
  };
}
