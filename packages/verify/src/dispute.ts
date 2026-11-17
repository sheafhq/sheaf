// Dispute Bundle verifier.
//
// Returns two verdicts:
//   valid     — cryptographic integrity + pinned trust + anchor (when online)
//   complete  — every required evidence section is present and strong enough
//
// The per-check array follows the 13-step sequence in the plan. Offline mode
// leaves `anchor_on_base` null and `anchor_confirmed` false; it never invents
// on-chain presence.

import { canonicalize, hashCanonical } from "./canonical.js";
import { computeRootFromProof } from "./merkle.js";
import {
  decodeCanonicalBase64,
  decodeEd25519Point,
  isSmallOrderEd25519,
  keyFingerprint,
  verifyEd25519,
} from "./signature.js";
import { verifyDisclosures } from "./disclosures.js";
import { verifyEvidenceDocument } from "./evidence.js";
import { defaultTrustStore } from "./trust.js";
import {
  evaluatePolicy,
  validatePolicy,
  type PolicyDocument,
} from "./policy.js";
import type {
  DisclosureEvent,
  DisclosureSet,
  Envelope,
  Sibling,
  TrustStore,
} from "./types.js";

export const DISPUTE_BUNDLE_SCHEMA = "sheaf.dispute-bundle/1";

export const DISPUTE_CHECK_NAMES = [
  "schema_supported",
  "bundle_id_matches",
  "selection_contiguous",
  "chain_links",
  "disclosure_signatures_and_proofs",
  "anchor_roots_match",
  "payload_hashes_match",
  "mandate_evidence",
  "delegation_authority",
  "consent_evidence",
  "temporal_order",
  "anchor_on_base",
  "completeness",
  "policy_enforced",
] as const;

export type DisputeCheckName = (typeof DISPUTE_CHECK_NAMES)[number];

export type DisputeCheck = {
  step: number;
  name: DisputeCheckName;
  ok: boolean | null;
  code?: string;
  reason?: string;
};

/** A non-fatal finding that weakens what the bundle proves. Integrity can
 *  still be valid; the authorisation claim is downgraded. */
export type DisputeWarning = {
  code:
    | "RECORDER_SIGNED_NOT_PRINCIPAL"
    | "ROOT_ATTESTATION_UNVERIFIED"
    | "TRUSTED_SIGNER_INVALID"
    | "TRUSTED_SIGNER_IS_RECORDER";
  section: string;
  reason: string;
};

/**
 * Terminology (S1 review). Kept deliberately distinct:
 *
 *  - cryptographically_valid: the signature verifies under the strict Ed25519
 *    profile over the document hash. Says nothing about who signed.
 *  - key_class "recognised_recorder": the key is a recorder key in scope. A
 *    recorder records; its signature never counts as authorisation.
 *  - key_class "unrecognised": any other key. It is self-asserted, embedded
 *    in the document. Anyone, including a recorder with a second key, can
 *    produce one.
 *  - key_class "trusted_signer": the key is pinned BY THE RELYING PARTY
 *    (options.trusted_signers) to a party id, for a role and time window.
 *  - principal_authenticated: trusted_signer AND the pinned party equals the
 *    party the document names (mandate principal / delegation issuer /
 *    consent payer or merchant) AND the event time is in the pinned window.
 *    Relative to the relying party's own pins; this is NOT SAP.
 *  - authorisation "verified": every authorising document is
 *    principal_authenticated and the delegation root is backed by one of
 *    those signatures. Only then.
 */
export type SignatureKeyClass = "recognised_recorder" | "unrecognised" | "trusted_signer";

export type SignatureAssessment = {
  section: string;
  /** null when the document carries no signature. */
  key_class: SignatureKeyClass | null;
  cryptographically_valid: boolean;
  /** Lowercase hex of the raw 32-byte public key. */
  key_fingerprint: string | null;
  /** The party the document names as its authoriser. */
  expected_party: string | null;
  principal_authenticated: boolean;
};

export type AuthorisationTier =
  | "verified"
  | "unauthenticated"
  | "recorder_attested"
  | "absent"
  | "not_evaluated";

export type DisputeVerification = {
  valid: boolean;
  /**
   * Evidence completeness: every evidence section present and signed by a
   * NON-RECORDER key, plus payloads and claims. Unchanged for historical
   * bundles. It does not mean authorised by an authenticated principal; see
   * `authorisation`.
   */
  complete: boolean;
  anchor_confirmed: boolean;
  anchor_mode?: "base" | "local";
  bundle_id?: string;
  code?: string;
  reason?: string;
  checks: DisputeCheck[];
  evidence_gaps: string[];
  /** Present only when non-empty. */
  warnings?: DisputeWarning[];
  /** The authorisation tier. Never "verified" via unrecognised keys. */
  authorisation: AuthorisationTier;
  /** One entry per evidence document, in section order. */
  signatures: SignatureAssessment[];
};

/** A relying-party pin: "this key speaks for this party, in these roles,
 *  during this window". The relying party's assertion, like pinned recorder
 *  keys. */
export type TrustedSigner = {
  key_id?: string;
  public_key_base64: string;
  party_id: string;
  roles: Array<"mandate" | "delegation" | "consent">;
  active_from: string;
  active_until: string | null;
};

// ---- S1: signature classification --------------------------------------------
// All key comparisons use keyFingerprint() (raw key bytes), never key strings
// and never key_id. key_id is a free-text label and is ignored for
// classification.

/** Fingerprints of every key acting as a RECORDER for this bundle: the
 *  bundle's own recorder key plus every pinned or supplied recorder key. A
 *  document signed by one of these was signed by the recorder, never by a
 *  principal. */
function recorderKeySet(bundle: AnyBundle, trust: TrustStore | undefined): Set<string> {
  const keys = new Set<string>();
  const own = keyFingerprint(bundle?.recorder?.public_key_base64);
  if (own) keys.add(own);
  for (const k of (trust ?? defaultTrustStore()).recorder_keys) {
    const fp = keyFingerprint(k.public_key_base64);
    if (fp) keys.add(fp);
  }
  return keys;
}

function signatureObject(document: any): Record<string, unknown> | null {
  const sig = document?.document_signature;
  return sig && typeof sig === "object" && !Array.isArray(sig) ? sig : null;
}

function recorderSigned(document: any, recorderKeys: Set<string>): boolean {
  const fp = keyFingerprint(signatureObject(document)?.public_key_base64);
  return fp !== null && recorderKeys.has(fp);
}

/** Signed by a key that is NOT a recorder key. Call only on documents that
 *  passed verifyEvidenceDocument (signature valid, canonical encoding). This
 *  is a classification of the KEY, not an authentication of the signer. */
function signedByNonRecorderKey(document: any, recorderKeys: Set<string>): boolean {
  const fp = keyFingerprint(signatureObject(document)?.public_key_base64);
  return fp !== null && !recorderKeys.has(fp);
}

type RootStatus = "verified" | "observed" | "recorder" | "unverified";

/**
 * The delegation root's attestation is a claim inside the bundle, not a
 * signature anyone verified. It counts only when it is backed by a principal
 * signature that DID verify:
 * - no key material: the first delegation link must be principal-signed;
 * - key material: the same key (by fingerprint) AND the identical signature
 *   as the mandate's or the first link's verified principal signature.
 * Anything else is "unverified"; a recorder key is "recorder".
 */
function rootAttestationStatus(
  delegation: any,
  mandateDocument: any,
  recorderKeys: Set<string>,
): RootStatus {
  const att = delegation?.root?.attestation;
  if (!att || typeof att !== "object") return "unverified";
  if (att.basis === "recorder_observed") return "observed";
  const first = delegation?.chain?.[0]?.document;
  const hasKeyMaterial =
    att.public_key_base64 !== undefined || att.signature_base64 !== undefined;
  if (!hasKeyMaterial) {
    if (recorderSigned(first, recorderKeys)) return "recorder";
    return signedByNonRecorderKey(first, recorderKeys) ? "verified" : "unverified";
  }
  const fp = keyFingerprint(att.public_key_base64);
  if (fp !== null && recorderKeys.has(fp)) return "recorder";
  const backs = (doc: any): boolean => {
    const sig = signatureObject(doc);
    return (
      fp !== null &&
      !!sig &&
      signedByNonRecorderKey(doc, recorderKeys) &&
      keyFingerprint(sig.public_key_base64) === fp &&
      typeof att.signature_base64 === "string" &&
      att.signature_base64 === sig.signature_base64
    );
  };
  return backs(mandateDocument) || backs(first) ? "verified" : "unverified";
}

export type VerifyDisputeOptions = {
  /** Pinned trust. Defaults to the verifier's shipped trust store. */
  trust?: TrustStore;
  /** If omitted, integrity-only: anchor_on_base is null. */
  base_rpc?: string;
  expected_network?: string;
  /** Relying-party signer pins. Without them no signature is
   *  principal-authenticated, and authorisation can't be "verified". */
  trusted_signers?: TrustedSigner[];
};

const ROLES = ["mandate", "delegation", "consent"] as const;

/** Validate pins; invalid ones never authenticate anything (fail closed). */
function usableTrustedSigners(
  signers: TrustedSigner[] | undefined,
  recorderKeys: Set<string>,
  warn: (w: DisputeWarning) => void,
): Array<TrustedSigner & { fingerprint: string }> {
  const out: Array<TrustedSigner & { fingerprint: string }> = [];
  (signers ?? []).forEach((s, i) => {
    const label = `trusted_signers[${i}]`;
    const raw = decodeCanonicalBase64(s?.public_key_base64, 32);
    const point = raw ? decodeEd25519Point(raw) : null;
    const ok =
      !!point &&
      !isSmallOrderEd25519(point) &&
      typeof s.party_id === "string" &&
      s.party_id.length > 0 &&
      Array.isArray(s.roles) &&
      s.roles.length > 0 &&
      s.roles.every((r) => (ROLES as readonly string[]).includes(r)) &&
      Number.isFinite(Date.parse(s.active_from)) &&
      (s.active_until === null || Number.isFinite(Date.parse(s.active_until)));
    if (!ok) {
      warn({
        code: "TRUSTED_SIGNER_INVALID",
        section: label,
        reason: "trusted signer entry is malformed or uses a weak/non-canonical key; ignored",
      });
      return;
    }
    const fingerprint = keyFingerprint(s.public_key_base64)!;
    if (recorderKeys.has(fingerprint)) {
      warn({
        code: "TRUSTED_SIGNER_IS_RECORDER",
        section: label,
        reason: "a recorder key can never be a trusted principal signer; ignored",
      });
      return;
    }
    out.push({ ...s, fingerprint });
  });
  return out;
}

/** The party a document names as its authoriser. */
function expectedParty(kind: (typeof ROLES)[number], document: any): string | null {
  if (kind === "mandate") return document?.principal?.id ?? null;
  if (kind === "delegation") return document?.issuer?.id ?? null;
  return document?.method === "merchant_signature"
    ? (document?.merchant ?? null)
    : (document?.payer?.id ?? null);
}

type AnyBundle = Record<string, any>;
type Ref = { chain_id: string; seq: number };

function freshChecks(): DisputeCheck[] {
  return DISPUTE_CHECK_NAMES.map((name, idx) => ({
    step: idx + 1,
    name,
    ok: null,
  }));
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

function eventRefString(ref: Ref): string {
  return `${ref.chain_id}/${ref.seq}`;
}

function findDisclosure(bundle: AnyBundle, ref: Ref): DisclosureEvent | null {
  return (
    (bundle.disclosures as DisclosureEvent[]).find(
      (d) =>
        d.envelope.chain.chain_id === ref.chain_id &&
        d.envelope.chain.seq === ref.seq,
    ) ?? null
  );
}

function parseAuthorityRef(
  value: unknown,
): { chain_id: string; seq: number } | null {
  if (typeof value !== "string") return null;
  const match = /^sheaf:\/\/(.+)\/(\d+)$/.exec(value);
  if (!match) return null;
  return { chain_id: match[1]!, seq: Number(match[2]) };
}

function sameRef(a: Ref | null, b: Ref | null): boolean {
  if (a === null || b === null) return a === null && b === null;
  return a.chain_id === b.chain_id && a.seq === b.seq;
}

export async function computeDisputeBundleId(
  bundle: AnyBundle,
): Promise<string> {
  const copy = { ...bundle };
  delete copy.bundle_id;
  delete copy.verification;
  return `sha256:${await hashCanonical(copy)}`;
}

function check(
  checks: DisputeCheck[],
  step: number,
  ok: boolean | null,
  code?: string,
  reason?: string,
): void {
  const item = checks[step - 1]!;
  item.ok = ok;
  if (code) item.code = code;
  if (reason) item.reason = reason;
}

async function localDisclosureCheck(
  bundle: AnyBundle,
  disclosure: DisclosureEvent,
  anchorRoot: string,
): Promise<{ ok: boolean; code?: string; reason?: string }> {
  const core = {
    v: disclosure.envelope.v,
    event: disclosure.envelope.event,
    chain: disclosure.envelope.chain,
  };
  const leaf = normalizeHash(disclosure.envelope_hash);
  if (!leaf) {
    return {
      ok: false,
      code: "INVALID_ENVELOPE_HASH",
      reason: `seq ${disclosure.envelope.chain.seq} has an invalid envelope hash`,
    };
  }
  let computed: string;
  try {
    computed = await hashCanonical(core);
  } catch (err) {
    return {
      ok: false,
      code: "INVALID_ENVELOPE",
      reason: `seq ${disclosure.envelope.chain.seq} cannot be canonicalized: ${(err as Error).message}`,
    };
  }
  if (computed !== leaf) {
    return {
      ok: false,
      code: "ENVELOPE_HASH_MISMATCH",
      reason: `seq ${disclosure.envelope.chain.seq} envelope hash mismatch`,
    };
  }

  const proofRoot = normalizeHash(disclosure.proof?.root);
  if (!proofRoot || proofRoot !== normalizeHash(anchorRoot)) {
    return {
      ok: false,
      code: "MERKLE_ROOT_MISMATCH",
      reason: `seq ${disclosure.envelope.chain.seq} proof root does not match anchor epoch`,
    };
  }
  let computedRoot: string;
  try {
    computedRoot = await computeRootFromProof(
      leaf,
      disclosure.proof.siblings as Sibling[],
    );
  } catch (err) {
    return {
      ok: false,
      code: "MERKLE_PROOF_INVALID",
      reason: `seq ${disclosure.envelope.chain.seq} proof invalid: ${(err as Error).message}`,
    };
  }
  if (computedRoot !== proofRoot) {
    return {
      ok: false,
      code: "MERKLE_PROOF_INVALID",
      reason: `seq ${disclosure.envelope.chain.seq} proof does not reproduce root`,
    };
  }

  try {
    const ok = await verifyEd25519(
      bundle.recorder.public_key_base64,
      disclosure.envelope.signatures.recorder,
      new TextEncoder().encode(canonicalize(core)),
    );
    if (!ok) {
      return {
        ok: false,
        code: "RECORDER_SIGNATURE_INVALID",
        reason: `seq ${disclosure.envelope.chain.seq} recorder signature failed`,
      };
    }
  } catch (err) {
    return {
      ok: false,
      code: "RECORDER_SIGNATURE_INVALID",
      reason: `seq ${disclosure.envelope.chain.seq} signature error: ${(err as Error).message}`,
    };
  }

  return { ok: true };
}

function claimValue(bundle: AnyBundle, key: string): string | number | null {
  const claim = bundle.subject?.claims?.[key];
  return claim && typeof claim.value !== "undefined" ? claim.value : null;
}

function evidenceSection(
  bundle: AnyBundle,
  kind: "mandate" | "delegation" | "consent",
  section: any,
): {
  status: "included" | "hash_only" | "absent";
  disclosure: DisclosureEvent | null;
  document: any | null;
  hash: string | null;
  error?: { code: string; reason: string };
} {
  if (!section || section.status === "absent") {
    return { status: "absent", disclosure: null, document: null, hash: null };
  }
  const ref = section.event_ref as Ref;
  if (!ref) {
    return {
      status: section.status,
      disclosure: null,
      document: null,
      hash: null,
      error: {
        code: "EVIDENCE_EVENT_NOT_DISCLOSED",
        reason: `${kind} evidence has no event_ref`,
      },
    };
  }
  const disclosure = findDisclosure(bundle, ref);
  if (!disclosure) {
    return {
      status: section.status,
      disclosure: null,
      document: null,
      hash: null,
      error: {
        code: "EVIDENCE_EVENT_NOT_DISCLOSED",
        reason: `${kind} event ${eventRefString(ref)} is not disclosed`,
      },
    };
  }
  if ((disclosure.envelope.event.kind ?? "tool_call") !== kind) {
    return {
      status: section.status,
      disclosure,
      document: null,
      hash: null,
      error: {
        code: "EVIDENCE_KIND_MISMATCH",
        reason: `${kind} event ${eventRefString(ref)} has kind ${disclosure.envelope.event.kind ?? "tool_call"}`,
      },
    };
  }
  if (section.status === "hash_only") {
    const hash = normalizeHash(section.document_hash);
    if (!hash) {
      return {
        status: "hash_only",
        disclosure,
        document: null,
        hash: null,
        error: {
          code: "EVIDENCE_DOC_HASH_MISMATCH",
          reason: `${kind} hash_only document_hash is invalid`,
        },
      };
    }
    return { status: "hash_only", disclosure, document: null, hash };
  }
  if (!section.document || typeof section.document !== "object") {
    return {
      status: "included",
      disclosure,
      document: null,
      hash: null,
      error: {
        code: "INVALID_EVIDENCE_DOCUMENT",
        reason: `${kind} document is missing`,
      },
    };
  }
  return {
    status: "included",
    disclosure,
    document: section.document,
    hash: normalizeHash(section.document_hash),
  };
}

async function verifySectionDocument(
  section: any,
  kind: "mandate" | "delegation" | "consent",
  disclosure: DisclosureEvent,
): Promise<{ ok: boolean; hash?: string; code?: string; reason?: string }> {
  if (section.status !== "included") {
    return { ok: true };
  }
  const result = await verifyEvidenceDocument(disclosure.envelope, section.document);
  if (!result.valid) {
    return { ok: false, code: result.code, reason: result.reason };
  }
  if (
    section.document_hash &&
    result.document_hash &&
    normalizeHash(section.document_hash) !== result.document_hash
  ) {
    return {
      ok: false,
      code: "EVIDENCE_DOC_HASH_MISMATCH",
      reason: `${kind} section document_hash does not match the document`,
    };
  }
  return { ok: true, hash: result.document_hash };
}

function mandateScopeCovers(bundle: AnyBundle, document: any): boolean {
  const disputedSeq =
    bundle.subject?.disputed_event_seqs?.[0] ?? bundle.subject?.from_seq;
  const disputed = findDisclosure(bundle, {
    chain_id: bundle.subject.chain_id,
    seq: disputedSeq,
  });
  if (!disputed) return false;
  if (document.agent?.id !== disputed.envelope.event.actor) return false;

  const merchant = claimValue(bundle, "merchant");
  if (merchant !== null && String(merchant).toLowerCase() !== String(document.scope?.merchant ?? "").toLowerCase()) {
    return false;
  }
  const tool = claimValue(bundle, "tool");
  if (tool !== null && !(document.scope?.tools ?? []).includes(String(tool))) {
    return false;
  }
  const amount = claimValue(bundle, "amount_minor");
  if (
    amount !== null &&
    (!Number.isInteger(amount) ||
      (amount as number) > Number(document.scope?.amount_max_minor))
  ) {
    return false;
  }
  const currency = claimValue(bundle, "currency");
  if (currency !== null && String(currency) !== String(document.scope?.currency)) {
    return false;
  }
  const ts = Date.parse(disputed.envelope.event.ts);
  const from = Date.parse(document.scope?.valid_from);
  const until = Date.parse(document.scope?.valid_until);
  if (!Number.isFinite(ts) || !Number.isFinite(from) || !Number.isFinite(until)) {
    return false;
  }
  return ts >= from && ts <= until;
}

function gapsFromEvidence(
  bundle: AnyBundle,
  mandate: ReturnType<typeof evidenceSection>,
  delegation: any,
  consent: ReturnType<typeof evidenceSection>,
  recorderKeys: Set<string>,
): Set<string> {
  const gaps = new Set<string>();
  if (mandate.status !== "included") {
    gaps.add("mandate");
  } else if (!signedByNonRecorderKey(mandate.document, recorderKeys)) {
    gaps.add("mandate_signature");
  }

  if (!delegation || delegation.status !== "included") {
    gaps.add("delegation");
  } else {
    if (!Array.isArray(delegation.chain) || delegation.chain.length === 0) {
      gaps.add("delegation");
    } else {
      for (const link of delegation.chain) {
        if (!signedByNonRecorderKey(link.document, recorderKeys)) gaps.add("delegation_signature");
      }
      const mandateDocument =
        mandate.status === "included" ? mandate.document : null;
      if (rootAttestationStatus(delegation, mandateDocument, recorderKeys) !== "verified") {
        gaps.add("delegation_root");
      }
    }
  }

  if (consent.status !== "included") {
    gaps.add("consent");
  } else if (!signedByNonRecorderKey(consent.document, recorderKeys)) {
    gaps.add("consent_signature");
  }

  const disputedSeq =
    bundle.subject?.disputed_event_seqs?.[0] ?? bundle.subject?.from_seq;
  const disputed = findDisclosure(bundle, {
    chain_id: bundle.subject.chain_id,
    seq: disputedSeq,
  });
  if (disputed) {
    const hasArgs = (bundle.payloads ?? []).some(
      (p: any) =>
        p.event_ref?.seq === disputedSeq &&
        p.kind === "tool_arguments",
    );
    if (!hasArgs) gaps.add("payloads");
    if (disputed.envelope.event.result === "ok") {
      const hasResult = (bundle.payloads ?? []).some(
        (p: any) =>
          p.event_ref?.seq === disputedSeq && p.kind === "tool_result",
      );
      if (!hasResult) gaps.add("payloads");
    }
  } else {
    gaps.add("payloads");
  }

  if (!bundle.subject?.claims || Object.keys(bundle.subject.claims).length === 0) {
    gaps.add("claims");
  }
  return gaps;
}

/**
 * Verify a sheaf.dispute-bundle/1 artifact.
 *
 * This is pinned-trust only. It never fetches recorder.public_key_url and never
 * executes verification.cmd.
 */
export async function verifyDisputeBundle(
  bundle: AnyBundle,
  opts: VerifyDisputeOptions = {},
): Promise<DisputeVerification> {
  const checks = freshChecks();
  const gaps = new Set<string>();
  const warnings: DisputeWarning[] = [];
  const recorderKeys = recorderKeySet(bundle, opts.trust);
  const warnRecorderSigned = (section: string): void => {
    warnings.push({
      code: "RECORDER_SIGNED_NOT_PRINCIPAL",
      section,
      reason:
        `${section} is signed with a recorder key; counted as unsigned. ` +
        "A recorder signature is not a principal's authorisation.",
    });
  };
  const signers = usableTrustedSigners(opts.trusted_signers, recorderKeys, (w) =>
    warnings.push(w),
  );
  const assessments: SignatureAssessment[] = [];
  /** Classify one evidence document that already passed verifyEvidenceDocument
   *  (so a present signature is cryptographically valid, strict profile). */
  const assess = (
    section: string,
    kind: (typeof ROLES)[number],
    document: any,
    disclosure: DisclosureEvent | null | undefined,
  ): void => {
    const sig = signatureObject(document);
    const fp = keyFingerprint(sig?.public_key_base64);
    const party = expectedParty(kind, document);
    if (!sig || !fp) {
      assessments.push({
        section,
        key_class: null,
        cryptographically_valid: false,
        key_fingerprint: null,
        expected_party: party,
        principal_authenticated: false,
      });
      return;
    }
    const at = Date.parse(disclosure?.envelope?.event?.ts ?? "");
    const pins = signers.filter((s) => s.fingerprint === fp);
    const keyClass: SignatureKeyClass = recorderKeys.has(fp)
      ? "recognised_recorder"
      : pins.length
        ? "trusted_signer"
        : "unrecognised";
    const authenticated =
      keyClass === "trusted_signer" &&
      party !== null &&
      Number.isFinite(at) &&
      pins.some(
        (s) =>
          s.roles.includes(kind) &&
          s.party_id === party &&
          at >= Date.parse(s.active_from) &&
          (s.active_until === null || at < Date.parse(s.active_until)),
      );
    assessments.push({
      section,
      key_class: keyClass,
      cryptographically_valid: true,
      key_fingerprint: fp,
      expected_party: party,
      principal_authenticated: authenticated,
    });
  };
  let anchorConfirmed = false;
  let anchorMode: "base" | "local" = "base";
  let topCode: string | undefined;
  let topReason: string | undefined;

  const finish = (): DisputeVerification => {
    const valid =
      checks.slice(0, 12).every((c) => c.ok !== false) &&
      checks[13]!.ok !== false;
    const complete = checks[12]!.ok === true;
    const authorisation: AuthorisationTier = (() => {
      if (!valid) return "not_evaluated";
      if (assessments.some((a) => a.key_class === "recognised_recorder")) {
        return "recorder_attested";
      }
      const sectionMissing = ["mandate", "delegation", "consent"].some((g) => gaps.has(g));
      if (sectionMissing || assessments.length === 0 || assessments.some((a) => a.key_class === null)) {
        return "absent";
      }
      if (assessments.every((a) => a.principal_authenticated) && !gaps.has("delegation_root")) {
        return "verified";
      }
      return "unauthenticated";
    })();
    return {
      valid,
      complete,
      anchor_confirmed: anchorConfirmed,
      anchor_mode: anchorMode,
      ...(typeof bundle?.bundle_id === "string"
        ? { bundle_id: bundle.bundle_id }
        : {}),
      ...(topCode ? { code: topCode } : {}),
      ...(topReason ? { reason: topReason } : {}),
      checks,
      evidence_gaps: [...gaps].sort(),
      ...(warnings.length ? { warnings: [...warnings] } : {}),
      authorisation,
      signatures: assessments.map((a) => ({ ...a })),
    };
  };

  const fail = (step: number, code: string, reason: string): DisputeVerification => {
    check(checks, step, false, code, reason);
    topCode = code;
    topReason = reason;
    return finish();
  };

  // 1. schema and basic shape
  if (
    !bundle ||
    typeof bundle !== "object" ||
    bundle.schema !== DISPUTE_BUNDLE_SCHEMA ||
    !bundle.subject ||
    !Array.isArray(bundle.disclosures) ||
    !bundle.anchor ||
    !bundle.recorder ||
    !bundle.evidence
  ) {
    return fail(
      1,
      "SCHEMA_UNSUPPORTED",
      "bundle is not a sheaf.dispute-bundle/1 artifact",
    );
  }
  check(checks, 1, true);

  // 2. bundle_id
  let computedBundleId: string;
  try {
    computedBundleId = await computeDisputeBundleId(bundle);
  } catch (err) {
    return fail(
      2,
      "BUNDLE_ID_MISMATCH",
      `bundle_id could not be recomputed: ${(err as Error).message}`,
    );
  }
  if (computedBundleId !== bundle.bundle_id) {
    return fail(
      2,
      "BUNDLE_ID_MISMATCH",
      `bundle_id ${String(bundle.bundle_id)} does not match ${computedBundleId}`,
    );
  }
  check(checks, 2, true);

  // 3-6, 12: reuse #1's disclosure verifier for the execution window. Evidence
  // events outside the window are verified below.
  const execution = bundle.evidence.execution ?? {};
  const fromSeq = bundle.subject.from_seq;
  const toSeq = bundle.subject.to_seq;
  const beforeRef = execution.before_ref ?? null;
  const afterRef = execution.after_ref ?? null;

  const executionRefs: Ref[] = [];
  for (let seq = fromSeq; seq <= toSeq; seq++) {
    executionRefs.push({ chain_id: bundle.subject.chain_id, seq });
  }
  for (const ref of executionRefs) {
    if (!findDisclosure(bundle, ref)) {
      return fail(
        3,
        "MISSING_DISCLOSURE",
        `execution window is missing ${eventRefString(ref)}`,
      );
    }
  }

  const neededSeqs = new Set<number>([
    ...executionRefs.map((r) => r.seq),
    ...(beforeRef ? [beforeRef.seq] : []),
    ...(afterRef ? [afterRef.seq] : []),
  ]);
  const executionDisclosures = (bundle.disclosures as DisclosureEvent[]).filter(
    (d) => neededSeqs.has(d.envelope.chain.seq),
  );

  // All disclosed events must be either execution, boundary, or evidence.
  const evidenceRefs: Ref[] = [];
  const mandateSection = evidenceSection(bundle, "mandate", bundle.evidence.mandate);
  if (mandateSection.disclosure) evidenceRefs.push(mandateSection.disclosure.event_ref);
  if (bundle.evidence.delegation?.status === "included") {
    for (const link of bundle.evidence.delegation.chain ?? []) {
      evidenceRefs.push(link.event_ref);
    }
  }
  const consentSection = evidenceSection(bundle, "consent", bundle.evidence.consent);
  if (consentSection.disclosure) evidenceRefs.push(consentSection.disclosure.event_ref);

  const allowedSeqs = new Set<number>([...neededSeqs]);
  for (const ref of evidenceRefs) allowedSeqs.add(ref.seq);
  for (const d of bundle.disclosures as DisclosureEvent[]) {
    if (!allowedSeqs.has(d.envelope.chain.seq)) {
      return fail(
        3,
        "UNEXPECTED_DISCLOSURE",
        `seq ${d.envelope.chain.seq} is neither execution, boundary, nor evidence`,
      );
    }
  }

  const dset: DisclosureSet = {
    version: "sheaf-disclosure/1",
    chain_id: bundle.subject.chain_id,
    from_seq: fromSeq,
    to_seq: toSeq,
    recorder: bundle.recorder,
    disclosures: executionDisclosures,
    anchor: bundle.anchor,
    before_ref: beforeRef,
    after_ref: afterRef,
    warnings: [],
  };

  const dr = await verifyDisclosures(dset, {
    mode: "dispute",
    ...(opts.trust ? { trust: opts.trust } : {}),
    ...(opts.base_rpc ? { base_rpc: opts.base_rpc } : {}),
    ...(opts.expected_network
      ? { expected_network: opts.expected_network }
      : {}),
  });

  check(checks, 3, dr.checks.selection_contiguous);
  check(checks, 4, dr.checks.chain_links);
  const step5 =
    dr.checks.envelope_hash_matches_leaf &&
    dr.checks.recorder_key_known &&
    dr.checks.recorder_key_matches &&
    dr.checks.recorder_key_active &&
    dr.checks.recorder_signature_verifies &&
    dr.checks.merkle_inclusion_proof;
  check(checks, 5, step5);
  const step6 =
    dr.checks.anchor_epoch_present && dr.checks.anchor_calldata_matches_root;
  check(checks, 6, step6);
  check(
    checks,
    12,
    dr.checks.anchor_tx_on_chain === null
      ? null
      : dr.checks.anchor_tx_on_chain &&
          dr.checks.anchor_from_authorized_anchorer === true,
  );

  if (!dr.valid) {
    const keyError =
      dr.code === "UNKNOWN_RECORDER_KEY" ||
      dr.code === "RECORDER_KEY_MISMATCH" ||
      dr.code === "RECORDER_KEY_NOT_ACTIVE" ||
      dr.code === "RECORDER_SIGNATURE_INVALID" ||
      dr.code?.includes("MERKLE") ||
      dr.code === "ENVELOPE_HASH_MISMATCH";
    const selectionError =
      dr.code === "MISSING_DISCLOSURE" ||
      dr.code === "INVALID_BOUNDARY_REF" ||
      dr.code === "UNEXPECTED_DISCLOSURE";
    const chainError =
      dr.code?.includes("CHAIN_LINK") ||
      dr.code?.includes("BEFORE_LINK") ||
      dr.code?.includes("AFTER_LINK");
    const step = selectionError ? 3 : chainError ? 4 : keyError ? 5 : 12;
    return fail(step, dr.code ?? "DISCLOSURE_CHECK_FAILED", dr.reason ?? "disclosure verification failed");
  }
  anchorConfirmed = dr.anchor_confirmed;
  // A local bundle commits the same Merkle root offline. It is not a Base
  // transaction, so anchor_on_base stays null; the local anchor is still a
  // complete integrity proof for the offline ledger.
  const localAnchor =
    bundle.anchor?.mode === "local" ||
    (Array.isArray(bundle.anchor?.epochs) &&
      bundle.anchor.epochs.every(
        (epoch: any) =>
          typeof epoch?.tx_hash === "string" &&
          epoch.tx_hash.startsWith("local:"),
      ));
  if (localAnchor) {
    anchorMode = "local";
    if (!opts.base_rpc) anchorConfirmed = true;
  }

  // 5: verify evidence envelopes not covered by the execution set.
  for (const ref of evidenceRefs) {
    if (neededSeqs.has(ref.seq)) continue;
    const disclosure = findDisclosure(bundle, ref);
    if (!disclosure) {
      return fail(
        5,
        "EVIDENCE_EVENT_NOT_DISCLOSED",
        `evidence event ${eventRefString(ref)} is not disclosed`,
      );
    }
    const epoch = (bundle.anchor.epochs as any[]).find(
      (e) => e.epoch_id === disclosure.epoch_id,
    );
    if (!epoch) {
      return fail(
        6,
        "ANCHOR_EPOCH_MISSING",
        `evidence event ${eventRefString(ref)} references a missing anchor epoch`,
      );
    }
    const local = await localDisclosureCheck(
      bundle,
      disclosure,
      epoch.merkle_root,
    );
    if (!local.ok) {
      return fail(5, local.code ?? "EVIDENCE_PROOF_INVALID", local.reason ?? "evidence envelope verification failed");
    }
  }

  // 7: payloads
  if (!Array.isArray(bundle.payloads) || bundle.payloads.length === 0) {
    check(checks, 7, null);
  } else {
    for (const payload of bundle.payloads as any[]) {
      const disclosure = findDisclosure(bundle, payload.event_ref);
      if (!disclosure) {
        return fail(
          7,
          "PAYLOAD_EVENT_MISSING",
          `payload references undisclosed event ${eventRefString(payload.event_ref)}`,
        );
      }
      let hash: string;
      try {
        hash = await hashCanonical(payload.content);
      } catch (err) {
        return fail(
          7,
          "PAYLOAD_HASH_MISMATCH",
          `payload ${payload.id} cannot be canonicalized: ${(err as Error).message}`,
        );
      }
      if (normalizeHash(payload.sha256) !== hash) {
        return fail(
          7,
          "PAYLOAD_HASH_MISMATCH",
          `payload ${payload.id} content does not match payload.sha256`,
        );
      }
      const expected =
        payload.kind === "tool_arguments"
          ? disclosure.envelope.event.inputs_hash
          : payload.kind === "tool_result"
            ? disclosure.envelope.event.outputs_hash
            : (disclosure.envelope.event.outputs_hash ??
              disclosure.envelope.event.inputs_hash);
      if (normalizeHash(expected) !== hash) {
        return fail(
          7,
          "PAYLOAD_HASH_MISMATCH",
          `payload ${payload.id} does not match the event hash`,
        );
      }
    }
    check(checks, 7, true);
  }

  // 8: mandate
  if (mandateSection.error) {
    return fail(8, mandateSection.error.code, mandateSection.error.reason);
  }
  if (mandateSection.status !== "included") {
    check(checks, 8, null);
    gaps.add("mandate");
  } else {
    const docCheck = await verifySectionDocument(
      bundle.evidence.mandate,
      "mandate",
      mandateSection.disclosure!,
    );
    if (!docCheck.ok) {
      return fail(8, docCheck.code ?? "EVIDENCE_DOC_HASH_MISMATCH", docCheck.reason ?? "mandate document invalid");
    }
    if (mandateSection.disclosure!.envelope.event.actor !== mandateSection.document.principal?.id) {
      return fail(
        8,
        "MANDATE_PRINCIPAL_MISMATCH",
        "mandate event actor does not equal document principal.id",
      );
    }
    if (!mandateScopeCovers(bundle, mandateSection.document)) {
      return fail(
        8,
        "MANDATE_SCOPE_MISMATCH",
        "mandate scope does not cover the disputed event and subject claims",
      );
    }
    check(checks, 8, true);
    if (recorderSigned(mandateSection.document, recorderKeys)) {
      warnRecorderSigned("mandate");
    }
    assess("mandate", "mandate", mandateSection.document, mandateSection.disclosure);
    if (!signedByNonRecorderKey(mandateSection.document, recorderKeys)) {
      gaps.add("mandate_signature");
    }
  }

  // 9: delegation
  if (!bundle.evidence.delegation || bundle.evidence.delegation.status === "absent") {
    check(checks, 9, null);
    gaps.add("delegation");
  } else {
    const chain = bundle.evidence.delegation.chain ?? [];
    if (!Array.isArray(chain) || chain.length === 0) {
      check(checks, 9, null);
      gaps.add("delegation");
    } else {
      const disputedSeq =
        bundle.subject.disputed_event_seqs?.[0] ?? bundle.subject.from_seq;
      const disputed = findDisclosure(bundle, {
        chain_id: bundle.subject.chain_id,
        seq: disputedSeq,
      });
      for (let i = 0; i < chain.length; i++) {
        const link = chain[i];
        const disclosure = findDisclosure(bundle, link.event_ref);
        if (!disclosure) {
          return fail(
            9,
            "EVIDENCE_EVENT_NOT_DISCLOSED",
            `delegation event ${eventRefString(link.event_ref)} is not disclosed`,
          );
        }
        const parsed = parseAuthorityRef(disclosure.envelope.event.authority);
        if (!sameRef(link.parent_event_ref ?? null, parsed)) {
          return fail(
            9,
            "DELEGATION_PARENT_MISMATCH",
            `delegation ${eventRefString(link.event_ref)} parent_event_ref does not equal event.authority`,
          );
        }
        if (disclosure.envelope.event.actor !== link.document?.issuer?.id) {
          return fail(
            9,
            "DELEGATION_ISSUER_MISMATCH",
            `delegation ${eventRefString(link.event_ref)} issuer does not equal event.actor`,
          );
        }
        const expectedSubject =
          i + 1 < chain.length
            ? chain[i + 1].document?.issuer?.id
            : disputed?.envelope.event.actor;
        if (expectedSubject && link.document?.subject?.id !== expectedSubject) {
          return fail(
            9,
            "DELEGATION_SUBJECT_MISMATCH",
            `delegation ${eventRefString(link.event_ref)} subject does not continue the chain`,
          );
        }
        const docCheck = await verifySectionDocument(
          link,
          "delegation",
          disclosure,
        );
        if (!docCheck.ok) {
          return fail(9, docCheck.code ?? "EVIDENCE_DOC_HASH_MISMATCH", docCheck.reason ?? "delegation document invalid");
        }
        if (recorderSigned(link.document, recorderKeys)) {
          warnRecorderSigned(`delegation ${eventRefString(link.event_ref)}`);
        }
        assess(`delegation ${eventRefString(link.event_ref)}`, "delegation", link.document, disclosure);
        if (!signedByNonRecorderKey(link.document, recorderKeys)) {
          gaps.add("delegation_signature");
        }
      }
      const rootStatus = rootAttestationStatus(
        bundle.evidence.delegation,
        mandateSection.status === "included" ? mandateSection.document : null,
        recorderKeys,
      );
      const claimed = String(bundle.evidence.delegation.root?.attestation?.basis ?? "none");
      if (rootStatus === "recorder") {
        warnRecorderSigned(`delegation root (claimed ${claimed})`);
      } else if (rootStatus === "unverified") {
        warnings.push({
          code: "ROOT_ATTESTATION_UNVERIFIED",
          section: `delegation root (claimed ${claimed})`,
          reason:
            "the root attestation is not backed by a verified principal signature in this bundle " +
            "(no matching mandate or first-delegation signature); counted as absent.",
        });
      }
      if (rootStatus !== "verified") gaps.add("delegation_root");
      check(checks, 9, true);
    }
  }

  // 10: consent
  if (consentSection.error) {
    return fail(10, consentSection.error.code, consentSection.error.reason);
  }
  if (consentSection.status !== "included") {
    check(checks, 10, null);
    gaps.add("consent");
  } else {
    const docCheck = await verifySectionDocument(
      bundle.evidence.consent,
      "consent",
      consentSection.disclosure!,
    );
    if (!docCheck.ok) {
      return fail(10, docCheck.code ?? "EVIDENCE_DOC_HASH_MISMATCH", docCheck.reason ?? "consent document invalid");
    }
    const consent = bundle.evidence.consent;
    const doc = consent.document;
    if (
      mandateSection.status === "included" &&
      doc.mandate_id !== mandateSection.document.mandate_id
    ) {
      return fail(10, "CONSENT_MANDATE_MISMATCH", "consent mandate_id does not match mandate");
    }
    const disputedSeq =
      bundle.subject.disputed_event_seqs?.[0] ?? bundle.subject.from_seq;
    const disputed = findDisclosure(bundle, {
      chain_id: bundle.subject.chain_id,
      seq: disputedSeq,
    });
    if (!disputed || doc.agent_id !== disputed.envelope.event.actor) {
      return fail(10, "CONSENT_AGENT_MISMATCH", "consent agent_id does not match disputed actor");
    }
    if (Date.parse(doc.consented_at) > Date.parse(disputed.envelope.event.ts)) {
      return fail(10, "CONSENT_TIME_MISMATCH", "consent was recorded after the disputed event");
    }
    if (
      consent.artifact &&
      normalizeHash(consent.artifact.sha256) !== docCheck.hash
    ) {
      return fail(10, "CONSENT_ARTIFACT_MISMATCH", "consent artifact hash does not match document");
    }
    if (recorderSigned(doc, recorderKeys)) warnRecorderSigned("consent");
    assess("consent", "consent", doc, consentSection.disclosure);
    if (!signedByNonRecorderKey(doc, recorderKeys)) gaps.add("consent_signature");
    check(checks, 10, true);
  }

  // 11: temporal order
  {
    const created = Date.parse(bundle.created_at);
    if (!Number.isFinite(created)) {
      return fail(11, "TEMPORAL_ORDER_INVALID", "bundle.created_at is invalid");
    }
    for (const d of bundle.disclosures as DisclosureEvent[]) {
      const ts = Date.parse(d.envelope.event.ts);
      if (!Number.isFinite(ts) || ts > created) {
        return fail(
          11,
          "TEMPORAL_ORDER_INVALID",
          `event ${d.envelope.chain.seq} timestamp is after bundle.created_at`,
        );
      }
    }
    const times: number[] = [];
    if (mandateSection.status === "included") {
      times.push(Date.parse(mandateSection.document.issued_at));
    }
    if (bundle.evidence.delegation?.status === "included") {
      for (const link of bundle.evidence.delegation.chain ?? []) {
        times.push(Date.parse(link.document.issued_at));
      }
    }
    if (consentSection.status === "included") {
      times.push(Date.parse(consentSection.document.consented_at));
    }
    if (times.some((t) => !Number.isFinite(t))) {
      return fail(11, "TEMPORAL_ORDER_INVALID", "evidence timestamp is invalid");
    }
    for (let i = 1; i < times.length; i++) {
      if (times[i]! < times[i - 1]!) {
        return fail(
          11,
          "TEMPORAL_ORDER_INVALID",
          "mandate/delegation/consent timestamps are out of order",
        );
      }
    }
    check(checks, 11, true);
  }

  // 13: completeness
  const finalGaps = gapsFromEvidence(
    bundle,
    mandateSection,
    bundle.evidence.delegation,
    consentSection,
    recorderKeys,
  );
  for (const gap of finalGaps) gaps.add(gap);
  const complete = gaps.size === 0;
  check(
    checks,
    13,
    complete,
    complete ? undefined : "EVIDENCE_INCOMPLETE",
    complete ? undefined : [...gaps].sort().join(", "),
  );

  // 14: policy_enforced (optional attachment)
  if (!bundle.policy) {
    check(checks, 14, null);
  } else {
    const policySection = bundle.policy;
    const errors = validatePolicy(policySection.document);
    if (errors.length > 0) {
      return fail(14, "INVALID_POLICY", errors.join("; "));
    }
    const policy = policySection.document as PolicyDocument;
    const policyHash = `sha256:${await hashCanonical(policy)}`;
    if (policySection.hash !== policyHash) {
      return fail(
        14,
        "POLICY_HASH_MISMATCH",
        `attached policy hash ${String(policySection.hash)} does not match ${policyHash}`,
      );
    }

    for (const disclosure of bundle.disclosures as DisclosureEvent[]) {
      const kind = disclosure.envelope.event.kind ?? "tool_call";
      if (kind !== "tool_call") continue;
      const applied = disclosure.envelope.event.policy;
      if (!applied) {
        return fail(
          14,
          "POLICY_NOT_APPLIED",
          `tool_call seq ${disclosure.envelope.chain.seq} has no policy verdict`,
        );
      }
      if (applied.hash !== policyHash) {
        return fail(
          14,
          "POLICY_HASH_MISMATCH",
          `tool_call seq ${disclosure.envelope.chain.seq} uses policy hash ${applied.hash}`,
        );
      }
      if (disclosure.envelope.event.result === "blocked") {
        if (applied.verdict === "ALLOW") {
          return fail(
            14,
            "POLICY_INCONSISTENT",
            `blocked event seq ${disclosure.envelope.chain.seq} has ALLOW verdict`,
          );
        }
        continue;
      }
      if (applied.verdict !== "ALLOW") {
        return fail(
          14,
          "POLICY_VIOLATION_RECORDED",
          `tool_call seq ${disclosure.envelope.chain.seq} was recorded with verdict ${applied.verdict}`,
        );
      }

      const argsPayload = (bundle.payloads as any[]).find(
        (payload) =>
          payload.event_ref?.seq === disclosure.envelope.chain.seq &&
          payload.kind === "tool_arguments",
      );
      if (argsPayload) {
        const tool = String(disclosure.envelope.event.tool).replace(
          /^mcp:\/\/tool\//,
          "",
        );
        const decision = evaluatePolicy(tool, argsPayload.content, policy);
        if (decision.verdict !== "ALLOW") {
          return fail(
            14,
            "POLICY_VIOLATION_RECORDED",
            `tool_call seq ${disclosure.envelope.chain.seq} violates policy: ${decision.reason_code}`,
          );
        }
      }
    }
    check(checks, 14, true);
  }

  return finish();
}

/** Stable text output shared by the CLI and the browser verifier. */
export function formatDisputeVerification(
  result: DisputeVerification,
): string {
  const verdict = !result.valid
    ? "NOT VALID"
    : !result.anchor_confirmed
      ? "VALID (integrity only; anchor unconfirmed)"
      : result.complete
        ? "VALID (complete)"
        : "VALID (partial)";

  // Line 2, always: what the verdict does NOT say. Never "verified" via an
  // unrecognised key.
  const AUTHORISATION_TEXT: Record<AuthorisationTier, string> = {
    verified:
      "verified — every authorising document is signed by a relying-party-pinned signer for the party it names (a relying-party pin, not SAP identity)",
    unauthenticated:
      "unauthenticated — signatures are cryptographically valid but made with unrecognised keys; no signer is authenticated as the named principal",
    recorder_attested:
      "recorder-attested only — a recorder key signed evidence documents; there is no principal signature",
    absent: "absent — at least one authorising document is missing or unsigned",
    not_evaluated: "not evaluated — the bundle is not valid",
  };
  const lines: string[] = [verdict];
  lines.push(`authorisation: ${AUTHORISATION_TEXT[result.authorisation ?? "not_evaluated"]}`);
  if (result.bundle_id) lines.push(`bundle_id: ${result.bundle_id}`);
  if (result.code) lines.push(`code: ${result.code}`);
  if (result.reason) lines.push(`reason: ${result.reason}`);
  lines.push("checks:");
  for (const c of result.checks) {
    const mark = c.ok === true ? "✓" : c.ok === false ? "✗" : "–";
    lines.push(
      `[${c.step}] ${c.name} ${mark}${c.code ? ` ${c.code}` : ""}`,
    );
  }
  lines.push(
    `evidence_gaps: ${result.evidence_gaps.length ? result.evidence_gaps.join(", ") : "none"}`,
  );
  lines.push(`anchor_confirmed: ${result.anchor_confirmed}`);
  lines.push(`anchor_mode: ${result.anchor_mode ?? "base"}`);
  for (const s of result.signatures ?? []) {
    const key =
      s.key_class === null
        ? "unsigned"
        : `${s.cryptographically_valid ? "valid" : "INVALID"} signature, key ${s.key_class.replace(/_/g, " ")} (${s.key_fingerprint?.slice(0, 16)}…)`;
    lines.push(
      `signature [${s.section}]: ${key}; names party ${s.expected_party ?? "?"}; principal ${s.principal_authenticated ? "AUTHENTICATED (relying-party pin)" : "not authenticated"}`,
    );
  }
  for (const w of result.warnings ?? []) {
    lines.push(`warning: ${w.code} [${w.section}] ${w.reason}`);
  }
  return lines.join("\n") + "\n";
}
