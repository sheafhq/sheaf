// Evidence document verification for control events.
//
// The recorder signs whatever it is given; this module is the adjudicating
// check for a disclosed mandate/delegation/consent document:
//   - the document schema must match event.kind;
//   - sha256(JCS(document without document_signature)) must equal
//     event.inputs_hash;
//   - if document_signature is present, it must verify under its embedded key.
//
// The signature key is self-asserted. Identity binding (does this key belong to
// the named principal?) is out of scope; the eventual Dispute Bundle reports
// authorization_basis separately.

import { canonicalize, sha256Hex } from "./canonical.js";
import { verifyEd25519 } from "./signature.js";
import type { Envelope } from "./types.js";

export const EVIDENCE_SCHEMAS = {
  mandate: "sheaf.mandate-document/1",
  delegation: "sheaf.delegation-document/1",
  consent: "sheaf.consent-document/1",
} as const;

export type EvidenceKind = keyof typeof EVIDENCE_SCHEMAS;

export type EvidenceDocumentSignature = {
  alg: "Ed25519";
  key_id: string;
  public_key_base64: string;
  signature_base64: string;
};

export type EvidenceDocument = {
  schema: string;
  document_signature?: EvidenceDocumentSignature;
  [key: string]: unknown;
};

export type VerifyEvidenceOptions = {
  /** If true, a document without document_signature is invalid. Defaults false. */
  require_document_signature?: boolean;
};

export type VerifyEvidenceResult = {
  valid: boolean;
  code?: string;
  reason?: string;
  document_hash?: string;
  checks: {
    kind_supported: boolean;
    schema_matches_kind: boolean;
    document_hash_matches_inputs_hash: boolean;
    document_signature_verifies: boolean | null;
  };
};

export function evidenceKindForSchema(schema: unknown): EvidenceKind | null {
  if (schema === EVIDENCE_SCHEMAS.mandate) return "mandate";
  if (schema === EVIDENCE_SCHEMAS.delegation) return "delegation";
  if (schema === EVIDENCE_SCHEMAS.consent) return "consent";
  return null;
}

export function stripDocumentSignature(
  document: EvidenceDocument,
): Record<string, unknown> {
  const copy = { ...(document as Record<string, unknown>) };
  delete copy.document_signature;
  return copy;
}

export function canonicalEvidenceDocument(document: EvidenceDocument): string {
  return canonicalize(stripDocumentSignature(document));
}

/** Lowercase 64-hex SHA-256 of JCS(document without document_signature). */
export async function evidenceDocumentHash(
  document: EvidenceDocument,
): Promise<string> {
  return sha256Hex(canonicalEvidenceDocument(document));
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

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Verify that a disclosed document belongs to a control event, and that the
 * optional document signature covers the unsigned document hash.
 */
export async function verifyEvidenceDocument(
  envelope: Envelope,
  document: EvidenceDocument,
  opts: VerifyEvidenceOptions = {},
): Promise<VerifyEvidenceResult> {
  const checks: VerifyEvidenceResult["checks"] = {
    kind_supported: false,
    schema_matches_kind: false,
    document_hash_matches_inputs_hash: false,
    document_signature_verifies: null,
  };
  let computedHash: string | undefined;
  const invalid = (code: string, reason: string): VerifyEvidenceResult => ({
    valid: false,
    code,
    reason,
    ...(computedHash ? { document_hash: computedHash } : {}),
    checks: { ...checks },
  });

  if (!envelope || typeof envelope !== "object" || !envelope.event) {
    return invalid("INVALID_EVIDENCE_EVENT", "envelope.event is required");
  }
  if (!document || typeof document !== "object") {
    return invalid("INVALID_EVIDENCE_DOCUMENT", "document must be an object");
  }

  const kind = envelope.event.kind ?? "tool_call";
  if (kind === "tool_call") {
    return invalid(
      "NOT_EVIDENCE_EVENT",
      "event.kind is tool_call (or absent); no evidence document is expected",
    );
  }
  if (!(kind in EVIDENCE_SCHEMAS)) {
    return invalid("UNSUPPORTED_EVIDENCE_KIND", `unsupported event.kind: ${kind}`);
  }
  checks.kind_supported = true;

  if (document.schema !== EVIDENCE_SCHEMAS[kind as EvidenceKind]) {
    return invalid(
      "EVIDENCE_SCHEMA_MISMATCH",
      `document.schema ${String(document.schema)} does not match event.kind ${kind}`,
    );
  }
  checks.schema_matches_kind = true;

  const hash = await evidenceDocumentHash(document);
  computedHash = hash;
  const inputsHash = normalizeHash(envelope.event.inputs_hash);
  if (!inputsHash || inputsHash !== hash) {
    return invalid(
      "EVIDENCE_DOC_HASH_MISMATCH",
      `event.inputs_hash does not match sha256(JCS(document without document_signature))`,
    );
  }
  checks.document_hash_matches_inputs_hash = true;

  const signature = document.document_signature;
  if (signature === undefined) {
    if (opts.require_document_signature) {
      return invalid(
        "EVIDENCE_DOC_SIGNATURE_MISSING",
        "document_signature is required but absent",
      );
    }
    return {
      valid: true,
      document_hash: hash,
      checks: { ...checks },
    };
  }

  if (
    !signature ||
    typeof signature !== "object" ||
    signature.alg !== "Ed25519" ||
    typeof signature.public_key_base64 !== "string" ||
    typeof signature.signature_base64 !== "string"
  ) {
    return invalid(
      "EVIDENCE_DOC_SIGNATURE_INVALID",
      "document_signature is malformed",
    );
  }

  let ok = false;
  try {
    ok = await verifyEd25519(
      signature.public_key_base64,
      signature.signature_base64,
      hexToBytes(hash),
    );
  } catch {
    ok = false;
  }
  checks.document_signature_verifies = ok;
  if (!ok) {
    return invalid(
      "EVIDENCE_DOC_SIGNATURE_INVALID",
      "document_signature did not verify over the unsigned document hash",
    );
  }

  return {
    valid: true,
    document_hash: hash,
    checks: { ...checks },
  };
}
