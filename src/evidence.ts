// Evidence document authoring path.
//
// This is the supported way to turn a mandate/delegation/consent document into
// an arca/1 control event. It is intentionally client-side and strict:
//   - the document is validated against the versioned schema;
//   - the unsigned document is canonicalized with RFC 8785 JCS;
//   - its SHA-256 hash becomes event.inputs_hash;
//   - event.kind is set from the document schema.
//
// The recorder still signs whatever it is given; it does not adjudicate the
// document. A caller that posts a hand-built kind:"mandate" event bypasses this
// path, and the Dispute Bundle verifier will catch a hash mismatch later.

import { canonicalize, sha256Hex } from "./canonical.js";
import type { ChainRef, EventKind, UnsignedSubmission } from "./types.js";

export const EVIDENCE_SCHEMAS = {
  mandate: "sheaf.mandate-document/1",
  delegation: "sheaf.delegation-document/1",
  consent: "sheaf.consent-document/1",
} as const;

/** Canonical authority reference used by control events and delegation
 *  parent checks: sheaf://<chain_id>/<seq>. */
export function authorityRef(chainId: string, seq: number): string {
  if (!chainId) throw new Error("authorityRef: chain_id is required");
  if (!Number.isInteger(seq) || seq < 0) {
    throw new Error("authorityRef: seq must be a non-negative integer");
  }
  return `sheaf://${chainId}/${seq}`;
}

export type EvidenceKind = keyof typeof EVIDENCE_SCHEMAS;

export type DocumentSignature = {
  alg: "Ed25519";
  key_id: string;
  public_key_base64: string;
  signature_base64: string;
};

export type EvidenceParty = {
  type: "human" | "policy";
  id: string;
  display_name: string;
};

export type EvidenceAgent = {
  type: "agent";
  id: string;
  display_name: string;
};

export type EvidenceScope = {
  merchant: string;
  tools: string[];
  amount_max_minor: number;
  currency: string;
  valid_from: string;
  valid_until: string;
};

export type MandateDocument = {
  schema: "sheaf.mandate-document/1";
  mandate_id: string;
  principal: EvidenceParty;
  agent: EvidenceAgent;
  scope: EvidenceScope;
  issued_at: string;
  expires_at: string;
  nonce: string;
  document_signature?: DocumentSignature;
};

export type DelegationDocument = {
  schema: "sheaf.delegation-document/1";
  delegation_id: string;
  issuer: { type: "human" | "policy"; id: string };
  subject: { type: "agent"; id: string };
  parent_id: string | null;
  scope: EvidenceScope;
  issued_at: string;
  expires_at: string;
  document_signature?: DocumentSignature;
};

export type ConsentDocument = {
  schema: "sheaf.consent-document/1";
  consent_id: string;
  payer: { type: "human"; id: string };
  agent_id: string;
  mandate_id: string;
  merchant: string;
  amount_minor: number;
  currency: string;
  consented_at: string;
  method:
    | "payer_signature"
    | "merchant_signature"
    | "passkey"
    | "checkout_consent"
    | "other";
  session_id: string;
  document_signature?: DocumentSignature;
};

export type EvidenceDocument =
  | MandateDocument
  | DelegationDocument
  | ConsentDocument;

export class EvidenceDocumentError extends Error {
  readonly errors: string[];
  constructor(errors: string[]) {
    super(`invalid evidence document: ${errors.join("; ")}`);
    this.name = "EvidenceDocumentError";
    this.errors = errors;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function onlyKeys(
  value: Record<string, unknown>,
  allowed: string[],
  path: string,
  errors: string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) errors.push(`${path}.${key}: unexpected field`);
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isIsoDate(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    return false;
  }
  return Number.isFinite(Date.parse(value));
}

function requireString(
  value: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
): void {
  if (!isNonEmptyString(value[key])) errors.push(`${path}.${key}: non-empty string required`);
}

function requireDate(
  value: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
): void {
  if (!isIsoDate(value[key])) errors.push(`${path}.${key}: ISO 8601 UTC timestamp required`);
}

function validateDocumentSignature(
  value: unknown,
  path: string,
  errors: string[],
): void {
  if (value === undefined) return;
  if (!isRecord(value)) {
    errors.push(`${path}: object required`);
    return;
  }
  onlyKeys(
    value,
    ["alg", "key_id", "public_key_base64", "signature_base64"],
    path,
    errors,
  );
  if (value.alg !== "Ed25519") errors.push(`${path}.alg: "Ed25519" required`);
  requireString(value, "key_id", path, errors);
  requireString(value, "public_key_base64", path, errors);
  requireString(value, "signature_base64", path, errors);
}

function validateScope(
  value: unknown,
  path: string,
  errors: string[],
): void {
  if (!isRecord(value)) {
    errors.push(`${path}: object required`);
    return;
  }
  onlyKeys(
    value,
    [
      "merchant",
      "tools",
      "amount_max_minor",
      "currency",
      "valid_from",
      "valid_until",
    ],
    path,
    errors,
  );
  requireString(value, "merchant", path, errors);

  if (!Array.isArray(value.tools) || value.tools.length === 0) {
    errors.push(`${path}.tools: non-empty array required`);
  } else {
    const seen = new Set<string>();
    value.tools.forEach((tool, idx) => {
      if (!isNonEmptyString(tool)) {
        errors.push(`${path}.tools[${idx}]: non-empty string required`);
      } else if (seen.has(tool)) {
        errors.push(`${path}.tools[${idx}]: duplicate tool`);
      } else {
        seen.add(tool);
      }
    });
  }

  if (
    !Number.isInteger(value.amount_max_minor) ||
    (value.amount_max_minor as number) < 0
  ) {
    errors.push(`${path}.amount_max_minor: non-negative integer required`);
  }
  if (
    typeof value.currency !== "string" ||
    !/^[A-Z]{3}$/.test(value.currency)
  ) {
    errors.push(`${path}.currency: ISO 4217 uppercase code required`);
  }
  requireDate(value, "valid_from", path, errors);
  requireDate(value, "valid_until", path, errors);
  if (
    isIsoDate(value.valid_from) &&
    isIsoDate(value.valid_until) &&
    Date.parse(value.valid_from) >= Date.parse(value.valid_until)
  ) {
    errors.push(`${path}.valid_until: must be after valid_from`);
  }
}

function validateMandate(document: Record<string, unknown>, errors: string[]): void {
  onlyKeys(
    document,
    [
      "schema",
      "mandate_id",
      "principal",
      "agent",
      "scope",
      "issued_at",
      "expires_at",
      "nonce",
      "document_signature",
    ],
    "document",
    errors,
  );
  if (document.schema !== EVIDENCE_SCHEMAS.mandate) {
    errors.push(`document.schema: "${EVIDENCE_SCHEMAS.mandate}" required`);
  }
  requireString(document, "mandate_id", "document", errors);

  if (!isRecord(document.principal)) {
    errors.push("document.principal: object required");
  } else {
    onlyKeys(
      document.principal,
      ["type", "id", "display_name"],
      "document.principal",
      errors,
    );
    if (!["human", "policy"].includes(String(document.principal.type))) {
      errors.push('document.principal.type: "human" or "policy" required');
    }
    requireString(document.principal, "id", "document.principal", errors);
    requireString(
      document.principal,
      "display_name",
      "document.principal",
      errors,
    );
  }

  if (!isRecord(document.agent)) {
    errors.push("document.agent: object required");
  } else {
    onlyKeys(
      document.agent,
      ["type", "id", "display_name"],
      "document.agent",
      errors,
    );
    if (document.agent.type !== "agent") {
      errors.push('document.agent.type: "agent" required');
    }
    requireString(document.agent, "id", "document.agent", errors);
    requireString(document.agent, "display_name", "document.agent", errors);
  }

  validateScope(document.scope, "document.scope", errors);
  requireDate(document, "issued_at", "document", errors);
  requireDate(document, "expires_at", "document", errors);
  if (
    isIsoDate(document.issued_at) &&
    isIsoDate(document.expires_at) &&
    Date.parse(document.issued_at) >= Date.parse(document.expires_at)
  ) {
    errors.push("document.expires_at: must be after issued_at");
  }
  requireString(document, "nonce", "document", errors);
  validateDocumentSignature(document.document_signature, "document.document_signature", errors);
}

function validateDelegation(document: Record<string, unknown>, errors: string[]): void {
  onlyKeys(
    document,
    [
      "schema",
      "delegation_id",
      "issuer",
      "subject",
      "parent_id",
      "scope",
      "issued_at",
      "expires_at",
      "document_signature",
    ],
    "document",
    errors,
  );
  if (document.schema !== EVIDENCE_SCHEMAS.delegation) {
    errors.push(`document.schema: "${EVIDENCE_SCHEMAS.delegation}" required`);
  }
  requireString(document, "delegation_id", "document", errors);

  if (!isRecord(document.issuer)) {
    errors.push("document.issuer: object required");
  } else {
    onlyKeys(document.issuer, ["type", "id"], "document.issuer", errors);
    if (!["human", "policy"].includes(String(document.issuer.type))) {
      errors.push('document.issuer.type: "human" or "policy" required');
    }
    requireString(document.issuer, "id", "document.issuer", errors);
  }

  if (!isRecord(document.subject)) {
    errors.push("document.subject: object required");
  } else {
    onlyKeys(document.subject, ["type", "id"], "document.subject", errors);
    if (document.subject.type !== "agent") {
      errors.push('document.subject.type: "agent" required');
    }
    requireString(document.subject, "id", "document.subject", errors);
  }

  if (
    document.parent_id !== null &&
    !isNonEmptyString(document.parent_id)
  ) {
    errors.push("document.parent_id: non-empty string or null required");
  }

  validateScope(document.scope, "document.scope", errors);
  requireDate(document, "issued_at", "document", errors);
  requireDate(document, "expires_at", "document", errors);
  if (
    isIsoDate(document.issued_at) &&
    isIsoDate(document.expires_at) &&
    Date.parse(document.issued_at) >= Date.parse(document.expires_at)
  ) {
    errors.push("document.expires_at: must be after issued_at");
  }
  validateDocumentSignature(document.document_signature, "document.document_signature", errors);
}

function validateConsent(document: Record<string, unknown>, errors: string[]): void {
  onlyKeys(
    document,
    [
      "schema",
      "consent_id",
      "payer",
      "agent_id",
      "mandate_id",
      "merchant",
      "amount_minor",
      "currency",
      "consented_at",
      "method",
      "session_id",
      "document_signature",
    ],
    "document",
    errors,
  );
  if (document.schema !== EVIDENCE_SCHEMAS.consent) {
    errors.push(`document.schema: "${EVIDENCE_SCHEMAS.consent}" required`);
  }
  requireString(document, "consent_id", "document", errors);

  if (!isRecord(document.payer)) {
    errors.push("document.payer: object required");
  } else {
    onlyKeys(document.payer, ["type", "id"], "document.payer", errors);
    if (document.payer.type !== "human") {
      errors.push('document.payer.type: "human" required');
    }
    requireString(document.payer, "id", "document.payer", errors);
  }

  requireString(document, "agent_id", "document", errors);
  requireString(document, "mandate_id", "document", errors);
  requireString(document, "merchant", "document", errors);
  if (
    !Number.isInteger(document.amount_minor) ||
    (document.amount_minor as number) < 0
  ) {
    errors.push("document.amount_minor: non-negative integer required");
  }
  if (
    typeof document.currency !== "string" ||
    !/^[A-Z]{3}$/.test(document.currency)
  ) {
    errors.push("document.currency: ISO 4217 uppercase code required");
  }
  requireDate(document, "consented_at", "document", errors);
  if (
    ![
      "payer_signature",
      "merchant_signature",
      "passkey",
      "checkout_consent",
      "other",
    ].includes(String(document.method))
  ) {
    errors.push("document.method: unsupported consent method");
  }
  requireString(document, "session_id", "document", errors);
  validateDocumentSignature(document.document_signature, "document.document_signature", errors);
}

export function evidenceKindForDocument(
  document: unknown,
): EvidenceKind | null {
  if (!isRecord(document)) return null;
  if (document.schema === EVIDENCE_SCHEMAS.mandate) return "mandate";
  if (document.schema === EVIDENCE_SCHEMAS.delegation) return "delegation";
  if (document.schema === EVIDENCE_SCHEMAS.consent) return "consent";
  return null;
}

/** Strict validation; returns every error rather than throwing. */
export function validateEvidenceDocument(document: unknown): string[] {
  if (!isRecord(document)) return ["document: object required"];
  const kind = evidenceKindForDocument(document);
  if (!kind) {
    return [
      `document.schema: one of ${Object.values(EVIDENCE_SCHEMAS).join(", ")} required`,
    ];
  }
  const errors: string[] = [];
  if (kind === "mandate") validateMandate(document, errors);
  else if (kind === "delegation") validateDelegation(document, errors);
  else validateConsent(document, errors);
  return errors;
}

/** The bytes that are hashed and signed: the document without its optional
 *  document_signature member. */
export function stripDocumentSignature(
  document: EvidenceDocument | Record<string, unknown>,
): Record<string, unknown> {
  const copy = { ...(document as Record<string, unknown>) };
  delete copy.document_signature;
  return copy;
}

export function canonicalEvidenceDocument(
  document: EvidenceDocument | Record<string, unknown>,
): string {
  return canonicalize(stripDocumentSignature(document));
}

/** Lowercase 64-hex SHA-256 of JCS(document without document_signature). */
export async function evidenceDocumentHash(
  document: EvidenceDocument | Record<string, unknown>,
): Promise<string> {
  return sha256Hex(canonicalEvidenceDocument(document));
}

export type BuildEvidenceOptions = {
  chain: ChainRef;
  ts: string;
  intent?: string;
  authority?: string | null;
  actor?: string;
  tool?: string;
  actor_signature?: string | null;
};

function defaultActor(document: EvidenceDocument): string {
  if (document.schema === EVIDENCE_SCHEMAS.mandate) return document.principal.id;
  if (document.schema === EVIDENCE_SCHEMAS.delegation) return document.issuer.id;
  return document.payer.id;
}

function defaultTool(kind: EvidenceKind): string {
  return `sheaf.${kind}`;
}

function defaultIntent(kind: EvidenceKind): string {
  if (kind === "mandate") return "issue mandate";
  if (kind === "delegation") return "delegate authority";
  return "record payer consent";
}

/**
 * Build the unsigned arca/1 submission for a control event.
 *
 * The caller then posts it to POST /events, where the recorder signs it. The
 * recorder does not validate the document; this function is the authoring gate.
 */
export async function buildEvidenceSubmission(
  document: EvidenceDocument,
  opts: BuildEvidenceOptions,
): Promise<UnsignedSubmission> {
  const errors = validateEvidenceDocument(document);
  if (errors.length > 0) throw new EvidenceDocumentError(errors);

  if (!opts || !opts.chain || !isNonEmptyString(opts.chain.chain_id)) {
    throw new Error("buildEvidenceSubmission: chain is required");
  }
  if (
    !Number.isInteger(opts.chain.seq) ||
    opts.chain.seq < 0 ||
    (opts.chain.prev_hash !== null &&
      typeof opts.chain.prev_hash !== "string")
  ) {
    throw new Error("buildEvidenceSubmission: invalid chain ref");
  }
  if (!isIsoDate(opts.ts)) {
    throw new Error("buildEvidenceSubmission: ts must be ISO 8601 UTC");
  }

  const kind = evidenceKindForDocument(document) as EvidenceKind;
  const documentHash = await evidenceDocumentHash(document);
  const actor = opts.actor ?? defaultActor(document);

  const event: UnsignedSubmission["event"] = {
    kind: kind as EventKind,
    intent: opts.intent ?? defaultIntent(kind),
    actor,
    // `authority` should be a sheaf://<chain_id>/<seq> ref when the caller has
    // one. It is deliberately not defaulted from document IDs (which identify
    // documents, not event positions).
    authority: opts.authority !== undefined ? opts.authority : null,
    tool: opts.tool ?? defaultTool(kind),
    inputs_hash: `sha256:${documentHash}`,
    outputs_hash: null,
    result: "ok",
    ts: opts.ts,
  };

  return {
    v: "arca/1",
    event,
    chain: opts.chain,
    signatures: { actor: opts.actor_signature ?? null },
  };
}

export type SignEvidenceDocumentOptions = {
  private_key_pkcs8_base64: string;
  key_id: string;
  public_key_base64: string;
};

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
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
 * Attach an Ed25519 document signature over the 32 raw bytes of
 * sha256(JCS(document without document_signature)).
 *
 * This is a convenience for authoring tools. The recorder never does this; the
 * principal/merchant signs on their own side.
 */
export async function signEvidenceDocument(
  document: EvidenceDocument,
  opts: SignEvidenceDocumentOptions,
): Promise<EvidenceDocument> {
  const errors = validateEvidenceDocument(document);
  if (errors.length > 0) throw new EvidenceDocumentError(errors);
  if (!opts || !opts.private_key_pkcs8_base64 || !opts.key_id) {
    throw new Error("signEvidenceDocument: private key and key_id required");
  }

  const digest = hexToBytes(await evidenceDocumentHash(document));
  const subtle = crypto.subtle as unknown as {
    importKey(
      f: string,
      k: Uint8Array,
      a: { name: string },
      e: boolean,
      u: string[],
    ): Promise<CryptoKey>;
    sign(a: string, k: CryptoKey, d: ArrayBuffer): Promise<ArrayBuffer>;
  };
  const key = await subtle.importKey(
    "pkcs8",
    b64decode(opts.private_key_pkcs8_base64),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const signature = await subtle.sign(
    "Ed25519",
    key,
    digest.buffer as ArrayBuffer,
  );
  return {
    ...document,
    document_signature: {
      alg: "Ed25519",
      key_id: opts.key_id,
      public_key_base64: opts.public_key_base64,
      signature_base64: b64encode(new Uint8Array(signature)),
    },
  } as EvidenceDocument;
}
