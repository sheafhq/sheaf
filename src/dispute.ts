// Dispute Bundle assembler.
//
// The builder is deliberately offline: it consumes a disclosure set (already
// produced by the selective-disclosure primitive), local evidence documents,
// and local payloads. It never contacts Sheaf or a Base RPC.
//
// `bundle_id` seals everything except itself and the advisory `verification`
// block: sha256(JCS(bundle without bundle_id and verification)).

import { canonicalize, hashCanonical } from "./canonical.js";
import {
  normalizeHash,
  type AnchorEpoch,
  type Disclosure,
  type DisclosureSet,
  type EventRef,
  type RecorderIdentity,
} from "./disclose.js";
import {
  authorityRef,
  evidenceDocumentHash,
  validateEvidenceDocument,
  type ConsentDocument,
  type DelegationDocument,
  type DocumentSignature,
  type EvidenceDocument,
  type MandateDocument,
} from "./evidence.js";

export const DISPUTE_BUNDLE_SCHEMA = "sheaf.dispute-bundle/1" as const;

export type DisputeBasis = {
  category: string;
  asserted_by: string;
  merchant_position: string;
};

export type DisputeCase = {
  case_id: string;
  card_network: string;
  reason_code: {
    schema: string;
    value: string;
    label: string | null;
  };
  transaction: {
    reference: string;
    amount_minor: number;
    currency: string;
    occurred_at: string;
  };
  merchant: {
    id: string;
    name: string;
    url: string;
  };
  response_due_at: string;
  dispute_basis: DisputeBasis;
};

export type SubjectClaim = {
  value: string | number;
  derived_from: "event.actor" | "event.tool" | "event.ts" | "payload" | "case";
  ref?: string;
  path?: string;
};

export type SubjectClaims = Record<string, SubjectClaim>;

export type DisputeSubjectInput = {
  from_seq: number;
  to_seq: number;
  disputed_event_seqs: number[];
  claims?: SubjectClaims;
};

export type DisputeCaseInput = DisputeCase & {
  subject: DisputeSubjectInput;
  created_at?: string;
};

export type RootAuthority = {
  type: "human" | "policy";
  id: string;
  display_name: string;
  attestation: {
    basis: "principal_signature" | "policy_signature" | "recorder_observed";
    key_id?: string;
    public_key_base64?: string;
    signature_base64?: string;
  };
};

export type IncludedEvidence<T> = {
  status: "included";
  event_ref: EventRef;
  document: T;
  authorization_basis?: string;
};

export type HashOnlyEvidence = {
  status: "hash_only";
  event_ref: EventRef;
  document_hash: string;
};

export type AbsentEvidence = { status: "absent" };

export type EvidenceInput<T> =
  | IncludedEvidence<T>
  | HashOnlyEvidence
  | AbsentEvidence;

export type DelegationLinkInput = {
  event_ref: EventRef;
  parent_event_ref: EventRef | null;
  document: DelegationDocument;
  authorization_basis?: string;
};

export type DelegationEvidenceInput =
  | {
      status: "included";
      root?: RootAuthority;
      chain: DelegationLinkInput[];
    }
  | { status: "absent" };

export type ConsentEvidenceInput = EvidenceInput<ConsentDocument> & {
  consent_type?: string;
  captured_at?: string;
};

export type EvidenceInputs = {
  mandate: EvidenceInput<MandateDocument>;
  delegation: DelegationEvidenceInput;
  consent: ConsentEvidenceInput;
};

export type PayloadInput = {
  id?: string;
  event_ref: EventRef;
  kind: "tool_arguments" | "tool_result" | "other";
  content: unknown;
  media_type?: string;
};

export type DisputePayload = {
  id: string;
  event_ref: EventRef;
  kind: PayloadInput["kind"];
  sha256: string;
  media_type: string;
  canonicalization: "RFC8785";
  content: unknown;
  attachment_ref: null;
};

export type DisputeEvidenceSection<T> =
  | {
      status: "included";
      event_ref: EventRef;
      document: T;
      document_hash: string;
      document_signature: DocumentSignature | null;
      authorization_basis: string;
    }
  | {
      status: "hash_only";
      event_ref: EventRef;
      document: null;
      document_hash: string;
      document_signature: null;
      authorization_basis: null;
    }
  | {
      status: "absent";
      event_ref: null;
      document: null;
      document_hash: null;
      document_signature: null;
      authorization_basis: null;
    };

export type DisputeBundle = {
  schema: typeof DISPUTE_BUNDLE_SCHEMA;
  bundle_id: string;
  created_at: string;
  producer: { name: string; version: string; command: string };
  case: DisputeCase;
  subject: {
    chain_id: string;
    from_seq: number;
    to_seq: number;
    selection: "contiguous_range";
    disputed_event_seqs: number[];
    claims: SubjectClaims;
  };
  recorder: RecorderIdentity;
  disclosures: Disclosure[];
  evidence: {
    mandate: DisputeEvidenceSection<MandateDocument>;
    delegation:
      | {
          status: "included";
          root: RootAuthority;
          chain: Array<{
            event_ref: EventRef;
            parent_event_ref: EventRef | null;
            document: DelegationDocument;
            document_hash: string;
            document_signature: DelegationDocument["document_signature"] | null;
            authorization_basis: string;
          }>;
        }
      | { status: "absent" };
    execution: {
      window: { from_seq: number; to_seq: number; contiguous: true };
      event_refs: EventRef[];
      before_ref: EventRef | null;
      after_ref: EventRef | null;
    };
    consent: DisputeEvidenceSection<ConsentDocument> & {
      consent_type: string | null;
      captured_at: string | null;
      artifact:
        | {
            sha256: string;
            media_type: "application/json";
            content: ConsentDocument;
            attachment_ref: null;
          }
        | null;
    };
  };
  anchor: {
    network: string;
    anchorer: string;
    epochs: AnchorEpoch[];
  };
  payloads: DisputePayload[];
  policy?: {
    schema: "sheaf.policy/1";
    hash: string;
    document: unknown;
  };
  attachments: [];
  presentation: {
    title: string;
    summary: string;
    timeline: Array<{ at: string; label: string; event_ref: EventRef }>;
    limitations: string[];
  };
  verification: {
    lib: string;
    min_version: string;
    cmd: string;
    trust: {
      recorder_key_id: string;
      anchorer_address: string;
      base_network: string;
    };
  };
};

export class DisputeBuildError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DisputeBuildError";
    this.code = code;
  }
}

function refKey(ref: EventRef): string {
  return `${ref.chain_id}/${ref.seq}`;
}

function findDisclosure(
  disclosures: DisclosureSet,
  ref: EventRef,
): Disclosure | null {
  return (
    disclosures.disclosures.find(
      (d) =>
        d.envelope.chain.chain_id === ref.chain_id &&
        d.envelope.chain.seq === ref.seq,
    ) ?? null
  );
}

function requireDisclosure(
  disclosures: DisclosureSet,
  ref: EventRef,
): Disclosure {
  if (ref.chain_id !== disclosures.chain_id) {
    throw new DisputeBuildError(
      "EVENT_REF_CHAIN_MISMATCH",
      `event ref ${refKey(ref)} is not on ${disclosures.chain_id}`,
    );
  }
  const disclosure = findDisclosure(disclosures, ref);
  if (!disclosure) {
    throw new DisputeBuildError(
      "EVENT_NOT_DISCLOSED",
      `event ${refKey(ref)} is not in the disclosure set`,
    );
  }
  return disclosure;
}

export function parseAuthorityRef(
  value: string | null,
): { chain_id: string; seq: number } | null {
  if (typeof value !== "string") return null;
  const match = /^sheaf:\/\/(.+)\/(\d+)$/.exec(value);
  if (!match) return null;
  return { chain_id: match[1]!, seq: Number(match[2]) };
}

function sameRef(a: EventRef | null, b: { chain_id: string; seq: number } | null): boolean {
  if (a === null || b === null) return a === null && b === null;
  return a.chain_id === b.chain_id && a.seq === b.seq;
}

function defaultAuthorizationBasis(
  doc: EvidenceDocument,
  eventKind: "mandate" | "delegation" | "consent",
): string {
  if (!doc.document_signature) return "recorder_observed";
  if (eventKind === "consent") {
    return doc.schema === "sheaf.consent-document/1" &&
      doc.method === "merchant_signature"
      ? "merchant_signature"
      : "payer_signature";
  }
  if (doc.schema === "sheaf.mandate-document/1") {
    return doc.principal.type === "policy"
      ? "policy_signature"
      : "principal_signature";
  }
  if (doc.schema === "sheaf.delegation-document/1") {
    return doc.issuer.type === "policy"
      ? "policy_signature"
      : "principal_signature";
  }
  return "recorder_observed";
}

function hashMatchesEvent(
  hash: string,
  expected: string | null,
): boolean {
  if (!expected) return false;
  try {
    return normalizeHash(expected) === hash;
  } catch {
    return false;
  }
}

async function buildEvidenceSection<T extends EvidenceDocument>(
  input: EvidenceInput<T>,
  disclosures: DisclosureSet,
  kind: "mandate" | "delegation" | "consent",
): Promise<DisputeEvidenceSection<T>> {
  if (input.status === "absent") {
    return {
      status: "absent",
      event_ref: null,
      document: null,
      document_hash: null,
      document_signature: null,
      authorization_basis: null,
    };
  }

  const disclosure = requireDisclosure(disclosures, input.event_ref);
  if ((disclosure.envelope.event.kind ?? "tool_call") !== kind) {
    throw new DisputeBuildError(
      "EVIDENCE_KIND_MISMATCH",
      `event ${refKey(input.event_ref)} is not kind ${kind}`,
    );
  }

  if (input.status === "hash_only") {
    let expected: string;
    try {
      expected = normalizeHash(input.document_hash);
    } catch {
      throw new DisputeBuildError(
        "EVIDENCE_DOC_HASH_MISMATCH",
        `hash_only ${kind} has an invalid document_hash`,
      );
    }
    if (!hashMatchesEvent(expected, disclosure.envelope.event.inputs_hash)) {
      throw new DisputeBuildError(
        "EVIDENCE_DOC_HASH_MISMATCH",
        `hash_only ${kind} document_hash does not match event.inputs_hash`,
      );
    }
    return {
      status: "hash_only",
      event_ref: input.event_ref,
      document: null,
      document_hash: expected,
      document_signature: null,
      authorization_basis: null,
    };
  }

  const errors = validateEvidenceDocument(input.document);
  if (errors.length > 0) {
    throw new DisputeBuildError("INVALID_EVIDENCE_DOCUMENT", errors.join("; "));
  }
  const hash = await evidenceDocumentHash(input.document);
  if (!hashMatchesEvent(hash, disclosure.envelope.event.inputs_hash)) {
    throw new DisputeBuildError(
      "EVIDENCE_DOC_HASH_MISMATCH",
      `${kind} document hash does not match event.inputs_hash`,
    );
  }

  return {
    status: "included",
    event_ref: input.event_ref,
    document: input.document,
    document_hash: hash,
    document_signature: input.document.document_signature ?? null,
    authorization_basis:
      input.authorization_basis ??
      defaultAuthorizationBasis(input.document, kind),
  };
}

async function buildPayloads(
  inputs: PayloadInput[],
  disclosures: DisclosureSet,
): Promise<DisputePayload[]> {
  return Promise.all(
    inputs.map(async (input, idx) => {
      const disclosure = requireDisclosure(disclosures, input.event_ref);
      const hash = await hashCanonical(input.content);
      const expected =
        input.kind === "tool_arguments"
          ? disclosure.envelope.event.inputs_hash
          : input.kind === "tool_result"
            ? disclosure.envelope.event.outputs_hash
            : (disclosure.envelope.event.outputs_hash ??
              disclosure.envelope.event.inputs_hash);
      if (!hashMatchesEvent(hash, expected)) {
        throw new DisputeBuildError(
          "PAYLOAD_HASH_MISMATCH",
          `payload ${idx} (${input.kind}) does not hash to the event's ${input.kind === "tool_result" ? "outputs_hash" : "inputs_hash"}`,
        );
      }
      const suffix =
        input.kind === "tool_arguments"
          ? "args"
          : input.kind === "tool_result"
            ? "result"
            : "other";
      return {
        id: input.id ?? `pl_${input.event_ref.seq}_${suffix}`,
        event_ref: input.event_ref,
        kind: input.kind,
        sha256: hash,
        media_type: input.media_type ?? "application/json",
        canonicalization: "RFC8785" as const,
        content: input.content,
        attachment_ref: null,
      };
    }),
  );
}

function deriveClaims(
  caseInput: DisputeCaseInput,
  disclosures: DisclosureSet,
  payloads: DisputePayload[],
): SubjectClaims {
  if (caseInput.subject.claims) return caseInput.subject.claims;

  const seq = caseInput.subject.disputed_event_seqs[0] ?? caseInput.subject.from_seq;
  const disclosure = requireDisclosure(disclosures, {
    chain_id: disclosures.chain_id,
    seq,
  });
  const args = payloads.find(
    (p) => p.event_ref.seq === seq && p.kind === "tool_arguments",
  );
  const argsRecord =
    args && args.content && typeof args.content === "object"
      ? (args.content as Record<string, unknown>)
      : null;

  const claims: SubjectClaims = {
    agent_id: {
      value: disclosure.envelope.event.actor,
      derived_from: "event.actor",
      ref: `seq:${seq}`,
    },
    tool: {
      value: disclosure.envelope.event.tool,
      derived_from: "event.tool",
      ref: `seq:${seq}`,
    },
  };

  const merchant = argsRecord?.merchant;
  if (typeof merchant === "string") {
    claims.merchant = {
      value: merchant,
      derived_from: "payload",
      ref: args!.id,
      path: "$.merchant",
    };
  } else {
    claims.merchant = {
      value: caseInput.merchant.url,
      derived_from: "case",
    };
  }

  const amount = argsRecord?.amount_minor;
  if (typeof amount === "number") {
    claims.amount_minor = {
      value: amount,
      derived_from: "payload",
      ref: args!.id,
      path: "$.amount_minor",
    };
  } else {
    claims.amount_minor = {
      value: caseInput.transaction.amount_minor,
      derived_from: "case",
    };
  }

  const currency = argsRecord?.currency;
  if (typeof currency === "string") {
    claims.currency = {
      value: currency,
      derived_from: "payload",
      ref: args!.id,
      path: "$.currency",
    };
  } else {
    claims.currency = {
      value: caseInput.transaction.currency,
      derived_from: "case",
    };
  }

  return claims;
}

/**
 * Assemble a sheaf.dispute-bundle/1 artifact.
 *
 * The caller supplies the already-built disclosure set, the local evidence
 * documents, the anchor block, and local payloads. This function performs no
 * network I/O and does not read files.
 */
export async function buildDisputeBundle(
  caseInput: DisputeCaseInput,
  disclosures: DisclosureSet,
  evidence: EvidenceInputs,
  anchor: DisclosureSet["anchor"],
  payloads: PayloadInput[],
  policy?: unknown,
): Promise<DisputeBundle> {
  if (!caseInput || !caseInput.subject) {
    throw new DisputeBuildError("INVALID_CASE", "case.subject is required");
  }
  if (
    !Number.isInteger(caseInput.subject.from_seq) ||
    !Number.isInteger(caseInput.subject.to_seq) ||
    caseInput.subject.from_seq < 0 ||
    caseInput.subject.to_seq < caseInput.subject.from_seq
  ) {
    throw new DisputeBuildError("INVALID_CASE", "invalid subject seq range");
  }
  if (
    !caseInput.dispute_basis ||
    typeof caseInput.dispute_basis.category !== "string" ||
    typeof caseInput.dispute_basis.asserted_by !== "string" ||
    typeof caseInput.dispute_basis.merchant_position !== "string"
  ) {
    throw new DisputeBuildError(
      "INVALID_CASE",
      "case.dispute_basis {category, asserted_by, merchant_position} is required",
    );
  }
  if (!Array.isArray(disclosures.disclosures)) {
    throw new DisputeBuildError("INVALID_DISCLOSURES", "disclosures are required");
  }

  const eventRefs: EventRef[] = [];
  for (let seq = caseInput.subject.from_seq; seq <= caseInput.subject.to_seq; seq++) {
    eventRefs.push({ chain_id: disclosures.chain_id, seq });
  }
  // Validate every execution event is disclosed and is a tool_call/control
  // event on this chain.
  for (const ref of eventRefs) requireDisclosure(disclosures, ref);

  const beforeRef =
    caseInput.subject.from_seq > 0
      ? { chain_id: disclosures.chain_id, seq: caseInput.subject.from_seq - 1 }
      : null;
  const afterRef = {
    chain_id: disclosures.chain_id,
    seq: caseInput.subject.to_seq + 1,
  };
  const beforeDisclosed = beforeRef ? findDisclosure(disclosures, beforeRef) : null;
  const afterDisclosed = findDisclosure(disclosures, afterRef);

  const includedBeforeRef = beforeDisclosed ? beforeRef : null;
  const includedAfterRef = afterDisclosed ? afterRef : null;

  const builtPayloads = await buildPayloads(payloads, disclosures);
  const claims = deriveClaims(caseInput, disclosures, builtPayloads);

  const mandate = await buildEvidenceSection(
    evidence.mandate,
    disclosures,
    "mandate",
  );

  let delegation: DisputeBundle["evidence"]["delegation"] = { status: "absent" };
  if (evidence.delegation.status === "included") {
    if (evidence.delegation.chain.length === 0) {
      throw new DisputeBuildError(
        "INVALID_DELEGATION",
        "included delegation must have at least one link",
      );
    }
    const chain = [];
    for (let i = 0; i < evidence.delegation.chain.length; i++) {
      const link = evidence.delegation.chain[i]!;
      const disclosure = requireDisclosure(disclosures, link.event_ref);
      if ((disclosure.envelope.event.kind ?? "tool_call") !== "delegation") {
        throw new DisputeBuildError(
          "EVIDENCE_KIND_MISMATCH",
          `event ${refKey(link.event_ref)} is not kind delegation`,
        );
      }
      const parsedAuthority = parseAuthorityRef(disclosure.envelope.event.authority);
      if (!sameRef(link.parent_event_ref, parsedAuthority)) {
        throw new DisputeBuildError(
          "DELEGATION_PARENT_MISMATCH",
          `delegation ${refKey(link.event_ref)} parent_event_ref does not equal event.authority`,
        );
      }
      const errors = validateEvidenceDocument(link.document);
      if (errors.length > 0) {
        throw new DisputeBuildError(
          "INVALID_EVIDENCE_DOCUMENT",
          errors.join("; "),
        );
      }
      const hash = await evidenceDocumentHash(link.document);
      if (!hashMatchesEvent(hash, disclosure.envelope.event.inputs_hash)) {
        throw new DisputeBuildError(
          "EVIDENCE_DOC_HASH_MISMATCH",
          `delegation ${refKey(link.event_ref)} document hash does not match inputs_hash`,
        );
      }
      chain.push({
        event_ref: link.event_ref,
        parent_event_ref: link.parent_event_ref,
        document: link.document,
        document_hash: hash,
        document_signature: link.document.document_signature ?? null,
        authorization_basis:
          link.authorization_basis ??
          defaultAuthorizationBasis(link.document, "delegation"),
      });
    }

    const first = chain[0]!;
    const root =
      evidence.delegation.root ?? {
        type: first.document.issuer.type,
        id: first.document.issuer.id,
        display_name: first.document.issuer.id,
        attestation: {
          basis:
            first.authorization_basis === "recorder_observed"
              ? ("recorder_observed" as const)
              : first.document.issuer.type === "policy"
                ? ("policy_signature" as const)
                : ("principal_signature" as const),
        },
      };

    delegation = { status: "included", root, chain };
  }

  const consent = (await buildEvidenceSection(
    evidence.consent,
    disclosures,
    "consent",
  )) as DisputeBundle["evidence"]["consent"];

  const consentStatus = evidence.consent.status;
  if (consentStatus === "included") {
    const doc = evidence.consent.document;
    consent.consent_type =
      evidence.consent.consent_type ?? "payer_authorization";
    consent.captured_at = evidence.consent.captured_at ?? doc.consented_at;
    consent.artifact = {
      sha256: consent.document_hash!,
      media_type: "application/json",
      content: doc,
      attachment_ref: null,
    };
  } else {
    consent.consent_type = null;
    consent.captured_at = null;
    consent.artifact = null;
  }

  const timeline: DisputeBundle["presentation"]["timeline"] = [];
  if (mandate.status === "included") {
    timeline.push({
      at: mandate.document.issued_at,
      label: "Mandate issued",
      event_ref: mandate.event_ref,
    });
  }
  if (delegation.status === "included") {
    for (const link of delegation.chain) {
      timeline.push({
        at: link.document.issued_at,
        label: "Authority delegated",
        event_ref: link.event_ref,
      });
    }
  }
  if (consent.status === "included") {
    timeline.push({
      at: consent.captured_at!,
      label: "Payer consent recorded",
      event_ref: consent.event_ref!,
    });
  }
  const disputedSeq =
    caseInput.subject.disputed_event_seqs[0] ?? caseInput.subject.from_seq;
  const disputedDisclosure = requireDisclosure(disclosures, {
    chain_id: disclosures.chain_id,
    seq: disputedSeq,
  });
  timeline.push({
    at: disputedDisclosure.envelope.event.ts,
    label: "Disputed transaction recorded",
    event_ref: disputedDisclosure.event_ref,
  });

  const caseOut: DisputeCase = {
    case_id: caseInput.case_id,
    card_network: caseInput.card_network,
    reason_code: caseInput.reason_code,
    transaction: caseInput.transaction,
    merchant: caseInput.merchant,
    response_due_at: caseInput.response_due_at,
    dispute_basis: caseInput.dispute_basis,
  };

  const policySection = policy
    ? {
        schema: "sheaf.policy/1" as const,
        hash: `sha256:${await hashCanonical(policy)}`,
        document: policy,
      }
    : undefined;

  const base = {
    schema: DISPUTE_BUNDLE_SCHEMA,
    created_at: caseInput.created_at ?? new Date().toISOString(),
    producer: {
      name: "sheaf",
      version: "0.5.0",
      command: "sheaf dispute export",
    },
    case: caseOut,
    subject: {
      chain_id: disclosures.chain_id,
      from_seq: caseInput.subject.from_seq,
      to_seq: caseInput.subject.to_seq,
      selection: "contiguous_range" as const,
      disputed_event_seqs: caseInput.subject.disputed_event_seqs,
      claims,
    },
    recorder: disclosures.recorder,
    disclosures: disclosures.disclosures,
    evidence: {
      mandate,
      delegation,
      execution: {
        window: {
          from_seq: caseInput.subject.from_seq,
          to_seq: caseInput.subject.to_seq,
          contiguous: true as const,
        },
        event_refs: eventRefs,
        before_ref: includedBeforeRef,
        after_ref: includedAfterRef,
      },
      consent,
    },
    anchor,
    payloads: builtPayloads,
    ...(policySection ? { policy: policySection } : {}),
    attachments: [] as [],
    presentation: {
      title: `Dispute evidence — ${caseInput.case_id}`,
      summary:
        `${caseInput.merchant.name} recorded an agent-initiated transaction ` +
        `(${caseInput.transaction.currency} ${(caseInput.transaction.amount_minor / 100).toFixed(2)}) ` +
        `with mandate, delegation, payer-consent, and execution evidence.`,
      timeline,
      limitations: [
        "Case-to-chain linkage is merchant-attested, not proven.",
        "Field-level redaction is not supported in v1.",
        "Offline mode proves integrity, not anchor presence.",
      ],
    },
  };

  const bundleId = `sha256:${await hashCanonical(base)}`;

  return {
    ...base,
    bundle_id: bundleId,
    verification: {
      lib: "@sheafhq/verify",
      min_version: "0.5.0",
      cmd: "npx -y @sheafhq/cli@0.1.0 dispute verify <bundle.sheaf> --rpc <base-rpc>",
      trust: {
        recorder_key_id: disclosures.recorder.key_id,
        anchorer_address: anchor.anchorer,
        base_network: anchor.network,
      },
    },
  };
}

export { authorityRef };
