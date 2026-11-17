// Merchant-facing authoring workflow:
//   sheaf dispute init-case <dir>
//   sheaf dispute validate --case <dir>/case.json [--archive events.jsonl]
//
// `case.json` is a local manifest targeting sheaf.dispute-bundle/1. It is not
// the final bundle; export turns it into one. Validation is intentionally
// strict and fails on placeholder values so a merchant knows exactly what is
// still missing before export.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { hashCanonical } from "./canonical.js";
import { normalizeHash } from "./disclose.js";
import {
  EVIDENCE_SCHEMAS,
  evidenceDocumentHash,
  validateEvidenceDocument,
  type EvidenceKind,
} from "./evidence.js";
import { parseArchiveJsonl, type Archive } from "./archive.js";

export const CASE_MANIFEST_VERSION = "sheaf.dispute-case/1";
export const TARGET_BUNDLE_SCHEMA = "sheaf.dispute-bundle/1";

export type InitCaseResult =
  | { ok: true; directory: string; files: string[] }
  | { ok: false; error: string };

export type ValidateCaseOptions = {
  archivePath?: string;
};

export type ValidateCaseResult = {
  ok: boolean;
  casePath: string;
  errors: string[];
  warnings: string[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

function checkPlaceholder(
  value: unknown,
  path: string,
  errors: string[],
): void {
  if (typeof value === "string" && /\[PLACEHOLDER/i.test(value)) {
    errors.push(`${path}: replace the placeholder value`);
  }
}

function requireString(
  value: unknown,
  path: string,
  errors: string[],
): boolean {
  if (!isNonEmptyString(value)) {
    errors.push(`${path}: non-empty string required`);
    return false;
  }
  checkPlaceholder(value, path, errors);
  return true;
}

function requireInt(
  value: unknown,
  path: string,
  errors: string[],
  min = 0,
): boolean {
  if (!Number.isInteger(value) || (value as number) < min) {
    errors.push(`${path}: integer >= ${min} required`);
    return false;
  }
  return true;
}

function requireDate(
  value: unknown,
  path: string,
  errors: string[],
): boolean {
  if (!isIsoDate(value)) {
    errors.push(`${path}: ISO 8601 UTC timestamp required`);
    return false;
  }
  checkPlaceholder(value, path, errors);
  return true;
}

function caseTemplate(caseId?: string): any {
  return {
    schema: TARGET_BUNDLE_SCHEMA,
    manifest_version: CASE_MANIFEST_VERSION,
    case: {
      case_id: caseId ?? "[PLACEHOLDER: merchant case id]",
      card_network: "[PLACEHOLDER: card network]",
      reason_code: {
        schema: "[PLACEHOLDER: card-network 2026 guide name]",
        value: "[PLACEHOLDER: reason code]",
        label: null,
      },
      transaction: {
        reference: "[PLACEHOLDER: processor transaction id]",
        amount_minor: -1,
        currency: "[PLACEHOLDER: ISO 4217]",
        occurred_at: "[PLACEHOLDER: ISO 8601 UTC]",
      },
      merchant: {
        id: "[PLACEHOLDER: merchant id]",
        name: "[PLACEHOLDER: merchant name]",
        url: "[PLACEHOLDER: merchant URL]",
      },
      response_due_at: "[PLACEHOLDER: ISO 8601 UTC]",
      dispute_basis: {
        category: "[PLACEHOLDER: friendly_fraud | unauthorized | ...]",
        asserted_by: "[PLACEHOLDER: merchant | payer | ...]",
        merchant_position: "[PLACEHOLDER: one-sentence merchant position]",
      },
    },
    subject: {
      from_seq: 0,
      to_seq: 0,
      disputed_event_seqs: [],
      claims: {},
    },
    evidence: {
      mandate: { status: "absent" },
      delegation: { status: "absent" },
      consent: { status: "absent" },
    },
    payloads: [],
  };
}

export function initCase(
  directory: string,
  opts: { force?: boolean; caseId?: string } = {},
): InitCaseResult {
  const target = resolve(directory);
  if (existsSync(target)) {
    if (!statSync(target).isDirectory()) {
      return { ok: false, error: `${target} exists and is not a directory` };
    }
    if (readdirSync(target).length > 0 && !opts.force) {
      return {
        ok: false,
        error: `directory ${target} already exists and is not empty (use --force to overwrite scaffold files)`,
      };
    }
  }

  mkdirSync(target, { recursive: true });
  mkdirSync(join(target, "documents"), { recursive: true });
  mkdirSync(join(target, "payloads"), { recursive: true });

  const casePath = join(target, "case.json");
  if (existsSync(casePath) && !opts.force) {
    return { ok: false, error: `${casePath} already exists` };
  }

  writeFileSync(casePath, JSON.stringify(caseTemplate(opts.caseId), null, 2) + "\n");
  writeFileSync(
    join(target, "MAPPING.md"),
    [
      "# Reason-code mapping",
      "",
      "Map the vendor's reason-code fields to bundle paths. Do not invent",
      "card-network field names; copy them from the applicable 2026 guide.",
      "",
      "| Card-network field | Bundle path | Notes |",
      "| --- | --- | --- |",
      "|  |  |  |",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(target, "documents", "README.md"),
    [
      "# Documents",
      "",
      "Place the mandate, delegation, and consent JSON documents here.",
      "",
      "- `sheaf.mandate-document/1`",
      "- `sheaf.delegation-document/1`",
      "- `sheaf.consent-document/1`",
      "",
      "Schemas: `schemas/` in the Sheaf repo.",
      "The CLI hashes each document with RFC 8785; do not hand-edit a hash.",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(target, "payloads", "README.md"),
    [
      "# Payloads",
      "",
      "Place the raw tool arguments and tool results for the disputed event here.",
      "Use JSON. The CLI canonicalizes with RFC 8785 and checks the hash against",
      "the event's inputs_hash/outputs_hash.",
      "",
      "Example:",
      "  sheaf dispute export ... \\",
      "    --payload 3:tool_arguments=payloads/3-args.json \\",
      "    --payload 3:tool_result=payloads/3-result.json",
      "",
    ].join("\n"),
  );

  return {
    ok: true,
    directory: target,
    files: [
      casePath,
      join(target, "documents"),
      join(target, "payloads"),
      join(target, "MAPPING.md"),
    ],
  };
}

function resolveFrom(baseFile: string, path: string): string {
  return isAbsolute(path) ? path : resolve(dirname(baseFile), path);
}

function readJson(path: string, errors: string[]): any | null {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    errors.push(`${path}: ${(err as Error).message}`);
    return null;
  }
}

function validateSignatureShape(
  signature: any,
  path: string,
  errors: string[],
): void {
  if (!isRecord(signature)) {
    errors.push(`${path}: object required`);
    return;
  }
  if (signature.alg !== "Ed25519") errors.push(`${path}.alg: "Ed25519" required`);
  requireString(signature.key_id, `${path}.key_id`, errors);
  requireString(signature.public_key_base64, `${path}.public_key_base64`, errors);
  requireString(signature.signature_base64, `${path}.signature_base64`, errors);
  if (typeof signature.public_key_base64 === "string") {
    const bytes = Buffer.from(signature.public_key_base64, "base64");
    if (bytes.length !== 32) {
      errors.push(`${path}.public_key_base64: decoded key must be 32 bytes`);
    }
  }
  if (typeof signature.signature_base64 === "string") {
    const bytes = Buffer.from(signature.signature_base64, "base64");
    if (bytes.length !== 64) {
      errors.push(`${path}.signature_base64: decoded signature must be 64 bytes`);
    }
  }
}

type ArchiveContext = {
  archive: Archive;
  events: Map<number, any>;
  leaves: Map<number, string>;
};

function loadArchiveContext(
  archivePath: string | undefined,
  errors: string[],
): ArchiveContext | null {
  if (!archivePath) return null;
  try {
    const archive = parseArchiveJsonl(readFileSync(archivePath, "utf8"));
    const events = new Map<number, any>();
    const leaves = new Map<number, string>();
    for (const row of archive.events) {
      const envelope = JSON.parse(row.envelope_json);
      events.set(row.seq, envelope);
      if (row.envelope_hash) leaves.set(row.seq, row.envelope_hash);
    }
    return { archive, events, leaves };
  } catch (err) {
    errors.push(`${archivePath}: ${(err as Error).message}`);
    return null;
  }
}

export async function validateCase(
  casePath: string,
  opts: ValidateCaseOptions = {},
): Promise<ValidateCaseResult> {
  const path = resolve(casePath);
  const errors: string[] = [];
  const warnings: string[] = [];
  const manifest = readJson(path, errors);
  if (!manifest) {
    return { ok: false, casePath: path, errors, warnings };
  }
  const baseDir = dirname(path);

  if (manifest.schema !== TARGET_BUNDLE_SCHEMA) {
    errors.push(`schema: expected ${TARGET_BUNDLE_SCHEMA}`);
  }
  if (
    manifest.manifest_version !== undefined &&
    manifest.manifest_version !== CASE_MANIFEST_VERSION
  ) {
    errors.push(`manifest_version: expected ${CASE_MANIFEST_VERSION}`);
  }

  const context = loadArchiveContext(opts.archivePath, errors);

  // Directory structure
  if (!existsSync(join(baseDir, "documents"))) {
    errors.push(`documents/: directory required next to ${path}`);
  }
  if (!existsSync(join(baseDir, "payloads"))) {
    errors.push(`payloads/: directory required next to ${path}`);
  }
  if (!existsSync(join(baseDir, "MAPPING.md"))) {
    errors.push(`MAPPING.md: file required next to ${path}`);
  }

  // Case block
  const c = manifest.case;
  if (!isRecord(c)) {
    errors.push("case: object required");
  } else {
    requireString(c.case_id, "case.case_id", errors);
    requireString(c.card_network, "case.card_network", errors);
    if (!isRecord(c.reason_code)) {
      errors.push("case.reason_code: object required");
    } else {
      requireString(c.reason_code.schema, "case.reason_code.schema", errors);
      requireString(c.reason_code.value, "case.reason_code.value", errors);
    }
    if (!isRecord(c.transaction)) {
      errors.push("case.transaction: object required");
    } else {
      requireString(c.transaction.reference, "case.transaction.reference", errors);
      if (!requireInt(c.transaction.amount_minor, "case.transaction.amount_minor", errors)) {
        // already reported
      }
      if (
        typeof c.transaction.currency !== "string" ||
        !/^[A-Z]{3}$/.test(c.transaction.currency)
      ) {
        errors.push("case.transaction.currency: ISO 4217 uppercase code required");
      } else {
        checkPlaceholder(c.transaction.currency, "case.transaction.currency", errors);
      }
      requireDate(c.transaction.occurred_at, "case.transaction.occurred_at", errors);
    }
    if (!isRecord(c.merchant)) {
      errors.push("case.merchant: object required");
    } else {
      requireString(c.merchant.id, "case.merchant.id", errors);
      requireString(c.merchant.name, "case.merchant.name", errors);
      requireString(c.merchant.url, "case.merchant.url", errors);
    }
    requireDate(c.response_due_at, "case.response_due_at", errors);
    if (!isRecord(c.dispute_basis)) {
      errors.push("case.dispute_basis: object required");
    } else {
      requireString(c.dispute_basis.category, "case.dispute_basis.category", errors);
      requireString(c.dispute_basis.asserted_by, "case.dispute_basis.asserted_by", errors);
      requireString(
        c.dispute_basis.merchant_position,
        "case.dispute_basis.merchant_position",
        errors,
      );
    }
  }

  // Subject block
  const s = manifest.subject;
  if (!isRecord(s)) {
    errors.push("subject: object required");
  } else {
    const fromOk = requireInt(s.from_seq, "subject.from_seq", errors);
    const toOk = requireInt(s.to_seq, "subject.to_seq", errors);
    if (fromOk && toOk && (s.from_seq as number) > (s.to_seq as number)) {
      errors.push("subject.from_seq: must be <= subject.to_seq");
    }
    if (!Array.isArray(s.disputed_event_seqs) || s.disputed_event_seqs.length === 0) {
      errors.push("subject.disputed_event_seqs: at least one seq required");
    } else {
      s.disputed_event_seqs.forEach((seq: unknown, idx: number) => {
        if (!Number.isInteger(seq)) {
          errors.push(`subject.disputed_event_seqs[${idx}]: integer required`);
        } else if (
          fromOk &&
          toOk &&
          ((seq as number) < (s.from_seq as number) ||
            (seq as number) > (s.to_seq as number))
        ) {
          errors.push(
            `subject.disputed_event_seqs[${idx}]: must be within the subject range`,
          );
        }
      });
    }
    if (s.claims !== undefined) {
      if (!isRecord(s.claims)) {
        errors.push("subject.claims: object required when present");
      } else {
        for (const [key, claim] of Object.entries(s.claims)) {
          if (!isRecord(claim)) {
            errors.push(`subject.claims.${key}: object required`);
            continue;
          }
          if (
            typeof claim.value !== "string" &&
            typeof claim.value !== "number"
          ) {
            errors.push(`subject.claims.${key}.value: string or number required`);
          } else if (typeof claim.value === "string") {
            checkPlaceholder(claim.value, `subject.claims.${key}.value`, errors);
          }
          if (
            ![
              "event.actor",
              "event.tool",
              "event.ts",
              "payload",
              "case",
            ].includes(String(claim.derived_from))
          ) {
            errors.push(`subject.claims.${key}.derived_from: unsupported source`);
          }
        }
      }
    }
  }

  // Evidence block
  const e = manifest.evidence;
  if (!isRecord(e)) {
    errors.push("evidence: object required");
  } else {
    await validateEvidenceItemAsync(
      "mandate",
      e.mandate,
      "evidence.mandate",
      path,
      context,
      errors,
      warnings,
    );
    const delegation = e.delegation;
    if (!isRecord(delegation)) {
      errors.push("evidence.delegation: object required");
    } else if (delegation.status === "absent") {
      warnings.push("evidence.delegation: absent; the bundle will be partial");
    } else if (delegation.status === "included") {
      if (!Array.isArray(delegation.chain) || delegation.chain.length === 0) {
        errors.push("evidence.delegation.chain: at least one link required");
      } else {
        for (let i = 0; i < delegation.chain.length; i++) {
          const link = delegation.chain[i];
          await validateEvidenceItemAsync(
            "delegation",
            { ...link, status: "included" },
            `evidence.delegation.chain[${i}]`,
            path,
            context,
            errors,
            warnings,
          );
        }
      }
      if (delegation.root !== undefined) {
        if (!isRecord(delegation.root)) {
          errors.push("evidence.delegation.root: object required");
        } else {
          requireString(delegation.root.type, "evidence.delegation.root.type", errors);
          requireString(delegation.root.id, "evidence.delegation.root.id", errors);
          requireString(
            delegation.root.display_name,
            "evidence.delegation.root.display_name",
            errors,
          );
        }
      } else {
        warnings.push("evidence.delegation.root: omitted; builder will derive a root");
      }
    } else {
      errors.push("evidence.delegation.status: \"included\" or \"absent\" required");
    }

    await validateEvidenceItemAsync(
      "consent",
      e.consent,
      "evidence.consent",
      path,
      context,
      errors,
      warnings,
    );
  }

  // Payloads
  const payloads = manifest.payloads;
  if (payloads !== undefined) {
    if (!Array.isArray(payloads)) {
      errors.push("payloads: array required");
    } else {
      for (let i = 0; i < payloads.length; i++) {
        const item = payloads[i];
        if (!isRecord(item)) {
          errors.push(`payloads[${i}]: object required`);
          continue;
        }
        if (!requireInt(item.seq, `payloads[${i}].seq`, errors)) continue;
        if (!["tool_arguments", "tool_result", "other"].includes(String(item.kind))) {
          errors.push(`payloads[${i}].kind: tool_arguments | tool_result | other required`);
        }
        if (!requireString(item.path, `payloads[${i}].path`, errors)) continue;
        const payloadPath = resolveFrom(path, item.path as string);
        if (!existsSync(payloadPath)) {
          errors.push(`payloads[${i}].path: file not found at ${payloadPath}`);
          continue;
        }
        const content = readJson(payloadPath, errors);
        if (content === null) continue;
        if (context) {
          const event = context.events.get(item.seq as number);
          if (!event) {
            errors.push(`payloads[${i}].seq: event ${item.seq} not found in archive`);
          } else {
            const digest = await hashCanonical(content);
            const expected =
              item.kind === "tool_arguments"
                ? event.event?.inputs_hash
                : item.kind === "tool_result"
                  ? event.event?.outputs_hash
                  : (event.event?.outputs_hash ?? event.event?.inputs_hash);
            if (normalizeHash(expected) !== digest) {
              errors.push(
                `payloads[${i}]: PAYLOAD_HASH_MISMATCH (${digest} != event hash ${normalizeHash(expected) ?? "invalid"})`,
              );
            }
          }
        }
      }
    }
  }

  if (context && isRecord(s) && Array.isArray(s.disputed_event_seqs)) {
    for (const seq of s.disputed_event_seqs) {
      const hasArgs = Array.isArray(payloads)
        ? payloads.some(
            (p: any) =>
              isRecord(p) &&
              p.seq === seq &&
              p.kind === "tool_arguments" &&
              typeof p.path === "string",
          )
        : false;
      if (!hasArgs) {
        errors.push(
          `payloads: no tool_arguments payload for disputed seq ${seq}`,
        );
      }
    }
  }

  return { ok: errors.length === 0, casePath: path, errors, warnings };
}

async function validateEvidenceItemAsync(
  kind: EvidenceKind,
  item: any,
  path: string,
  baseFile: string,
  context: ArchiveContext | null,
  errors: string[],
  warnings: string[],
): Promise<void> {
  if (!isRecord(item)) {
    errors.push(`${path}: object required`);
    return;
  }
  if (item.status === "absent") {
    warnings.push(`${path}: absent; the bundle will be partial`);
    return;
  }
  if (item.status !== "included") {
    errors.push(`${path}.status: "included" or "absent" required`);
    return;
  }
  if (!requireInt(item.seq, `${path}.seq`, errors)) return;
  if (!requireString(item.document, `${path}.document`, errors)) return;
  const docPath = resolveFrom(baseFile, item.document as string);
  if (!existsSync(docPath)) {
    errors.push(`${path}.document: file not found at ${docPath}`);
    return;
  }
  const doc = readJson(docPath, errors);
  if (!doc) return;
  const docErrors = validateEvidenceDocument(doc);
  for (const error of docErrors) errors.push(`${path}.document: ${error}`);
  if (doc.schema !== EVIDENCE_SCHEMAS[kind]) {
    errors.push(
      `${path}.document.schema: expected ${EVIDENCE_SCHEMAS[kind]}, got ${String(doc.schema)}`,
    );
  }
  if (doc.document_signature) {
    validateSignatureShape(
      doc.document_signature,
      `${path}.document.document_signature`,
      errors,
    );
  }

  if (context) {
    const event = context.events.get(item.seq as number);
    if (!event) {
      errors.push(`${path}.seq: event ${item.seq} not found in archive`);
    } else {
      const expected = normalizeHash(event.event?.inputs_hash);
      const actual = await evidenceDocumentHash(doc);
      if (actual !== expected) {
        errors.push(
          `${path}.document: EVIDENCE_DOC_HASH_MISMATCH (document hash ${actual} != event inputs_hash ${expected ?? "invalid"})`,
        );
      }
    }
  }
}
