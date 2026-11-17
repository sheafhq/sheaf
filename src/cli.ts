#!/usr/bin/env node
// Umbrella CLI for the Dispute Bundle.
//
//   sheaf dispute export --archive events.jsonl --case case.json --out bundle.sheaf
//   sheaf dispute verify bundle.sheaf --rpc https://mainnet.base.org
//   sheaf dispute verify bundle.sheaf --offline
//
// The export path is local-first: with --archive it never contacts Sheaf.

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  defaultTrustStore,
  formatDisputeVerification,
  validatePolicy,
  verifyDisputeBundle,
  type TrustStore,
  type VerifyDisputeOptions,
} from "../packages/verify/dist/index.js";
import { parseArchiveJsonl } from "./archive.js";
import { initCase, validateCase } from "./authoring.js";
import { discloseRange, type DisclosureSet } from "./disclose.js";
import {
  prepareLocalExport,
  syncLocalAnchor,
} from "./local.js";
import {
  buildDisputeBundle,
  parseAuthorityRef,
  type DisputeCase,
  type DisputeCaseInput,
  type EvidenceInputs,
  type PayloadInput,
  type RootAuthority,
} from "./dispute.js";

const DEFAULT_RPC = "https://mainnet.base.org";

type Flags = {
  archive?: string;
  casePath?: string;
  out?: string;
  chainDir?: string;
  localMode: boolean;
  anchorMode?: "base" | "local";
  endpoint?: string;
  rpc?: string;
  trustPath?: string;
  policyPath?: string;
  offline: boolean;
  strict: boolean;
  selfCheck: boolean;
  allowUnconfirmedAnchor: boolean;
  force: boolean;
  payloads: string[];
  help: boolean;
  positionals: string[];
};

function parseFlags(argv: string[]): Flags {
  const flags: Flags = {
    localMode: false,
    offline: false,
    strict: false,
    selfCheck: false,
    allowUnconfirmedAnchor: false,
    force: false,
    payloads: [],
    help: false,
    positionals: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--archive") flags.archive = argv[++i] ?? "";
    else if (arg === "--case") flags.casePath = argv[++i] ?? "";
    else if (arg === "--out") flags.out = argv[++i] ?? "";
    else if (arg === "--chain-dir") flags.chainDir = argv[++i] ?? "";
    else if (arg === "--endpoint") flags.endpoint = argv[++i] ?? "";
    else if (arg === "--rpc") flags.rpc = argv[++i] ?? "";
    else if (arg === "--trust") flags.trustPath = argv[++i] ?? "";
    else if (arg === "--policy") flags.policyPath = argv[++i] ?? "";
    else if (arg === "--offline") flags.offline = true;
    else if (arg === "--strict") flags.strict = true;
    else if (arg === "--self-check") flags.selfCheck = true;
    else if (arg === "--allow-unconfirmed-anchor")
      flags.allowUnconfirmedAnchor = true;
    else if (arg === "--force") flags.force = true;
    else if (arg === "--payload") flags.payloads.push(argv[++i] ?? "");
    else if (arg === "--help" || arg === "-h") flags.help = true;
    else if (arg.startsWith("--")) throw new Error(`unknown flag ${arg}`);
    else flags.positionals.push(arg);
  }
  return flags;
}

function help(): string {
  return [
    "usage:",
    "  sheaf dispute init-case <directory> [--force]",
    "  sheaf dispute validate --case <case.json> [--archive <events.jsonl>]",
    "  sheaf dispute export --archive <events.jsonl> --case <case.json> --out <bundle.sheaf> [options]",
    "  sheaf dispute verify <bundle.sheaf> [options]",
    "  sheaf local export --chain-dir <dir> --case <case.json> --out <bundle.sheaf>",
    "  sheaf local sync --chain-dir <dir>",
    "",
    "init-case options:",
    "  --force            overwrite scaffold files in a non-empty directory",
    "",
    "validate options:",
    "  --case <path>      local case manifest (required)",
    "  --archive <path>   optional archive for document/payload hash checks",
    "",
    "export options:",
    "  --archive <path>   local JSONL archive (required; no Sheaf network)",
    "  --case <path>      local case manifest (required)",
    "  --out <path>       output .sheaf path (required)",
    "  --payload <seq>:<kind>=<path>  add/override a payload (kind: tool_arguments|tool_result)",
    "  --policy <path>    attach and verify a sheaf.policy/1 document",
    "  --self-check       run verifyDisputeBundle before writing",
    "  --strict           fail on placeholders, incomplete evidence, or invalid bundle",
    "  --offline          self-check without a Base RPC",
    "  --rpc <url>        Base RPC for the self-check",
    "  --trust <path>     testing only: pinned {recorder_keys, anchorers}",
    "",
    "verify options:",
    "  --rpc <url>                    Base RPC (default https://mainnet.base.org)",
    "  --offline                      integrity-only; no network calls",
    "  --allow-unconfirmed-anchor     exit 0 when offline integrity is valid",
    "  --strict                       fail on placeholders or incomplete evidence",
    "  --trust <path>                 testing only: pinned {recorder_keys, anchorers}",
    "",
    "local options:",
    "  --chain-dir <dir>  local .sheaf directory (default ./.sheaf)",
    "  --case <path>      case manifest for local export",
    "  --out <path>       output .sheaf path for local export",
    "  --endpoint <url>   anchor endpoint for local sync",
    "",
    "Trust material is versioned with @sheafhq/verify. Rotating a recorder key",
    "requires a verifier release; --trust is for tests, not production.",
  ].join("\n");
}

function fail(message: string): never {
  throw new Error(message);
}

function readJson(path: string): any {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    fail(`could not read JSON ${path}: ${(err as Error).message}`);
  }
}

function readText(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    fail(`could not read ${path}: ${(err as Error).message}`);
  }
}

function loadTrust(path: string | undefined): TrustStore {
  if (!path) return defaultTrustStore();
  const parsed = readJson(path) as Partial<TrustStore>;
  if (!Array.isArray(parsed.recorder_keys) || !Array.isArray(parsed.anchorers)) {
    fail("--trust file must contain recorder_keys[] and anchorers[]");
  }
  return parsed as TrustStore;
}

function resolveFrom(baseFile: string, path: string): string {
  return isAbsolute(path) ? path : resolve(dirname(baseFile), path);
}

function mergeDisclosures(
  execution: DisclosureSet,
  extra: DisclosureSet,
): DisclosureSet {
  const bySeq = new Map<number, DisclosureSet["disclosures"][number]>();
  for (const d of [...execution.disclosures, ...extra.disclosures]) {
    bySeq.set(d.envelope.chain.seq, d);
  }
  const epochById = new Map<number, DisclosureSet["anchor"]["epochs"][number]>();
  for (const e of [...execution.anchor.epochs, ...extra.anchor.epochs]) {
    epochById.set(e.epoch_id, e);
  }
  return {
    ...execution,
    disclosures: [...bySeq.values()].sort(
      (a, b) => a.envelope.chain.seq - b.envelope.chain.seq,
    ),
    anchor: {
      ...execution.anchor,
      epochs: [...epochById.values()].sort((a, b) => a.epoch_id - b.epoch_id),
    },
    warnings: [...new Set([...execution.warnings, ...extra.warnings])],
  };
}

async function buildDisclosureSet(
  archive: ReturnType<typeof parseArchiveJsonl>,
  manifest: any,
  evidenceSeqs: number[],
): Promise<DisclosureSet> {
  const subject = manifest.subject;
  if (!subject) fail("case manifest: subject is required");
  const fromSeq = subject.from_seq;
  const toSeq = subject.to_seq;
  if (!Number.isInteger(fromSeq) || !Number.isInteger(toSeq)) {
    fail("case manifest: subject.from_seq/to_seq must be integers");
  }

  const baseOpts = {
    recorder: archive.meta.recorder,
    anchorer: archive.meta.anchorer,
    network: archive.meta.network,
  };

  const execution = await discloseRange(
    archive.source,
    archive.meta.chain_id,
    fromSeq,
    toSeq,
    baseOpts,
  );
  if (!execution.ok) fail(`${execution.status} ${execution.code}: ${execution.error}`);

  let merged = execution.disclosure;
  for (const seq of [...new Set(evidenceSeqs)]) {
    if (seq >= fromSeq && seq <= toSeq) continue;
    if (merged.disclosures.some((d) => d.envelope.chain.seq === seq)) continue;
    const one = await discloseRange(
      archive.source,
      archive.meta.chain_id,
      seq,
      seq,
      { ...baseOpts, includeBoundaries: false },
    );
    if (!one.ok) fail(`${one.status} ${one.code}: ${one.error}`);
    merged = mergeDisclosures(merged, one.disclosure);
  }
  return merged;
}

async function buildEvidenceInputs(
  manifest: any,
  archive: ReturnType<typeof parseArchiveJsonl>,
  casePath: string,
): Promise<{ evidence: EvidenceInputs; evidenceSeqs: number[] }> {
  const chainId = archive.meta.chain_id;
  const ref = (seq: number) => ({ chain_id: chainId, seq });
  const evidenceSeqs: number[] = [];

  let mandate: EvidenceInputs["mandate"];
  if (!manifest.evidence?.mandate || manifest.evidence.mandate.status === "absent") {
    mandate = { status: "absent" };
  } else {
    const item = manifest.evidence.mandate;
    evidenceSeqs.push(item.seq);
    mandate = {
      status: "included",
      event_ref: ref(item.seq),
      document: readJson(resolveFrom(casePath, item.document)),
      ...(item.authorization_basis
        ? { authorization_basis: item.authorization_basis }
        : {}),
    };
  }

  let delegation: EvidenceInputs["delegation"];
  if (
    !manifest.evidence?.delegation ||
    manifest.evidence.delegation.status === "absent"
  ) {
    delegation = { status: "absent" };
  } else {
    const item = manifest.evidence.delegation;
    const chain = (item.chain ?? []).map((link: any) => {
      evidenceSeqs.push(link.seq);
      const event = archive.events.find((e) => e.seq === link.seq);
      if (!event) fail(`case manifest: delegation seq ${link.seq} missing from archive`);
      let parentEventRef: { chain_id: string; seq: number } | null = null;
      if (typeof link.parent_seq === "number") {
        parentEventRef = { chain_id: chainId, seq: link.parent_seq };
      } else if (event) {
        const envelope = JSON.parse(event.envelope_json);
        parentEventRef = parseAuthorityRef(envelope.event.authority);
      }
      return {
        event_ref: ref(link.seq),
        parent_event_ref: parentEventRef,
        document: readJson(resolveFrom(casePath, link.document)),
        ...(link.authorization_basis
          ? { authorization_basis: link.authorization_basis }
          : {}),
      };
    });
    delegation = {
      status: "included",
      ...(item.root ? { root: item.root as RootAuthority } : {}),
      chain,
    };
  }

  let consent: EvidenceInputs["consent"];
  if (!manifest.evidence?.consent || manifest.evidence.consent.status === "absent") {
    consent = { status: "absent" };
  } else {
    const item = manifest.evidence.consent;
    evidenceSeqs.push(item.seq);
    consent = {
      status: "included",
      event_ref: ref(item.seq),
      document: readJson(resolveFrom(casePath, item.document)),
      ...(item.consent_type ? { consent_type: item.consent_type } : {}),
      ...(item.captured_at ? { captured_at: item.captured_at } : {}),
      ...(item.authorization_basis
        ? { authorization_basis: item.authorization_basis }
        : {}),
    };
  }

  return { evidence: { mandate, delegation, consent }, evidenceSeqs };
}

function parsePayloadFlag(value: string): {
  seq: number;
  kind: PayloadInput["kind"];
  path: string;
} {
  const eq = value.indexOf("=");
  if (eq === -1) fail(`--payload must be <seq>:<kind>=<path>, got ${value}`);
  const left = value.slice(0, eq);
  const path = value.slice(eq + 1);
  const colon = left.indexOf(":");
  if (colon === -1) fail(`--payload must be <seq>:<kind>=<path>, got ${value}`);
  const seq = Number(left.slice(0, colon));
  const kindRaw = left.slice(colon + 1);
  if (!Number.isInteger(seq) || seq < 0) {
    fail(`--payload seq must be a non-negative integer, got ${left.slice(0, colon)}`);
  }
  const kind =
    kindRaw === "args" || kindRaw === "tool_arguments"
      ? "tool_arguments"
      : kindRaw === "result" || kindRaw === "tool_result"
        ? "tool_result"
        : kindRaw === "other"
          ? "other"
          : null;
  if (!kind) {
    fail(`--payload kind must be tool_arguments|tool_result|args|result, got ${kindRaw}`);
  }
  if (!path) fail(`--payload path is required`);
  return { seq, kind, path };
}

function buildPayloadInputs(
  manifest: any,
  archive: ReturnType<typeof parseArchiveJsonl>,
  casePath: string,
  payloadFlags: string[],
): PayloadInput[] {
  const chainId = archive.meta.chain_id;
  const items: any[] = Array.isArray(manifest.payloads)
    ? [...manifest.payloads]
    : [];
  for (const flag of payloadFlags) {
    const parsed = parsePayloadFlag(flag);
    items.push({
      seq: parsed.seq,
      kind: parsed.kind,
      path: parsed.path,
      flagPath: true,
    });
  }

  const byKey = new Map<string, any>();
  for (const item of items) {
    if (typeof item.seq !== "number" || !Number.isInteger(item.seq) || item.seq < 0) {
      fail("case manifest: payload.seq must be a non-negative integer");
    }
    if (!["tool_arguments", "tool_result", "other"].includes(item.kind)) {
      fail(`case manifest: unsupported payload kind ${String(item.kind)}`);
    }
    if (typeof item.path !== "string" || !item.path) {
      fail("case manifest: payload.path is required");
    }
    byKey.set(`${item.seq}:${item.kind}`, item);
  }

  return [...byKey.values()].map((item: any) => ({
    ...(item.id ? { id: item.id } : {}),
    event_ref: { chain_id: chainId, seq: item.seq },
    kind: item.kind,
    content: readJson(
      item.flagPath ? resolve(item.path) : resolveFrom(casePath, item.path),
    ),
    media_type: item.media_type ?? "application/json",
  }));
}

function findPlaceholders(value: unknown, path = "bundle"): string[] {
  if (typeof value === "string") {
    return /\[PLACEHOLDER/i.test(value) ? [path] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((v, i) => findPlaceholders(v, `${path}[${i}]`));
  }
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) =>
      k === "verification" ? [] : findPlaceholders(v, `${path}.${k}`),
    );
  }
  return [];
}

async function exportBundle(flags: Flags): Promise<number> {
  if (!flags.archive || !flags.casePath || !flags.out) {
    fail("export requires --archive, --case, and --out");
  }
  const archive = parseArchiveJsonl(readText(flags.archive));
  const manifest = readJson(flags.casePath);
  if (!manifest.case) fail("case manifest: case is required");
  if (!manifest.subject) fail("case manifest: subject is required");

  const { evidence, evidenceSeqs } = await buildEvidenceInputs(
    manifest,
    archive,
    flags.casePath,
  );
  const disclosureSet = await buildDisclosureSet(
    archive,
    manifest,
    evidenceSeqs,
  );
  if (flags.localMode) {
    if (flags.anchorMode === "base") {
      delete (disclosureSet.anchor as { mode?: "base" | "local" }).mode;
    } else {
      disclosureSet.anchor.mode = "local";
    }
  }
  const payloads = buildPayloadInputs(
    manifest,
    archive,
    flags.casePath,
    flags.payloads,
  );

  const caseInput: DisputeCaseInput = {
    ...(manifest.case as DisputeCase),
    subject: manifest.subject,
    ...(manifest.case.created_at
      ? { created_at: manifest.case.created_at }
      : {}),
  };

  let policy: unknown | undefined;
  if (flags.policyPath) {
    policy = readJson(flags.policyPath);
    const errors = validatePolicy(policy);
    if (errors.length > 0) {
      fail(`invalid policy ${flags.policyPath}: ${errors.join("; ")}`);
    }
  }

  const bundle = await buildDisputeBundle(
    caseInput,
    disclosureSet,
    evidence,
    disclosureSet.anchor,
    payloads,
    policy,
  );

  const placeholders = findPlaceholders(bundle);
  if (flags.strict && placeholders.length > 0) {
    fail(`strict: placeholders remain: ${placeholders.join(", ")}`);
  }

  if (flags.selfCheck || flags.strict) {
    const result = await verifyDisputeBundle(bundle, {
      trust: loadTrust(flags.trustPath),
      ...(flags.offline
        ? {}
        : { base_rpc: flags.rpc ?? DEFAULT_RPC }),
    });
    if (!result.valid) {
      process.stderr.write(formatDisputeVerification(result));
      fail("self-check failed; refusing to write bundle");
    }
    if (flags.strict && !result.complete) {
      process.stderr.write(formatDisputeVerification(result));
      fail("strict: completeness is not complete; refusing to write bundle");
    }
  }

  const tmp = `${flags.out}.tmp`;
  writeFileSync(tmp, JSON.stringify(bundle, null, 2) + "\n");
  renameSync(tmp, flags.out);
  process.stdout.write(`WROTE ${flags.out}\n`);
  return 0;
}

async function verifyBundle(flags: Flags): Promise<number> {
  if (flags.positionals.length !== 1) {
    fail("verify requires exactly one bundle path");
  }
  const bundle = readJson(flags.positionals[0]!);
  const placeholders = findPlaceholders(bundle);
  if (flags.strict && placeholders.length > 0) {
    fail(`strict: placeholders remain: ${placeholders.join(", ")}`);
  }

  const opts: VerifyDisputeOptions = {
    trust: loadTrust(flags.trustPath),
    ...(flags.offline
      ? {}
      : { base_rpc: flags.rpc ?? DEFAULT_RPC }),
  };
  const result = await verifyDisputeBundle(bundle, opts);
  process.stdout.write(formatDisputeVerification(result));
  if (!result.valid) return 1;
  if (flags.strict && !result.complete) return 1;
  if (flags.offline && !result.anchor_confirmed && !flags.allowUnconfirmedAnchor) {
    return 3;
  }
  return 0;
}

async function initCaseCommand(flags: Flags): Promise<number> {
  if (flags.positionals.length !== 1) {
    fail("init-case requires exactly one directory");
  }
  const result = initCase(flags.positionals[0]!, { force: flags.force });
  if (!result.ok) fail(result.error);
  process.stdout.write(`INITIALIZED ${result.directory}\n`);
  for (const file of result.files) {
    process.stdout.write(`- ${file}\n`);
  }
  process.stdout.write(
    `next: fill case.json and documents/, then run:\n` +
      `  sheaf dispute validate --case ${result.files[0]}\n`,
  );
  return 0;
}

async function validateCommand(flags: Flags): Promise<number> {
  if (!flags.casePath) fail("validate requires --case <case.json>");
  const result = await validateCase(flags.casePath, {
    ...(flags.archive ? { archivePath: flags.archive } : {}),
  });
  if (result.ok) {
    process.stdout.write(`VALID ${result.casePath}\n`);
    for (const warning of result.warnings) {
      process.stdout.write(`warning: ${warning}\n`);
    }
    return 0;
  }
  process.stdout.write(`INVALID ${result.casePath}\n`);
  for (const error of result.errors) {
    process.stdout.write(`- ${error}\n`);
  }
  for (const warning of result.warnings) {
    process.stdout.write(`warning: ${warning}\n`);
  }
  return 1;
}

async function localExport(flags: Flags): Promise<number> {
  if (!flags.casePath || !flags.out) {
    fail("local export requires --case <case.json> and --out <bundle.sheaf>");
  }
  const chainDir = resolve(flags.chainDir ?? "./.sheaf");
  const prepared = await prepareLocalExport(chainDir, flags.casePath);
  const localFlags: Flags = {
    ...flags,
    archive: prepared.archivePath,
    casePath: prepared.casePath,
    out: flags.out,
    ...(prepared.policyPath ? { policyPath: prepared.policyPath } : {}),
    trustPath: prepared.trustPath,
    localMode: true,
    anchorMode: prepared.anchorMode,
    offline: true,
    selfCheck: true,
    strict: false,
    allowUnconfirmedAnchor: true,
  };
  const code = await exportBundle(localFlags);
  if (code === 0) {
    process.stdout.write(
      `LOCAL_CHAIN ${prepared.chainId}\n` +
        `LOCAL_EVENTS ${prepared.eventCount}\n` +
        `LOCAL_MERKLE_ROOT ${prepared.root}\n` +
        `LOCAL_ANCHOR_MODE ${prepared.anchorMode}\n` +
        (prepared.anchorMode === "base"
          ? `LOCAL_ANCHOR ${prepared.txHash}\n`
          : `LOCAL_ANCHOR local:${prepared.root}\n`),
    );
  }
  return code;
}

async function localSync(flags: Flags): Promise<number> {
  const chainDir = resolve(flags.chainDir ?? "./.sheaf");
  const endpoint =
    flags.endpoint ??
    process.env.SHEAF_ANCHOR_URL ??
    "https://api.sheafhq.io/v1/anchor/local";
  try {
    const synced = await syncLocalAnchor(chainDir, endpoint);
    process.stdout.write(
      `ANCHORED ${synced.state.tx_hash}\n` +
        `chain_id: ${synced.state.chain_id}\n` +
        `event_count: ${synced.state.event_count}\n` +
        `merkle_root: ${synced.state.merkle_root}\n` +
        `epoch_id: ${synced.state.epoch_id}\n` +
        `block_number: ${synced.state.block_number ?? "pending"}\n` +
        `anchorer: ${synced.state.anchorer}\n` +
        `state: ${synced.statePath}\n`,
    );
    return 0;
  } catch (err) {
    process.stderr.write(`SYNC_FAILED ${(err as Error).message}\n`);
    return 1;
  }
}

export async function runCli(argv: string[]): Promise<number> {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(help() + "\n");
    return 0;
  }
  if (argv[0] !== "dispute" && argv[0] !== "local") {
    process.stderr.write(help() + "\n");
    return 2;
  }
  const command = argv[1];
  const flags = parseFlags(argv.slice(2));
  if (argv[0] === "local") {
    if (command === "export") return localExport(flags);
    if (command === "sync") return localSync(flags);
    process.stderr.write(help() + "\n");
    return 2;
  }
  if (command === "init-case") return initCaseCommand(flags);
  if (command === "validate") return validateCommand(flags);
  if (command === "export") return exportBundle(flags);
  if (command === "verify") return verifyBundle(flags);
  process.stderr.write(help() + "\n");
  return 2;
}

function isDirectExecution(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  return import.meta.url === pathToFileURL(entry).href;
}

if (isDirectExecution()) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      process.stderr.write(`sheaf: ${(err as Error).message}\n`);
      process.exitCode = 1;
    });
}
