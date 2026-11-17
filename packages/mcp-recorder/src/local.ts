// Offline local mode: no HTTP, local Ed25519 signer, append-only ledger,
// optional local evidence bootstrap. The ledger is the source of truth for
// `sheaf local export`; the cloud recorder is never contacted.

import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { canonicalize, hashCanonical, sha256Hex } from "./canonical.js";
import type { PolicyDecision } from "./policy.js";
import type {
  PendingCall,
  PolicyMetadata,
  RecorderConfig,
} from "./types.js";

export const LOCAL_LEDGER_SCHEMA = "sheaf.local-ledger/1";
export const LOCAL_KEYS_SCHEMA = "sheaf.local-keys/1";

export type LocalKeys = {
  schema: typeof LOCAL_KEYS_SCHEMA;
  key_id: string;
  public_key_base64: string;
  private_key_pkcs8_base64: string;
  created_at: string;
};

export type LocalLedgerRow = {
  schema: typeof LOCAL_LEDGER_SCHEMA;
  seq: number;
  chain_id: string;
  envelope: {
    v: "arca/1";
    event: Record<string, unknown>;
    chain: { chain_id: string; seq: number; prev_hash: string | null };
    signatures: { actor: null; recorder: string };
  };
  envelope_hash: string;
  recorded_at: string;
  payloads?: { arguments?: string; result?: string };
};

export class LocalLedgerError extends Error {}

function mode(path: string, value: number): void {
  try {
    chmodSync(path, value);
  } catch {
    // Windows does not implement POSIX modes; the file ACL remains the
    // operating-system boundary.
  }
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function loadOrCreateLocalKeys(chainDir: string): LocalKeys {
  mkdirSync(chainDir, { recursive: true, mode: 0o700 });
  const path = join(chainDir, "local-keys.json");
  if (existsSync(path)) {
    const parsed = readJson(path) as LocalKeys;
    if (
      parsed?.schema !== LOCAL_KEYS_SCHEMA ||
      !parsed.key_id ||
      !parsed.public_key_base64 ||
      !parsed.private_key_pkcs8_base64
    ) {
      throw new LocalLedgerError(`invalid local key file ${path}`);
    }
    mode(path, 0o600);
    return parsed;
  }

  const pair = generateKeyPairSync("ed25519");
  const jwk = pair.publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new LocalLedgerError("could not export local public key");
  const publicRaw = Buffer.from(jwk.x, "base64url");
  const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" });
  const keys: LocalKeys = {
    schema: LOCAL_KEYS_SCHEMA,
    key_id: `local-ed25519-${new Date().toISOString().slice(0, 10)}`,
    public_key_base64: publicRaw.toString("base64"),
    private_key_pkcs8_base64: Buffer.from(privateDer).toString("base64"),
    created_at: new Date().toISOString(),
  };
  writeFileSync(path, JSON.stringify(keys, null, 2) + "\n", { mode: 0o600 });
  mode(path, 0o600);
  return keys;
}

export function readLocalLedger(chainDir: string): LocalLedgerRow[] {
  const path = join(chainDir, "ledger.jsonl");
  if (!existsSync(path)) return [];
  const rows: LocalLedgerRow[] = [];
  const lines = readFileSync(path, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  for (let i = 0; i < lines.length; i++) {
    let parsed: LocalLedgerRow;
    try {
      parsed = JSON.parse(lines[i]!) as LocalLedgerRow;
    } catch (err) {
      throw new LocalLedgerError(
        `ledger line ${i + 1}: invalid JSON: ${(err as Error).message}`,
      );
    }
    if (parsed.schema !== LOCAL_LEDGER_SCHEMA) {
      throw new LocalLedgerError(`ledger line ${i + 1}: unsupported schema`);
    }
    rows.push(parsed);
  }
  for (let i = 0; i < rows.length; i++) {
    if (rows[i]!.seq !== i) {
      throw new LocalLedgerError(`ledger seq ${i} is not contiguous`);
    }
    if (i > 0 && rows[i]!.envelope.chain.prev_hash !== rows[i - 1]!.envelope_hash) {
      throw new LocalLedgerError(`ledger seq ${i} prev_hash mismatch`);
    }
  }
  return rows;
}

function stripSignature(document: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...document };
  delete copy.document_signature;
  return copy;
}

function ref(chainId: string, seq: number): string {
  return `sheaf://${chainId}/${seq}`;
}

function deriveToolName(call: PendingCall): string {
  const p = call.params as { name?: string; uri?: string } | undefined;
  switch (call.method) {
    case "tools/call": {
      const name = p?.name ?? "unknown";
      return name.startsWith("mcp://") ? name : `mcp://tool/${name}`;
    }
    case "resources/read":
      return `mcp://resource/${p?.uri ?? "unknown"}`;
    case "sampling/createMessage":
      return "mcp://sampling/createMessage";
    default:
      return `mcp://method/${call.method}`;
  }
}

function deriveIntent(call: PendingCall): string {
  const p = call.params as { name?: string; uri?: string } | undefined;
  switch (call.method) {
    case "tools/call":
      return `invoke tool ${p?.name ?? "unknown"}`;
    case "resources/read":
      return `read resource ${p?.uri ?? "unknown"}`;
    case "sampling/createMessage":
      return "sample LLM completion";
    default:
      return call.method;
  }
}

function inputPayload(call: PendingCall): unknown {
  if (call.method === "tools/call") {
    const p = call.params as { arguments?: unknown } | undefined;
    return p?.arguments ?? {};
  }
  return call.params;
}

/** Local recorder compatible with the proxy's RecorderClient surface. */
export class LocalLedger {
  readonly chainDir: string;
  readonly keys: LocalKeys;
  readonly chainId: string;
  readonly ledgerPath: string;
  private actor: string;
  private rows: LocalLedgerRow[];
  private seq: number;
  private prevHash: string | null;
  private privateKey: ReturnType<typeof createPrivateKey>;

  constructor(private cfg: RecorderConfig) {
    if (!cfg.local) throw new LocalLedgerError("local config is required");
    this.chainDir = resolve(cfg.local.chainDir);
    mkdirSync(this.chainDir, { recursive: true, mode: 0o700 });
    mkdirSync(join(this.chainDir, "payloads"), { recursive: true, mode: 0o700 });
    this.keys = loadOrCreateLocalKeys(this.chainDir);
    this.privateKey = createPrivateKey({
      key: Buffer.from(this.keys.private_key_pkcs8_base64, "base64"),
      format: "der",
      type: "pkcs8",
    });
    this.rows = readLocalLedger(this.chainDir);
    this.ledgerPath = join(this.chainDir, "ledger.jsonl");
    this.chainId =
      this.rows[0]?.envelope.chain.chain_id ??
      cfg.local.chainId ??
      cfg.chainId ??
      `local-${new Date().toISOString().replace(/[-:.]/g, "")}`;
    this.actor = cfg.local.actor ?? cfg.actor ?? "local-user";
    this.seq = this.rows.length;
    this.prevHash = this.rows[this.rows.length - 1]?.envelope_hash ?? null;

    if (cfg.policy && cfg.policyHash) {
      writeFileSync(
        join(this.chainDir, "policy.json"),
        JSON.stringify(cfg.policy, null, 2) + "\n",
        { mode: 0o600 },
      );
      this.seedPolicy(cfg.policyHash);
    }
    if (cfg.local.casePath) this.seedCase(cfg.local.casePath);
  }

  private append(
    event: Record<string, unknown>,
    payloads?: { arguments?: unknown; result?: unknown },
  ): LocalLedgerRow {
    const chain = {
      chain_id: this.chainId,
      seq: this.seq,
      prev_hash: this.prevHash,
    };
    const core = { v: "arca/1" as const, event, chain };
    const signature = sign(
      null,
      Buffer.from(canonicalize(core)),
      this.privateKey,
    ).toString("base64");
    const envelope = {
      ...core,
      signatures: { actor: null as null, recorder: signature },
    };
    const envelope_hash = hashCanonical(core);
    const row: LocalLedgerRow = {
      schema: LOCAL_LEDGER_SCHEMA,
      seq: this.seq,
      chain_id: this.chainId,
      envelope,
      envelope_hash,
      recorded_at: new Date().toISOString(),
    };
    if (payloads) {
      const refs: { arguments?: string; result?: string } = {};
      if (payloads.arguments !== undefined) {
        refs.arguments = this.writePayload(this.seq, "arguments", payloads.arguments);
      }
      if (payloads.result !== undefined) {
        refs.result = this.writePayload(this.seq, "result", payloads.result);
      }
      if (Object.keys(refs).length > 0) row.payloads = refs;
    }
    appendFileSync(this.ledgerPath, JSON.stringify(row) + "\n", { mode: 0o600 });
    mode(this.ledgerPath, 0o600);
    this.rows.push(row);
    this.seq += 1;
    this.prevHash = envelope_hash;
    return row;
  }

  private writePayload(seq: number, kind: string, content: unknown): string {
    const relative = `payloads/${String(seq).padStart(6, "0")}-${kind}.json`;
    const absolute = join(this.chainDir, relative);
    mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    writeFileSync(absolute, JSON.stringify(content, null, 2) + "\n", {
      mode: 0o600,
    });
    mode(absolute, 0o600);
    return relative;
  }

  private seedPolicy(policyHash: string): void {
    const existing = this.rows.find(
      (row) => row.envelope.event.kind === "policy",
    );
    if (existing?.envelope.event.inputs_hash === policyHash) return;
    this.append({
      kind: "policy",
      intent: "register local policy",
      actor: this.actor,
      authority: null,
      tool: "sheaf.policy",
      inputs_hash: policyHash,
      outputs_hash: null,
      result: "ok",
      ts: new Date().toISOString(),
      policy: {
        schema: "sheaf.policy/1",
        hash: policyHash,
        verdict: "ALLOW",
        reason_code: "policy_registered",
      },
    });
  }

  private seedCase(casePath: string): void {
    let manifest: any;
    try {
      manifest = readJson(casePath);
    } catch (err) {
      throw new LocalLedgerError(
        `could not read local case ${casePath}: ${(err as Error).message}`,
      );
    }
    const base = dirname(resolve(casePath));
    const loadDoc = (path: string): Record<string, unknown> =>
      readJson(isAbsolute(path) ? path : resolve(base, path));
    const mandateItem = manifest?.evidence?.mandate;
    if (mandateItem?.document) {
      const mandateDoc = loadDoc(mandateItem.document);
      const agentId = (mandateDoc.agent as any)?.id;
      if (typeof agentId === "string") {
        this.actor = agentId;
      }
      this.seedEvidence("mandate", mandateDoc, null, mandateItem.seq);
    }
    const delegation = manifest?.evidence?.delegation;
    const chain = Array.isArray(delegation?.chain) ? delegation.chain : [];
    let lastDelegationSeq: number | null = null;
    for (const link of chain) {
      const doc = loadDoc(link.document);
      const authority =
        typeof link.parent_seq === "number"
          ? ref(this.chainId, link.parent_seq)
          : null;
      this.seedEvidence("delegation", doc, authority, link.seq);
      if (typeof link.seq === "number") lastDelegationSeq = link.seq;
    }
    const consentItem = manifest?.evidence?.consent;
    if (consentItem?.document) {
      this.seedEvidence(
        "consent",
        loadDoc(consentItem.document),
        lastDelegationSeq !== null ? ref(this.chainId, lastDelegationSeq) : null,
        consentItem.seq,
      );
    }
  }

  private seedEvidence(
    kind: "mandate" | "delegation" | "consent",
    document: Record<string, unknown>,
    authority: string | null,
    expectedSeq?: number,
  ): void {
    const documentHash = `sha256:${hashCanonical(stripSignature(document))}`;
    const already = this.rows.find(
      (row) =>
        row.envelope.event.kind === kind &&
        row.envelope.event.inputs_hash === documentHash,
    );
    if (already) return;
    if (typeof expectedSeq === "number" && expectedSeq !== this.seq) {
      throw new LocalLedgerError(
        `case ${kind} seq ${expectedSeq} does not match local ledger seq ${this.seq}`,
      );
    }
    const actor =
      kind === "mandate"
        ? (document.principal as any)?.id
        : kind === "delegation"
          ? (document.issuer as any)?.id
          : (document.payer as any)?.id;
    const ts =
      kind === "mandate"
        ? document.issued_at
        : kind === "delegation"
          ? document.issued_at
          : document.consented_at;
    this.append({
      kind,
      intent:
        kind === "mandate"
          ? "issue mandate"
          : kind === "delegation"
            ? "delegate authority"
            : "record payer consent",
      actor: actor ?? this.actor,
      authority,
      tool: `sheaf.${kind}`,
      inputs_hash: documentHash,
      outputs_hash: null,
      result: "ok",
      ts,
    });
  }

  /** Queue/write a normal tool call event. Synchronous by design: no network. */
  submit(
    call: PendingCall,
    response: { result?: unknown; error?: { message: string } } | null,
  ): void {
    let result = "ok";
    let outputsHash: string | null = null;
    if (!response) result = "timeout";
    else if (response.error) result = "error";
    else if (response.result !== undefined) {
      outputsHash = `sha256:${hashCanonical(response.result)}`;
    }
    const args = inputPayload(call);
    this.append(
      {
        kind: "tool_call",
        intent: deriveIntent(call),
        actor: this.actor,
        authority: null,
        tool: deriveToolName(call),
        inputs_hash: `sha256:${hashCanonical(args)}`,
        outputs_hash: outputsHash,
        result,
        ts: new Date().toISOString(),
        ...(call.policy ? { policy: call.policy } : {}),
      },
      {
        arguments: args,
        ...(response?.result !== undefined ? { result: response.result } : {}),
      },
    );
  }

  submitBlocked(
    call: PendingCall,
    decision: PolicyDecision,
    policyHash: string,
  ): void {
    const policy: PolicyMetadata = {
      schema: "sheaf.policy/1",
      hash: policyHash,
      verdict: decision.verdict,
      reason_code: decision.reason_code,
    };
    const args = inputPayload(call);
    this.append(
      {
        kind: "tool_call",
        intent: deriveIntent(call),
        actor: this.actor,
        authority: null,
        tool: deriveToolName(call),
        inputs_hash: `sha256:${hashCanonical(args)}`,
        outputs_hash: null,
        result: "blocked",
        ts: new Date().toISOString(),
        policy,
      },
      { arguments: args },
    );
  }

  async drain(): Promise<void> {
    // Writes are synchronous; nothing to flush.
  }
}
