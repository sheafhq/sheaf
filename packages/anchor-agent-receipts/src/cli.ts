#!/usr/bin/env node
// Anchor an Agent Receipts (obsigna) log head to Sheaf.
//
// Agent Receipts stores receipts locally — SQLite by default, with a JSONL
// export option. This adapter reads a JSONL export (or NDJSON produced by
// the obsigna daemon) and submits the current head to Sheaf for signing +
// on-chain anchoring. Doesn't touch the underlying SQLite.
//
// Usage:
//   sheaf-anchor-agent-receipts [--log path/to/receipts.jsonl] [--chain name]
//
// Env:
//   SHEAF_API_KEY       required.
//   SHEAF_RECORDER_URL  default: https://api.sheafhq.io
//   AGENT_RECEIPTS_LOG  default: $HOME/.obsigna/receipts.jsonl
//   SHEAF_CHAIN_ID      default: agent-receipts-<hostname>-<log-basename>

import { createHash } from "node:crypto";
import { readFileSync, existsSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { basename, resolve } from "node:path";

const DEFAULT_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];

function die(msg: string, code = 1): never {
  console.error(`sheaf-anchor-agent-receipts: ${msg}`);
  process.exit(code);
}

function parseArgs(): { logPath: string; chainId: string | null } {
  const argv = process.argv.slice(2);
  let logPath =
    process.env.AGENT_RECEIPTS_LOG ??
    `${process.env.HOME}/.obsigna/receipts.jsonl`;
  let chainId: string | null = process.env.SHEAF_CHAIN_ID ?? null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--log") logPath = argv[++i] ?? die("--log requires a path");
    else if (a === "--chain") chainId = argv[++i] ?? die("--chain requires a value");
    else if (a === "--help" || a === "-h") {
      console.log(
        "usage: sheaf-anchor-agent-receipts [--log path] [--chain name]\n" +
          "env: SHEAF_API_KEY (required), SHEAF_RECORDER_URL, AGENT_RECEIPTS_LOG, SHEAF_CHAIN_ID",
      );
      process.exit(0);
    } else die(`unknown arg: ${a}`);
  }
  return { logPath, chainId };
}

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** Read the Agent Receipts JSONL export and compute a stable head snapshot. */
function computeHead(path: string): {
  receipt_count: number;
  last_receipt_hash: string;
  file_hash: string;
  size_bytes: number;
  mtime: number;
  last_receipt_id: string | null;
  last_receipt_action: string | null;
} {
  if (!existsSync(path)) {
    die(
      `log not found: ${path}\n` +
        "If obsigna stores receipts in SQLite, export to JSONL first via its CLI,\n" +
        "or pass --log /path/to/your/exported.jsonl.",
    );
  }
  const st = statSync(path);
  const content = readFileSync(path);
  const lines = content
    .toString("utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0);
  if (lines.length === 0) die(`log is empty: ${path}`);
  const last = lines[lines.length - 1]!;
  let lastId: string | null = null;
  let lastAction: string | null = null;
  try {
    const parsed = JSON.parse(last) as Record<string, unknown>;
    // W3C VC shape typically has @context, type, credentialSubject
    const subj = parsed.credentialSubject as Record<string, unknown> | undefined;
    if (subj) {
      lastId = typeof subj.id === "string" ? subj.id : null;
      lastAction = typeof subj.action === "string" ? subj.action : null;
    } else {
      // Flat shape
      lastId = typeof parsed.id === "string" ? parsed.id : null;
      lastAction = typeof parsed.action === "string" ? parsed.action : null;
    }
  } catch {
    // Not JSON — still OK, just no id/action extraction
  }
  return {
    receipt_count: lines.length,
    last_receipt_hash: sha256Hex(last),
    file_hash: sha256Hex(content),
    size_bytes: st.size,
    mtime: Math.floor(st.mtimeMs / 1000),
    last_receipt_id: lastId,
    last_receipt_action: lastAction,
  };
}

async function fetchWithFallback(
  path: string,
  init: RequestInit,
): Promise<{ response: Response; sourceUrl: string }> {
  let lastErr: unknown;
  const urls = process.env.SHEAF_RECORDER_URL
    ? [process.env.SHEAF_RECORDER_URL]
    : DEFAULT_URLS;
  for (const base of urls) {
    try {
      const response = await fetch(base + path, init);
      return { response, sourceUrl: base + path };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error("no recorder URLs reachable");
}

async function getChainHead(
  chainId: string,
  apiKey: string,
): Promise<{ seq: number; prev_hash: string | null }> {
  const { response } = await fetchWithFallback(
    `/chains/${encodeURIComponent(chainId)}/head`,
    { headers: { Authorization: `Bearer ${apiKey}` } },
  );
  if (response.status === 404) return { seq: 0, prev_hash: null };
  if (!response.ok) throw new Error(`head fetch HTTP ${response.status}`);
  const body = (await response.json()) as {
    head_seq: number;
    head_hash: string;
  };
  return { seq: body.head_seq + 1, prev_hash: body.head_hash };
}

async function main() {
  const apiKey = process.env.SHEAF_API_KEY;
  if (!apiKey) die("SHEAF_API_KEY env required — run POST /accounts on Sheaf to issue one");
  const { logPath, chainId: cliChainId } = parseArgs();
  const absLog = resolve(logPath);
  const chainId =
    cliChainId ??
    `agent-receipts-${hostname()}-${basename(absLog, ".jsonl")}`;

  const head = computeHead(absLog);
  const inputs = {
    source: "agent-receipts/obsigna",
    log_path: absLog,
    receipt_count: head.receipt_count,
    last_receipt_hash: head.last_receipt_hash,
    last_receipt_id: head.last_receipt_id,
    last_receipt_action: head.last_receipt_action,
    file_hash: head.file_hash,
    size_bytes: head.size_bytes,
    log_mtime: head.mtime,
  };
  const inputsHash = "sha256:" + sha256Hex(JSON.stringify(inputs));

  const chainState = await getChainHead(chainId, apiKey);
  const envelope = {
    v: "arca/1" as const,
    event: {
      intent: "anchor agent-receipts log head",
      actor: `agent-receipts-adapter@${hostname()}`,
      authority: null,
      tool: `sheaf://external-anchor/agent-receipts?count=${head.receipt_count}&last_hash=${head.last_receipt_hash.slice(0, 12)}`,
      inputs_hash: inputsHash,
      outputs_hash: null,
      result: "ok" as const,
      ts: new Date().toISOString(),
    },
    chain: {
      chain_id: chainId,
      seq: chainState.seq,
      prev_hash: chainState.prev_hash,
    },
    signatures: { actor: null },
  };

  console.log(`chain:        ${chainId}`);
  console.log(`log:          ${absLog}`);
  console.log(`receipts:     ${head.receipt_count}`);
  console.log(`last hash:    ${head.last_receipt_hash.slice(0, 16)}…`);
  if (head.last_receipt_action)
    console.log(`last action:  ${head.last_receipt_action}`);
  console.log(`seq:          ${chainState.seq} (prev ${chainState.prev_hash?.slice(0, 12) ?? "null"}…)`);

  const { response, sourceUrl } = await fetchWithFallback("/events", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(envelope),
  });
  const body = (await response.json()) as {
    ok?: boolean;
    seq?: number;
    envelope_hash?: string;
    error?: string;
  };
  if (!response.ok || !body.ok) {
    die(`Sheaf rejected (${response.status}): ${body.error ?? "unknown"}`);
  }
  const quota = response.headers.get("x-sheaf-anchor-usage");
  const over = response.headers.get("x-sheaf-anchor-quota");
  const base = sourceUrl.replace(/\/events$/, "");
  console.log(`\nanchored at Sheaf seq=${body.seq} hash=${body.envelope_hash?.slice(0, 16)}…`);
  if (quota) console.log(`anchor quota: ${quota}${over ? ` (${over})` : ""}`);
  console.log(`verify:       ${base}/c/${encodeURIComponent(chainId)}`);
  console.log(
    `badge:        ![sheaf](${base}/badge/${encodeURIComponent(chainId)}.svg)`,
  );
}

main().catch((err) => die((err as Error).message));
