#!/usr/bin/env node
// Anchor a Signet records.jsonl head to Sheaf.
//
// Usage:
//   sheaf-anchor-signet [--log path/to/records.jsonl] [--chain my-signet-log]
//
// Env:
//   SHEAF_API_KEY       required. Issued by POST /accounts on the Sheaf recorder.
//   SHEAF_RECORDER_URL  default: https://api.sheafhq.io  (fallback: workers.dev)
//   SIGNET_LOG          default: $HOME/.signet/records.jsonl
//   SHEAF_CHAIN_ID      default: signet-<hostname>-<log-basename>
//
// Exits 0 on successful anchor submission; 1 on any error.

import { createHash } from "node:crypto";
import { readFileSync, existsSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { basename, resolve } from "node:path";

const DEFAULT_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];

function die(msg: string, code = 1): never {
  console.error(`sheaf-anchor-signet: ${msg}`);
  process.exit(code);
}

function parseArgs(): { logPath: string; chainId: string | null } {
  const argv = process.argv.slice(2);
  let logPath =
    process.env.SIGNET_LOG ??
    `${process.env.HOME}/.signet/records.jsonl`;
  let chainId: string | null = process.env.SHEAF_CHAIN_ID ?? null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--log") logPath = argv[++i] ?? die("--log requires a path");
    else if (a === "--chain") chainId = argv[++i] ?? die("--chain requires a value");
    else if (a === "--help" || a === "-h") {
      console.log(
        "usage: sheaf-anchor-signet [--log path] [--chain name]\n" +
          "env: SHEAF_API_KEY (required), SHEAF_RECORDER_URL, SIGNET_LOG, SHEAF_CHAIN_ID",
      );
      process.exit(0);
    } else die(`unknown arg: ${a}`);
  }
  return { logPath, chainId };
}

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** Compute Signet log head: count of non-empty lines, final-line hash,
 *  cumulative file hash. Streams in one pass; works on logs up to RAM size. */
function computeHead(path: string): {
  record_count: number;
  last_record_hash: string;
  file_hash: string;
  last_record_preview: string;
  size_bytes: number;
  mtime: number;
} {
  if (!existsSync(path)) die(`log not found: ${path}`);
  const st = statSync(path);
  const content = readFileSync(path);
  const lines = content
    .toString("utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0);
  if (lines.length === 0) die(`log is empty: ${path}`);
  const last = lines[lines.length - 1]!;
  return {
    record_count: lines.length,
    last_record_hash: sha256Hex(last),
    file_hash: sha256Hex(content),
    last_record_preview: last.slice(0, 160),
    size_bytes: st.size,
    mtime: Math.floor(st.mtimeMs / 1000),
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
    cliChainId ?? `signet-${hostname()}-${basename(absLog, ".jsonl")}`;

  const head = computeHead(absLog);
  const inputs = {
    source: "signet/records.jsonl",
    log_path: absLog,
    record_count: head.record_count,
    last_record_hash: head.last_record_hash,
    file_hash: head.file_hash,
    size_bytes: head.size_bytes,
    log_mtime: head.mtime,
  };
  const inputsHash = "sha256:" + sha256Hex(JSON.stringify(inputs));

  const chainState = await getChainHead(chainId, apiKey);
  const envelope = {
    v: "arca/1" as const,
    event: {
      intent: "anchor signet log head",
      actor: `signet-adapter@${hostname()}`,
      authority: null,
      tool: `sheaf://external-anchor/signet?count=${head.record_count}&last_hash=${head.last_record_hash.slice(0, 12)}`,
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
  console.log(`records:      ${head.record_count}`);
  console.log(`last hash:    ${head.last_record_hash.slice(0, 16)}…`);
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
