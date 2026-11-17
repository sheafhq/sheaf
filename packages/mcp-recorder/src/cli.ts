#!/usr/bin/env node
// CLI entry for sheaf-mcp-recorder.
//
//   sheaf-mcp-recorder wrap --local --policy ./policy.json -- npx server
//   sheaf-mcp-recorder --wrap npx server
//
// Environment variables:
//   SHEAF_RECORDER_URL   hosted recorder URL (ignored in --local mode)
//   SHEAF_CHAIN_ID       chain identifier (remote; optional local)
//   SHEAF_ACTOR          actor written into every event
//   SHEAF_CAPTURE_METHODS  comma-separated JSON-RPC methods
//   SHEAF_DEBUG=1        verbose stderr logging

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { hashCanonical } from "./canonical.js";
import { runProxy } from "./proxy.js";
import { validatePolicy, type PolicyDocument } from "./policy.js";
import type { RecorderConfig } from "./types.js";

const argv = process.argv.slice(2);

function die(msg: string, code = 2): never {
  console.error(`sheaf-mcp-recorder: ${msg}`);
  console.error(
    "usage:\n" +
      "  sheaf-mcp-recorder wrap --local --policy <policy.json> [--chain-dir ./.sheaf] [--case <case.json>] <command> [args...]\n" +
      "  sheaf-mcp-recorder --wrap <command> [args...]\n" +
      "  (remote mode requires SHEAF_CHAIN_ID; local mode writes ./.sheaf/ledger.jsonl)",
  );
  process.exit(code);
}

let local = false;
let policyPath: string | undefined;
let chainDir = "./.sheaf";
let casePath: string | undefined;
let chainIdFlag: string | undefined;
let actorFlag: string | undefined;
let debug = process.env.SHEAF_DEBUG === "1";
let command: string | undefined;
let commandArgs: string[] = [];
let sawWrap = false;

for (let i = 0; i < argv.length; i++) {
  const arg = argv[i]!;
  if (arg === "--local") local = true;
  else if (arg === "--policy") policyPath = argv[++i] ?? "";
  else if (arg === "--chain-dir") chainDir = argv[++i] ?? "";
  else if (arg === "--case") casePath = argv[++i] ?? "";
  else if (arg === "--chain-id") chainIdFlag = argv[++i] ?? "";
  else if (arg === "--actor") actorFlag = argv[++i] ?? "";
  else if (arg === "--debug") debug = true;
  else if (arg === "--wrap") {
    sawWrap = true;
    command = argv[++i];
    commandArgs = argv.slice(i + 1);
    break;
  } else if (arg === "wrap") {
    sawWrap = true;
  } else if (arg === "--") {
    command = argv[++i];
    commandArgs = argv.slice(i + 1);
    break;
  } else if (arg.startsWith("--")) {
    die(`unknown flag ${arg}`);
  } else if (!sawWrap) {
    die(`unexpected argument ${arg}`);
  } else {
    command = arg;
    commandArgs = argv.slice(i + 1);
    break;
  }
}

if (!command) die("missing wrapped command");
if (local && !policyPath) die("--local requires --policy <path>");

let policy: PolicyDocument | undefined;
let policyHash: string | undefined;
if (policyPath) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(policyPath, "utf8"));
  } catch (err) {
    die(`could not read policy ${policyPath}: ${(err as Error).message}`);
  }
  const errors = validatePolicy(parsed);
  if (errors.length > 0) {
    die(`invalid policy ${policyPath}:\n- ${errors.join("\n- ")}`);
  }
  policy = parsed as PolicyDocument;
  policyHash = "sha256:" + hashCanonical(policy);
}

const chainId =
  chainIdFlag ??
  process.env.SHEAF_CHAIN_ID ??
  (local ? "local" : undefined);
if (!chainId) die("SHEAF_CHAIN_ID env var is required for remote mode");

const DEFAULT_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];
const recorderUrls = local
  ? []
  : process.env.SHEAF_RECORDER_URL
    ? [process.env.SHEAF_RECORDER_URL]
    : DEFAULT_URLS;

const cfg: RecorderConfig = {
  recorderUrls,
  chainId,
  actor: actorFlag ?? process.env.SHEAF_ACTOR ?? chainId,
  captureMethods: new Set(
    (
      process.env.SHEAF_CAPTURE_METHODS ??
      "tools/call,resources/read,sampling/createMessage"
    )
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  ),
  logDebug: debug,
  ...(policy ? { policy, policyHash } : {}),
  ...(local
    ? {
        local: {
          chainDir: resolve(chainDir),
          ...(casePath ? { casePath: resolve(casePath) } : {}),
          ...(chainIdFlag ? { chainId: chainIdFlag } : {}),
          actor: actorFlag ?? process.env.SHEAF_ACTOR ?? "local-user",
        },
      }
    : {}),
};

if (cfg.logDebug) {
  console.error(`[sheaf] wrapping: ${command} ${commandArgs.join(" ")}`);
  console.error(
    local
      ? `[sheaf] local chain=${cfg.chainId} dir=${cfg.local!.chainDir} actor=${cfg.actor}`
      : `[sheaf] recorders=[${cfg.recorderUrls.join(",")}] chain=${cfg.chainId} actor=${cfg.actor} capture=[${[...cfg.captureMethods].join(",")}]`,
  );
  if (cfg.policy && cfg.policyHash) {
    console.error(
      `[sheaf] policy=${cfg.policy.policy_id} hash=${cfg.policyHash} enforcement=active`,
    );
  }
}

runProxy(cfg, command, commandArgs);
