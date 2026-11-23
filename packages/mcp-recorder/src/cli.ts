#!/usr/bin/env node
// CLI entry for sheaf-mcp-recorder.
//
//   sheaf-mcp-recorder init
//   sheaf-mcp-recorder wrap --local --policy ./policy.json -- npx server
//   sheaf-mcp-recorder --wrap npx server
//
// `init` creates a hosted chain + account + local credentials (.sheaf/).
//
// Environment variables:
//   SHEAF_RECORDER_URL   hosted recorder URL (ignored in --local mode)
//   SHEAF_CHAIN_ID       chain identifier (remote; optional local). Remote
//                        mode auto-loads it from .sheaf/config.json.
//   SHEAF_API_KEY        account key (remote). Auto-loaded from
//                        .sheaf/credentials.json if present.
//   SHEAF_ACTOR          actor written into every event
//   SHEAF_CAPTURE_METHODS  comma-separated JSON-RPC methods
//   SHEAF_DEBUG=1        verbose stderr logging

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { installGlobalScrubber } from "./scrub.js";
import { hashCanonical } from "./canonical.js";
import { runProxy } from "./proxy.js";
import { runInit } from "./init.js";
import { validatePolicy, type PolicyDocument } from "./policy.js";
import type { RecorderConfig } from "./types.js";

// Install the key scrubber BEFORE anything else can print. Any Sheaf API key
// written to stdout, stderr, console.*, or thrown in an error message is
// rewritten to [REDACTED_SHEAF_KEY]. The key itself lives in
// .sheaf/credentials.json (chmod 600); the scrubber cannot touch files.
installGlobalScrubber();

const argv = process.argv.slice(2);

const DEFAULT_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];

function die(msg: string, code = 2): never {
  console.error(`sheaf-mcp-recorder: ${msg}`);
  console.error(
    "usage:\n" +
      "  sheaf-mcp-recorder init\n" +
      "  sheaf-mcp-recorder wrap --local --policy <policy.json> [--chain-dir ./.sheaf] [--case <case.json>] <command> [args...]\n" +
      "  sheaf-mcp-recorder --wrap <command> [args...]\n" +
      "  (remote mode requires SHEAF_CHAIN_ID; local mode writes ./.sheaf/ledger.jsonl)",
  );
  process.exit(code);
}

if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
  console.log(
    "sheaf-mcp-recorder: signed, hash-chained receipts for every MCP tool call\n\n" +
      "usage:\n" +
      "  sheaf-mcp-recorder init\n" +
      "      Create a hosted chain + API key in ./.sheaf/ (no signup).\n" +
      "  sheaf-mcp-recorder --wrap <command> [args...]\n" +
      "      Record every tool call to the hosted recorder (needs SHEAF_CHAIN_ID).\n" +
      "  sheaf-mcp-recorder wrap --local --policy <policy.json> [--chain-dir ./.sheaf] [--case <case.json>] -- <command> [args...]\n" +
      "      sheaf.policy/1 firewall: ALLOW / BLOCK / REQUIRE_APPROVAL before a call\n" +
      "      reaches the server; writes a signed, chained ./.sheaf/ledger.jsonl with\n" +
      "      no network calls.\n\n" +
      "options: --chain-id <id>  --actor <name>  --debug\n" +
      "docs: https://github.com/sheafhq/sheaf/tree/main/packages/mcp-recorder",
  );
  process.exit(0);
} else if (argv[0] === "init") {
  runInit({
    recorderUrls: process.env.SHEAF_RECORDER_URL ? [process.env.SHEAF_RECORDER_URL] : DEFAULT_URLS,
    cwd: process.cwd(),
    logDebug: process.env.SHEAF_DEBUG === "1",
  }).catch((err) => {
    console.error(`sheaf-mcp-recorder init: ${(err as Error).message}`);
    process.exit(1);
  });
} else {
  runWrap();
}

function runWrap(): void {
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

// Remote mode: auto-load chain_id + api_key from .sheaf/ (written by
// `init`) when the env vars are missing.
let envChainId = process.env.SHEAF_CHAIN_ID;
let apiKey = process.env.SHEAF_API_KEY;
if (!local && (!envChainId || !apiKey)) {
  const sheafDir = join(process.cwd(), ".sheaf");
  const configPath = join(sheafDir, "config.json");
  const credsPath = join(sheafDir, "credentials.json");
  if (existsSync(configPath) && !envChainId) {
    try {
      envChainId = JSON.parse(readFileSync(configPath, "utf8")).chain_id;
    } catch {}
  }
  if (existsSync(credsPath) && !apiKey) {
    try {
      apiKey = JSON.parse(readFileSync(credsPath, "utf8")).api_key;
    } catch {}
  }
}

const chainId =
  chainIdFlag ??
  envChainId ??
  (local ? "local" : undefined);
if (!chainId) die("SHEAF_CHAIN_ID not set and no .sheaf/config.json found (run `sheaf-mcp-recorder init` first)");
const recorderUrls = local
  ? []
  : process.env.SHEAF_RECORDER_URL
    ? [process.env.SHEAF_RECORDER_URL]
    : DEFAULT_URLS;

const cfg: RecorderConfig = {
  recorderUrls,
  chainId,
  apiKey: local ? null : (apiKey ?? null),
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
      : `[sheaf] recorders=[${cfg.recorderUrls.join(",")}] chain=${cfg.chainId} actor=${cfg.actor} capture=[${[...cfg.captureMethods].join(",")}] authed=${cfg.apiKey ? "yes" : "no"}`,
  );
  if (cfg.policy && cfg.policyHash) {
    console.error(
      `[sheaf] policy=${cfg.policy.policy_id} hash=${cfg.policyHash} enforcement=active`,
    );
  }
}

runProxy(cfg, command!, commandArgs);
}
