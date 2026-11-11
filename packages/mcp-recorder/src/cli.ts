#!/usr/bin/env node
// CLI entry for sheaf-mcp-recorder. Usage:
//   sheaf-mcp-recorder --wrap <command> [args...]
//
// Environment variables:
//   SHEAF_RECORDER_URL   where to POST events (default: production)
//   SHEAF_CHAIN_ID       required. Stable per-session / per-agent identifier.
//   SHEAF_ACTOR          default: SHEAF_CHAIN_ID
//   SHEAF_CAPTURE_METHODS  comma-separated JSON-RPC methods to capture
//                       (default: tools/call,resources/read,sampling/createMessage)
//   SHEAF_DEBUG=1        verbose stderr logging

import { runProxy } from "./proxy.js";
import type { RecorderConfig } from "./types.js";

const argv = process.argv.slice(2);

function die(msg: string, code = 2): never {
  console.error(`sheaf-mcp-recorder: ${msg}`);
  console.error(
    "usage: sheaf-mcp-recorder --wrap <command> [args...]\n" +
      "       (set SHEAF_CHAIN_ID; see package README for all env vars)",
  );
  process.exit(code);
}

const wrapIdx = argv.indexOf("--wrap");
if (wrapIdx === -1) die("missing --wrap flag");
if (wrapIdx === argv.length - 1) die("no command after --wrap");

const command = argv[wrapIdx + 1]!;
const commandArgs = argv.slice(wrapIdx + 2);

const chainId = process.env.SHEAF_CHAIN_ID;
if (!chainId) die("SHEAF_CHAIN_ID env var is required");

const cfg: RecorderConfig = {
  recorderUrl:
    process.env.SHEAF_RECORDER_URL ??
    "https://sheaf-recorder.goldencalf.workers.dev",
  chainId,
  actor: process.env.SHEAF_ACTOR ?? chainId,
  captureMethods: new Set(
    (
      process.env.SHEAF_CAPTURE_METHODS ??
      "tools/call,resources/read,sampling/createMessage"
    )
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  ),
  logDebug: process.env.SHEAF_DEBUG === "1",
};

if (cfg.logDebug) {
  console.error(`[arca] wrapping: ${command} ${commandArgs.join(" ")}`);
  console.error(
    `[arca] recorder=${cfg.recorderUrl} chain=${cfg.chainId} actor=${cfg.actor} capture=[${[...cfg.captureMethods].join(",")}]`,
  );
}

runProxy(cfg, command, commandArgs);
