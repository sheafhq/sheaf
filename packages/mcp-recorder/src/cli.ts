#!/usr/bin/env node
// CLI entry for sheaf-mcp-recorder.
//
// Subcommands:
//   init                 create a Sheaf chain + account + local credentials
//                        (no signup; first event; MCP config printed).
//   --wrap <cmd> [args]  transparent MCP proxy around an existing server
//                        (reads SHEAF_CHAIN_ID + SHEAF_API_KEY from env or
//                        from .sheaf/ in the cwd).
//
// Environment variables for --wrap mode:
//   SHEAF_RECORDER_URL   where to POST events. Default: api.sheafhq.io with
//                        workers.dev fallback.
//   SHEAF_CHAIN_ID       chain identifier. Auto-loaded from .sheaf/config.json
//                        if present.
//   SHEAF_API_KEY        account key. Auto-loaded from .sheaf/credentials.json
//                        if present.
//   SHEAF_ACTOR          default: SHEAF_CHAIN_ID.
//   SHEAF_CAPTURE_METHODS  comma-separated JSON-RPC methods to capture.
//   SHEAF_DEBUG=1        verbose stderr logging.

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { installGlobalScrubber } from "./scrub.js";
import { runProxy } from "./proxy.js";
import { runInit } from "./init.js";
import type { RecorderConfig } from "./types.js";

// Install the key scrubber BEFORE anything else can print. Any Sheaf API key
// written to stdout, stderr, console.*, or thrown in an error message is
// rewritten to [REDACTED_SHEAF_KEY] — prevents the smoke-test leak class
// from recurring. Init's intentional "key display" paths are not stdout; the
// key goes to .sheaf/credentials.json on disk (chmod 600) and the MCP
// config snippet goes to .sheaf/mcp-config.json. Scrubber cannot touch
// files, so operators still have access to their own secrets.
installGlobalScrubber();

const argv = process.argv.slice(2);

function die(msg: string, code = 2): never {
  console.error(`sheaf-mcp-recorder: ${msg}`);
  console.error(
    "usage: sheaf-mcp-recorder init\n" +
      "       sheaf-mcp-recorder --wrap <command> [args...]\n" +
      "       (see package README for env vars)",
  );
  process.exit(code);
}

const DEFAULT_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];
const recorderUrls = process.env.SHEAF_RECORDER_URL
  ? [process.env.SHEAF_RECORDER_URL]
  : DEFAULT_URLS;

// --- init subcommand -------------------------------------------------------

if (argv[0] === "init") {
  runInit({
    recorderUrls,
    cwd: process.cwd(),
    logDebug: process.env.SHEAF_DEBUG === "1",
  }).catch((err) => {
    console.error(`sheaf-mcp-recorder init: ${(err as Error).message}`);
    process.exit(1);
  });
} else {
  // --- --wrap mode (existing) ---------------------------------------------
  const wrapIdx = argv.indexOf("--wrap");
  if (wrapIdx === -1) die("missing --wrap flag (or did you mean `init`?)");
  if (wrapIdx === argv.length - 1) die("no command after --wrap");

  const command = argv[wrapIdx + 1]!;
  const commandArgs = argv.slice(wrapIdx + 2);

  // Auto-load chain_id + api_key from .sheaf/ if env vars are missing.
  let chainId = process.env.SHEAF_CHAIN_ID;
  let apiKey = process.env.SHEAF_API_KEY;
  if (!chainId || !apiKey) {
    const sheafDir = join(process.cwd(), ".sheaf");
    const configPath = join(sheafDir, "config.json");
    const credsPath = join(sheafDir, "credentials.json");
    if (existsSync(configPath) && !chainId) {
      try {
        chainId = JSON.parse(readFileSync(configPath, "utf8")).chain_id;
      } catch {}
    }
    if (existsSync(credsPath) && !apiKey) {
      try {
        apiKey = JSON.parse(readFileSync(credsPath, "utf8")).api_key;
      } catch {}
    }
  }
  if (!chainId) die("SHEAF_CHAIN_ID not set and no .sheaf/config.json found (run `sheaf-mcp-recorder init` first)");

  const cfg: RecorderConfig = {
    recorderUrls,
    chainId,
    apiKey: apiKey ?? null,
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
    console.error(`[sheaf] wrapping: ${command} ${commandArgs.join(" ")}`);
    console.error(
      `[sheaf] recorders=[${cfg.recorderUrls.join(",")}] chain=${cfg.chainId} actor=${cfg.actor} capture=[${[...cfg.captureMethods].join(",")}] authed=${cfg.apiKey ? "yes" : "no"}`,
    );
  }

  runProxy(cfg, command, commandArgs);
}
