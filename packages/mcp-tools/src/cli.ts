#!/usr/bin/env node
// CLI entry for sheaf-mcp-tools. Spawned by an MCP-compatible client
// (Claude Desktop, Cline, custom runtime) and speaks JSON-RPC over stdio.
//
// Environment variables (all optional):
//   SHEAF_RECORDER_URL   explicit recorder override. If unset, tries
//                        https://api.sheafhq.io and falls back to
//                        https://sheaf-recorder.goldencalf.workers.dev.
//   SHEAF_BASE_RPC       Base mainnet RPC for anchor verification
//                        (default: https://mainnet.base.org)

import { runServer } from "./server.js";

const DEFAULT_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];
const recorderUrls = process.env.SHEAF_RECORDER_URL
  ? [process.env.SHEAF_RECORDER_URL]
  : DEFAULT_URLS;

const ctx = {
  recorderUrls,
  baseRpc: process.env.SHEAF_BASE_RPC ?? "https://mainnet.base.org",
};

runServer(ctx);
