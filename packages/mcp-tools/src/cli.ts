#!/usr/bin/env node
// CLI entry for sheaf-mcp-tools. Spawned by an MCP-compatible client
// (Claude Desktop, Cline, custom runtime) and speaks JSON-RPC over stdio.
//
// Environment variables (all optional):
//   SHEAF_RECORDER_URL   where to query (default: production recorder)
//   SHEAF_BASE_RPC       Base mainnet RPC for anchor verification
//                        (default: https://mainnet.base.org)

import { runServer } from "./server.js";

const ctx = {
  recorderUrl:
    process.env.SHEAF_RECORDER_URL ??
    "https://sheaf-recorder.goldencalf.workers.dev",
  baseRpc: process.env.SHEAF_BASE_RPC ?? "https://mainnet.base.org",
};

runServer(ctx);
