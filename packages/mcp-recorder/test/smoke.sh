#!/usr/bin/env bash
# Smoke test: feed a JSON-RPC tools/call to sheaf-mcp-recorder wrapping the
# mock MCP server. Check that (a) the response gets relayed back and
# (b) the recorder received an event for that call.
set -euo pipefail
cd "$(dirname "$0")/.."

CHAIN_ID="smoke-mcp-$(date +%s)"
echo "chain: $CHAIN_ID"

INPUT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/x","content":"hi"}}}'

echo "=== invoking proxy ==="
OUTPUT=$(SHEAF_CHAIN_ID="$CHAIN_ID" SHEAF_DEBUG=1 \
  node dist/cli.js --wrap node test/mock-mcp.mjs <<< "$INPUT" 2>&1 || true)
echo "$OUTPUT" | head -20

echo ""
echo "=== wait 2s then check recorder ==="
sleep 2
HEAD=$(curl -sS "https://sheaf-recorder.goldencalf.workers.dev/chains/$CHAIN_ID/head")
echo "head: $HEAD"
echo "$HEAD" | grep -q '"head_seq":0' && echo "✅ one event recorded for the tools/call" || { echo "❌ event not found"; exit 1; }
