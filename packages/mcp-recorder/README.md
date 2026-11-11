# @sheafhq/mcp-recorder

Transparent MCP (Model Context Protocol) proxy that captures every tool call an agent makes and emits signed, hash-chained, on-chain-anchored receipts to the [Sheaf](https://github.com/sheafhq/sheaf) recorder.

**Zero-code install.** Wrap any existing MCP server in Claude Desktop (or any MCP-aware client) with a one-line config change. No modifications to the wrapped server. No modifications to the agent.

Receipts are verifiable offline by any third party using [`@sheafhq/verify`](https://www.npmjs.com/package/@sheafhq/verify).

## Install

```bash
npm install -g @sheafhq/mcp-recorder
```

## Claude Desktop setup

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`; Windows: `%APPDATA%\Claude\`). Wrap the servers you want to audit:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "sheaf-mcp-recorder",
      "args": [
        "--wrap",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/me/Documents"
      ],
      "env": {
        "SHEAF_CHAIN_ID": "claude-me-filesystem",
        "SHEAF_ACTOR": "claude-desktop-me"
      }
    }
  }
}
```

Restart Claude Desktop. Every `tools/call`, `resources/read`, and `sampling/createMessage` through this server now flows through Sheaf and gets a signed, chained receipt — with the tool arguments and the response hashed (never sent raw).

## How it works

```
Claude (MCP client)
    │  JSON-RPC over stdio
    ▼
┌──────────────────────────┐
│  sheaf-mcp-recorder       │  ← this package. Transparent stdio proxy.
│  (zero-code wrapper)     │
└───────────┬──────────────┘
            │  JSON-RPC unchanged
            ▼
┌──────────────────────────┐
│  wrapped MCP server      │  (filesystem, github, slack, …)
└───────────┬──────────────┘
            │  JSON-RPC response
            ▼
       (tap: build envelope, POST to Sheaf recorder)
            │
            ▼
┌──────────────────────────┐
│  Sheaf recorder           │  signs + chains + persists
│  sheaf-recorder.*.dev     │  (anchored on-chain by Sheaf)
└──────────────────────────┘
```

Fail-open design: if the recorder is unreachable, the agent's tool calls still work. Missed events are logged to stderr; the chain re-syncs on the next successful submission.

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `SHEAF_CHAIN_ID` | **yes** | — | Stable identifier for this agent/session's event chain |
| `SHEAF_ACTOR` | no | = `SHEAF_CHAIN_ID` | Written into every event's `actor` field |
| `SHEAF_RECORDER_URL` | no | `https://sheaf-recorder.goldencalf.workers.dev` | Point at your own instance if self-hosting |
| `SHEAF_CAPTURE_METHODS` | no | `tools/call,resources/read,sampling/createMessage` | Comma-separated JSON-RPC methods to intercept |
| `SHEAF_DEBUG` | no | — | `1` to log every event to stderr |

## What gets recorded

For every intercepted tool call, one hash-chained event containing:

- **intent** — short description (e.g. `invoke tool write_file`)
- **actor** — from `SHEAF_ACTOR`
- **tool** — e.g. `mcp://tool/write_file`
- **inputs_hash** — `sha256(canonicalize(params))` of the tool arguments (raw args are **not** sent to the recorder)
- **outputs_hash** — same for the response, or null on error
- **result** — `ok` / `error` / `timeout` / `cancelled`
- **ts** — ISO 8601 UTC timestamp

The envelope is hash-chained (`prev_hash` → previous envelope hash) so any tamper is detectable. The recorder co-signs with Ed25519 and anchors the Merkle root on Base L2 periodically.

## Verifying a receipt later

Any third party can verify a stored receipt using `@sheafhq/verify` — it reads the anchor transaction from Base and checks the Merkle inclusion + Ed25519 signature offline.

See the main [Sheaf ARCHITECTURE.md](https://github.com/sheafhq/sheaf/blob/main/ARCHITECTURE.md) for the full protocol.

## License

MIT
