# Sheaf plugin for Claude Code

Adds three Sheaf tools to Claude Code — all read-only, all free, all offline-verifiable:

- `sheaf_chain_head` — current state of a Sheaf chain
- `sheaf_get_proof_for` — Merkle inclusion proof for a specific event
- `sheaf_verify_bundle` — verify a Sheaf bundle end-to-end

## Install

From Claude Code:

```
/plugin marketplace add sheafhq/sheaf
/plugin install sheafhq@sheafhq
```

Or manually by copying `packages/claude-plugin/.mcp.json` into your Claude Code config directory.

## To anchor every tool Claude Code makes

The Sheaf tools (above) are read-only — they let Claude verify a bundle or query chain state, but they don't *record* what Claude does. To get a cryptographic audit trail of every tool call Claude Code makes, wrap your MCP servers with `@sheafhq/mcp-recorder`:

```json
{
  "mcpServers": {
    "my-filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@sheafhq/mcp-recorder",
        "--wrap",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/files"
      ],
      "env": {
        "SHEAF_API_KEY": "sk_live_...",
        "SHEAF_CHAIN_ID": "claude-code-session-prod"
      }
    }
  }
}
```

Every `tools/call`, `resources/read`, and `sampling/createMessage` that flows through that wrapped server will be signed, hash-chained, and included in the next 15-minute Sheaf anchor on Base mainnet.

See [github.com/sheafhq/sheaf](https://github.com/sheafhq/sheaf) for the full architecture.

## License

MIT.
