# @sheafhq/mcp-tools

MCP server exposing three Sheaf read tools to any MCP-compatible agent:

| Tool | Purpose |
| --- | --- |
| `sheaf_chain_head` | Fetch the current head of a Sheaf chain (seq + hash). |
| `sheaf_get_proof_for` | Fetch a Merkle inclusion proof + on-chain anchor reference for a specific event. |
| `sheaf_verify_bundle` | Verify a Sheaf receipt bundle end-to-end (signature, Merkle inclusion, anchor tx). |

All three are **read-only and free**. No wallet, no payment, no mutation.

For event *capture* (transparently recording every tool call an agent makes), use the companion package [`@sheafhq/mcp-recorder`](https://www.npmjs.com/package/@sheafhq/mcp-recorder). It stays a pure proxy; this package is a separate, opt-in tool surface.

## Install

```bash
npm install -g @sheafhq/mcp-tools
```

## Use with Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sheaf-tools": {
      "command": "sheaf-mcp-tools"
    }
  }
}
```

## Env vars

| Var | Default | Purpose |
| --- | --- | --- |
| `SHEAF_RECORDER_URL` | `https://sheaf-recorder.goldencalf.workers.dev` | Recorder host to query. |
| `SHEAF_BASE_RPC` | `https://mainnet.base.org` | Base mainnet RPC used by `sheaf_verify_bundle` to read the anchor tx. |

## License

MIT
