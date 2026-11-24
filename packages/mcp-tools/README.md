# @sheafhq/mcp-tools

MCP server exposing Sheaf read tools and x402-paying tools to any MCP-compatible
agent:

| Tool | Purpose |
| --- | --- |
| `sheaf_chain_head` | Fetch the current head of a Sheaf chain (seq + hash). |
| `sheaf_get_proof_for` | Fetch a Merkle inclusion proof + on-chain anchor reference for a specific event. |
| `sheaf_verify_bundle` | Verify a `.sheaf` dispute bundle or a receipt bundle end-to-end (signatures, Merkle inclusion, Base anchor). Dispute bundles are checked against pinned keys only. |
| `sheaf_buy_bundle` | Pay $0.001 USDC on Base via x402 and buy the self-contained `/bundle` artifact. |
| `sheaf_anchor_local` | Pay $0.01 USDC on Base and anchor a signed local Merkle root via `/v1/anchor/local`. |

The read tools are free. The paid tools require `SHEAF_PAYER_PRIVATE_KEY` (a
funded Base wallet) and automatically parse `402 Payment Required`, sign the
EIP-3009 authorization, and retry with the x402 payment header.

For event *capture* (transparently recording every tool call an agent makes), use the companion package [`@sheafhq/mcp-recorder`](https://www.npmjs.com/package/@sheafhq/mcp-recorder). It stays a pure proxy; this package is a separate, opt-in tool surface.

## Install

```bash
npm install -g @sheafhq/mcp-tools
```

Listed in the official MCP Registry as `io.sheafhq/mcp-tools`.

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
| `SHEAF_RECORDER_URL` | `https://api.sheafhq.io` | Recorder host to query. |
| `SHEAF_BASE_RPC` | `https://mainnet.base.org` | Base mainnet RPC used by `sheaf_verify_bundle` to read the anchor tx. |
| `SHEAF_PAYER_PRIVATE_KEY` | — | 0x-prefixed Base wallet key with USDC. Required for paid tools. |

## License

MIT
