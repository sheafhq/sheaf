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

## Runtime policy enforcement

Pass `--policy <path>` to turn the proxy into an enforcement point. The policy
document is validated against `sheaf.policy/1`, hashed with RFC 8785, and
recorded as the first event on the chain:

```bash
sheaf-mcp-recorder --policy ./policy.json --wrap npx -y @modelcontextprotocol/server-filesystem /Users/me/Documents
```

```json
{
  "schema": "sheaf.policy/1",
  "policy_id": "agent-payments-001",
  "issued_at": "2026-11-10T16:00:00Z",
  "expires_at": null,
  "default_verdict": "BLOCK",
  "allowed_tools": ["payments.transfer", "orders.read"],
  "denied_tools": ["admin.*"],
  "rules": [
    {
      "tool": "payments.transfer",
      "verdict": "ALLOW",
      "on_violation": "BLOCK",
      "constraints": [
        { "path": "amount", "op": "lte", "value": 15000, "reason": "amount_exceeds_limit" },
        { "path": "currency", "op": "eq", "value": "USD", "reason": "currency_not_usd" },
        { "path": "order_id", "op": "required", "reason": "order_id_required" }
      ]
    }
  ]
}
```

On `ALLOW`, the call is recorded with `event.policy` and forwarded. On `BLOCK`
or `REQUIRE_APPROVAL`, it is **not** forwarded; the blocked attempt is recorded
with `result: "blocked"` and the agent receives a structured JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32001,
    "message": "Blocked by Sheaf policy",
    "data": {
      "sheaf": true,
      "verdict": "BLOCK",
      "code": "POLICY_VIOLATION",
      "reason_code": "amount_exceeds_limit",
      "policy_hash": "sha256:..."
    }
  }
}
```

`REQUIRE_APPROVAL` uses code `-32002` and message `Approval required by Sheaf
policy`. Policy event hash, blocked events, and `event.policy` are additive
`arca/1` fields; old events verify unchanged. Schema:
[`schemas/sheaf.policy-1.schema.json`](../../schemas/sheaf.policy-1.schema.json).

## Local mode (offline firewall & ledger)

`--local` removes the hosted recorder from the path entirely. The proxy creates
an Ed25519 keypair in `.sheaf/local-keys.json` (mode `0600`), appends signed,
hash-chained events to `.sheaf/ledger.jsonl`, and enforces `--policy` locally.
No HTTP request is made.

```bash
sheaf-mcp-recorder wrap --local \
  --policy ./policy.json \
  --chain-dir ./.sheaf \
  --case ./case.json \
  -- npx -y @modelcontextprotocol/server-filesystem .
```

Blocked calls are recorded with `result: "blocked"` and return the same
structured JSON-RPC policy error as remote enforcement. Export the ledger with
the umbrella CLI:

```bash
sheaf local export --chain-dir ./.sheaf --case ./case.json --out bundle.sheaf
sheaf local sync --chain-dir ./.sheaf
sheaf dispute verify bundle.sheaf --rpc https://mainnet.base.org --trust ./.sheaf/trust.json
```

`local sync` posts a signed root request to `POST /v1/anchor/local`; the Worker
anchors the root on Base and records the receipt in `local_anchors`. A subsequent
export includes `anchor_mode: base`. See `docs/AUTHORING.md` §8.

## Autonomous x402 payments

Heavy Sheaf endpoints return `402 Payment Required` with a `PAYMENT-REQUIRED`
header. Agents can pay and retry without a Sheaf account:

```ts
import { createX402Payer, paidFetch } from "@sheafhq/mcp-recorder";
const payer = createX402Payer(process.env.SHEAF_PAYER_PRIVATE_KEY!);
const response = await paidFetch(
  "https://sheafhq.io/v1/anchor/local",
  {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(anchorRequest),
  },
  payer,
);
```

The helper parses the 402, signs the exact EIP-3009 authorization with the
local viem account, and retries with the x402 payment header. The wallet needs
USDC on Base. `@sheafhq/mcp-tools` exposes `sheaf_buy_bundle` and
`sheaf_anchor_local` with the same mechanism.

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
- **inputs_hash** — `sha256(canonicalize(params.arguments))` for `tools/call` (raw args are **not** sent to the recorder)
- **outputs_hash** — same for the response, or null on error
- **result** — `ok` / `error` / `timeout` / `cancelled` / `blocked`
- **ts** — ISO 8601 UTC timestamp
- **policy** — optional `{ schema, hash, verdict, reason_code }` when `--policy` is active

The envelope is hash-chained (`prev_hash` → previous envelope hash) so any tamper is detectable. The recorder co-signs with Ed25519 and anchors the Merkle root on Base L2 periodically.

## Verifying a receipt later

Any third party can verify a stored receipt using `@sheafhq/verify` — it reads the anchor transaction from Base and checks the Merkle inclusion + Ed25519 signature offline.

See the main [Sheaf ARCHITECTURE.md](https://github.com/sheafhq/sheaf/blob/main/ARCHITECTURE.md) for the full protocol.

## License

MIT
