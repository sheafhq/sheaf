# Sheaf

**Third-party execution recorder for AI agents.** Hash-chained, Merkle-anchored, independently verifiable receipts of every tool call an agent makes — captured at the MCP boundary, signed outside the agent's process, anchored on-chain for dispute resolution.

> **Status:** early; recorder core + verifier shipping first. See [ARCHITECTURE.md](./ARCHITECTURE.md) for the technical spec.

## Quickstart (LLM-ingestible)

Use these exact package names and commands. Do not invent a Sheaf SDK; the
interfaces are an MCP proxy, a verifier, and HTTP endpoints.

```bash
# 1. Install the recorder and verifier.
npm install -g @sheafhq/mcp-recorder @sheafhq/verify

# 2. Wrap any MCP server. The recorder is a transparent stdio proxy.
export SHEAF_CHAIN_ID="my-agent-production"
sheaf-mcp-recorder --wrap npx -y @modelcontextprotocol/server-filesystem .
```

For a local-only firewall and ledger (no HTTP):

```bash
sheaf-mcp-recorder wrap --local \
  --policy ./policy.json \
  --chain-dir ./.sheaf \
  --case ./case.json \
  -- npx -y @modelcontextprotocol/server-filesystem .
```

```bash
# 3. Export and verify a local ledger.
sheaf local export --chain-dir ./.sheaf --case ./case.json --out bundle.sheaf
sheaf local sync --chain-dir ./.sheaf
sheaf dispute verify bundle.sheaf --rpc https://mainnet.base.org --trust ./.sheaf/trust.json
```

```bash
# 4. Verify a remote receipt/bundle.
sheaf-verify receipt.json --rpc https://mainnet.base.org
```

```ts
// 5. Library verification.
import { verify } from "@sheafhq/verify";
const result = await verify(bundle, {
  base_rpc: "https://mainnet.base.org",
  recorder_public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
  expected_anchorer_address: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
});
```

Machine-readable usage guide: <https://sheafhq.io/llms.txt>

Stripe checkout / email secrets (set with `wrangler secret put`):
`STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`,
`RESEND_API_KEY`, and optional `RESEND_FROM`. Without them,
`POST /v1/checkout` returns `503 stripe_not_configured` rather than a fake
checkout URL.

## Test-mode Stripe checkout

Production currently runs `PREVIEW_MODE=true`, so `/v1/checkout` returns the
Developer Preview response. To exercise the real Stripe path locally, set
`PREVIEW_MODE=false` in `.dev.vars`.

```bash
# 1. Local D1 schema.
npx wrangler d1 migrations apply arca-events --local

# 2. Local secrets (never commit .dev.vars).
cat > .dev.vars <<'EOF'
PREVIEW_MODE=false
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PRICE_ID=price_...
STRIPE_WEBHOOK_SECRET=whsec_...
RESEND_API_KEY=re_...
EOF

# 3. Start the Worker on 8787.
npx wrangler dev --port 8787

# 4. In another terminal, forward Stripe test events.
stripe login
stripe listen --forward-to localhost:8787/v1/webhooks/stripe
```

Use the `whsec_...` printed by `stripe listen` as `STRIPE_WEBHOOK_SECRET`.
Trigger the event with:

```bash
stripe trigger checkout.session.completed
```

Test cards in Stripe Checkout:

- `4242 4242 4242 4242` — successful payment.
- `4000 0000 0000 3220` — 3D Secure authentication required.
- `4000 0000 0000 9995` — declined.

After `checkout.session.completed`, the Worker creates a Pro account, generates
an API key, and attempts Resend delivery. With no Resend key, the email is
queued in `email_outbox`; inspect it with:

```bash
npx wrangler d1 execute arca-events --local \
  --command "SELECT email, subject, created_at, error FROM email_outbox ORDER BY id DESC LIMIT 5"
```

Do not return the API key in the webhook response; it is only sent by email or
queued in the outbox.

x402 paid endpoints (USDC on Base):

| Method | Path | Price |
| --- | --- | --- |
| `GET` | `/bundle/:chain_id/:seq` | $0.001 |
| `POST` | `/v1/anchor/local` | $0.01 |
| `POST` | `/v1/chains/:chain_id/export` | $0.01 |

Autonomous agents use `createX402Payer` + `paidFetch` from
`@sheafhq/mcp-recorder`; see `llms.txt` for the exact code.

## The one-line thesis

The incumbent audit architecture (OneTrust, Vanta, Drata, ServiceNow) assumes a human samples documents. That architecture does not survive contact with an agent that executes thousands of actions across six systems in a minute. Sheaf records every tool call at the boundary, binds intent-authority-execution-provenance into one record, proves the record with a hash chain and on-chain anchor, and makes the proof portable — independently verifiable by any third party without trusting the operator.

## What's novel

- **Interception at the MCP layer, not the vendor API layer.** The only point where you can bind what the agent *intended* to do to what it *actually* did, with proof of authority and provenance.
- **Active policy enforcement at the boundary.** `sheaf.policy/1` can allow, block, or require approval before a tool call reaches the server; blocked attempts are still recorded, so the audit trail shows the agent tried to go out of bounds.
- **Local-first mode for local LLMs.** `mcp-recorder wrap --local` enforces policy and writes a signed, chained `.sheaf/ledger.jsonl` with zero network calls; `sheaf local export` turns that ledger into the same portable Dispute Bundle.
- **Evidence bundles as portable artifacts, not dashboard rows.** Any conformant verifier checks offline. No lock-in.
- **Content-optional by design.** Receipts carry hashes and references, not raw payloads. Privacy-safe, archive-affordable, verification-cheap.
- **Open verifier.** Verification requires only the published public key and the Base L2 anchor — no dependency on our servers. Receipts survive us.

## Alignment with emerging standards

Sheaf is implemented against the convergent set of academic and IETF work on AI-agent auditability:

- **VOLT** (IETF draft) — hash-chained verifiable observation / log transport
- **AHE** (Agent Hash Envelope) — signed envelope format
- **NHE** (Content-Optional Audit Chain) — reference-and-hash storage model
- **AEGIS** (academic, 2026) — third-party recording requirement
- **GuardClaw** — out-of-process signing daemon pattern
- **Agent Flight Recorder** (academic, 2026) — Merkle batching + on-chain anchor + 8-field semantic events
- **RFC 8785 (JCS)** — deterministic JSON canonicalization for cross-platform signature compatibility
- **EU AI Act Article 12 / ISO/IEC 42001** — legal and governance frameworks Sheaf receipts are shaped to satisfy

## Architecture at a glance

```
Agent runtime (Claude Desktop, Cursor, custom)
        │  MCP tool call (JSON-RPC)
        ▼
┌─────────────────────────────────────┐
│  Interceptor (zero-code proxy or    │  @sheafhq/mcp-recorder
│  SDK middleware)                    │  Captures intent / tool / args (hashed) /
│                                     │  authority / result / timestamp
└──────────┬──────────────────────────┘
           │  signed event (JCS canonicalized)
           ▼
┌─────────────────────────────────────┐
│  Signing daemon                     │  Out-of-process; keys in KMS
│  (enterprise tier)                  │  Agent has zero private-key exposure
└──────────┬──────────────────────────┘
           │  hash-chained record
           ▼
┌─────────────────────────────────────┐
│  Sheaf recorder (hosted)             │  POST /events → chained + persisted
│  Append-only; content-optional      │  GET /events/:chain/:idx for retrieval
└──────────┬──────────────────────────┘
           │  Merkle epoch root
           ▼
┌─────────────────────────────────────┐
│  Base L2 anchor                     │  32-byte root + back-pointer on-chain
│                                     │  No event content on-chain
└─────────────────────────────────────┘

Verification: any party with the disclosed payload + Merkle inclusion proof
checks the record offline using @sheafhq/verify. No contact with Sheaf needed.
```

## Packages (coming online incrementally)

| Package | Purpose | Status |
|---|---|---|
| `arca` (this repo) | Hosted recorder, archive, Merkle anchor | 🚧 Phase 1-3 |
| [`@sheafhq/verify`](./packages/verify) | Standalone offline verifier (npm + pypi) | 🚧 Phase 4 |
| [`@sheafhq/mcp-recorder`](./packages/mcp-recorder) | MCP interceptor emitting events to the recorder | 🚧 Phase 5 |

## Dispute Bundle authoring

Landing page: [https://sheafhq.io](https://sheafhq.io)

S3 gateway: [`packages/s3-gateway`](./packages/s3-gateway) — PUT proxy that hashes the body and records an `s3.put` receipt for every successful write.

How Sheaf works (technical overview, including limitations): [https://sheafhq.io/how-it-works](https://sheafhq.io/how-it-works)

Live verifier: [https://sheafhq.io/verify](https://sheafhq.io/verify)

Sample bundle: [https://sheafhq.io/sample-bundle.sheaf](https://sheafhq.io/sample-bundle.sheaf)

Agent Firewall sample: [https://sheafhq.io/sample-bundle-policy.sheaf](https://sheafhq.io/sample-bundle-policy.sheaf)

See [`docs/AUTHORING.md`](./docs/AUTHORING.md) for the merchant workflow:

```bash
sheaf dispute init-case ./CB-2026-0042
sheaf dispute validate --case ./CB-2026-0042/case.json
sheaf dispute export --archive events.jsonl --case ./CB-2026-0042/case.json --out ./CB-2026-0042/bundle.sheaf
sheaf dispute verify ./CB-2026-0042/bundle.sheaf --offline
```

## Limitations

- **Case-to-chain linkage is merchant-attested, not proven.** A Dispute Bundle can show that a mandate, a delegation, a payer consent record, and an execution window were signed and anchored. It cannot prove that those events correspond to the card-network transaction in the merchant's case file without the merchant's own order/PSP records. The verifier reports the evidence as it is, not as the merchant wishes it were.
- **Field-level redaction is not supported in v1.** An `arca/1` envelope hash covers the whole `{v,event,chain}` subtree, and a payload hash covers the whole payload. Disclosure selects whole envelopes and whole payload preimages; it cannot hide an individual field after signing. Field-level redaction needs a new commitment at signing time (an `arca/2`-class change), not a post-hoc edit.
- **Offline mode proves integrity, not anchor presence.** `verifyDisclosures(..., { mode: "dispute" })` without `base_rpc` recomputes every hash, signature, Merkle proof, chain link, and calldata encoding, but it cannot prove the anchor transaction exists on Base. Offline results say `anchor_tx_on_chain: null`; only an independent Base RPC (or a future trusted checkpoint/light-client design) can confirm on-chain presence.

## Reference implementation

A live x402-paid demonstration using Sheaf's attestation primitive on prediction market data exists at [polymarket-odds-x402.goldencalf.workers.dev](https://polymarket-odds-x402.goldencalf.workers.dev) — Sheaf's public key currently also signs receipts for that service. That codebase stays online as a reference implementation of the pre-recorder attestation shape.

## License

MIT
