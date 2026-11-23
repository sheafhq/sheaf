# Sheaf

**A third-party execution recorder for AI agents.** Sheaf sits at the MCP
boundary, signs every tool call outside the agent's process, hash-chains the
records, and anchors Merkle roots on Base L2. The result is a `.sheaf` file
anyone can check offline, without trusting the operator's logs or Sheaf's
servers.

> **Status:** Developer Preview. The verifier, the MCP recorder and the local
> firewall are on npm and MIT-licensed. Read [How Sheaf works](https://sheafhq.io/how-it-works),
> including what Sheaf does **not** prove, before relying on it.

## Try it in two minutes

```bash
# 1. Verify a published sample bundle. No account, no clone.
curl -sO https://sheafhq.io/sample-bundle.sheaf
npx @sheafhq/verify sample-bundle.sheaf
```

It re-derives every hash, signature, Merkle proof and chain link, then reads
the anchor transaction from a public Base RPC. Edit any field and it reports
`NOT VALID` and exits `1`.

```bash
# 2. Watch a firewall block an agent and catch forged logs (needs Foundry's anvil).
git clone https://github.com/sheafhq/sheaf && cd sheaf
npm ci && npm run sim
```

The simulation runs a local chain, a buyer agent, a merchant and an
independent notary. The firewall blocks an over-budget purchase and allows a
valid one. The notary then rejects six forged versions of the log, including
one with the blocked attempt deleted and one with the deny rewritten as allow.
See [`simulation/`](./simulation).

## Use it

### Local firewall and ledger (no network)

```bash
npm install -g @sheafhq/mcp-recorder @sheafhq/verify

sheaf-mcp-recorder wrap --local \
  --policy ./policy.json \
  --chain-dir ./.sheaf \
  -- npx -y @modelcontextprotocol/server-filesystem .
```

Every `tools/call` is checked against a
[`sheaf.policy/1`](./schemas/sheaf.policy-1.schema.json) policy (ALLOW,
BLOCK or REQUIRE_APPROVAL, with constraints on arguments) before it reaches
the server. Allowed and blocked calls are both appended to a signed,
hash-chained `.sheaf/ledger.jsonl`. No HTTP requests are made. Example
policy: [`test/fixtures/dispute-walking/policy.json`](./test/fixtures/dispute-walking/policy.json).

### Hosted recorder

```bash
sheaf-mcp-recorder init        # creates a chain + API key in ./.sheaf/, no signup
sheaf-mcp-recorder --wrap npx -y @modelcontextprotocol/server-filesystem .
```

Events go to `https://api.sheafhq.io`, which chains them, batches them into
Merkle epochs, and anchors each epoch root on Base.

### Export and verify a Dispute Bundle

Turning a ledger into a portable Dispute Bundle uses the `sheaf` CLI in this
repo. It is not published to npm yet:

```bash
git clone https://github.com/sheafhq/sheaf && cd sheaf
npm ci && npm run build:sheaf

node dist-cli/cli.js local sync   --chain-dir ../.sheaf      # optional: anchor the root on Base
node dist-cli/cli.js local export --chain-dir ../.sheaf --case ../case.json --out ../bundle.sheaf
npx @sheafhq/verify ../bundle.sheaf --trust ../.sheaf/trust.json   # add --offline if you skipped sync
```

Run `sync` before `export`. A bundle exported before its root is anchored
carries a local anchor and verifies only with `--offline`. `sync` calls a
paid endpoint ($0.01 in USDC on Base via [x402](https://x402.org)). Set
`SHEAF_PAYER_PRIVATE_KEY` to a funded Base wallet, or skip it. The case
manifest, principal signatures and reason-code mapping are covered in
[`docs/AUTHORING.md`](./docs/AUTHORING.md).

### Library

```ts
import { verifyDisputeBundle, defaultTrustStore } from "@sheafhq/verify";

const result = await verifyDisputeBundle(bundle, {
  trust: defaultTrustStore(),            // pinned recorder keys + anchorers
  base_rpc: "https://mainnet.base.org",  // omit for integrity-only
});
```

Machine-readable usage guide: <https://sheafhq.io/llms.txt>

## How it works

```
Agent runtime (Claude Desktop, Cursor, custom)
        │  MCP tool call (JSON-RPC)
        ▼
┌─────────────────────────────────────┐
│  @sheafhq/mcp-recorder              │  stdio proxy, outside the agent process
│  policy check → sign → hash-chain   │  ALLOW / BLOCK / REQUIRE_APPROVAL
└──────────┬──────────────────────────┘
           │  signed arca/1 envelope (RFC 8785 JCS, Ed25519)
           ▼
┌─────────────────────────────────────┐
│  Local ledger or hosted recorder    │  append-only; hashes, not payloads
└──────────┬──────────────────────────┘
           │  Merkle epoch root
           ▼
┌─────────────────────────────────────┐
│  Base L2 anchor                     │  32-byte root on-chain, no content
└─────────────────────────────────────┘

Verification: bundle + Merkle inclusion proof + a Base RPC.
No contact with Sheaf needed.
```

- **Captured at the MCP boundary.** The proxy sees what the agent asked for
  and what came back, so the record isn't something the agent wrote about
  itself.
- **Enforced at the boundary.** Blocked attempts are recorded too, so the
  trail shows the agent tried to go out of bounds.
- **Content-optional.** Envelopes carry hashes and references. Payloads are
  disclosed selectively, as whole preimages, when a dispute needs them.
- **Portable.** A `.sheaf` file verifies with the open-source verifier, the
  [browser verifier](https://sheafhq.io/verify), or your own implementation of
  the [spec](./ARCHITECTURE.md).

## Limitations

Sheaf proves that a recorder signed a given sequence of events and that a
root covering them was anchored at a point in time. It does **not** prove:

- **Who the actor was.** The agent identifier is a label, not authenticated
  identity. Principal signatures count only when the verifying party pins the
  signer's key (`--signers`).
- **The client-supplied timestamp.** Only the anchor's block time is
  independent.
- **Completeness beyond a session.** The recorder can show a session was
  closed, not that the agent made no calls outside the proxy.
- **That everyone saw the same history.** Without an external log, a
  recorder could show different chains to different parties (split view).
- **Real-world effects.** A recorded payment call is not proof the payment
  settled.
- **Case-to-chain linkage.** Linking events to a card-network case is the
  merchant's assertion, not something Sheaf proves.
- **Field-level redaction.** Disclosure is whole-envelope and whole-payload in
  v1.
- **Anchor presence when offline.** `--offline` proves integrity only.
  Confirming the anchor needs a Base RPC.

## Related work

Sheaf builds on, and is aligned with, published work on agent auditability.
It does not claim conformance to any of these:

- [**VOLT**](https://datatracker.ietf.org/doc/draft-cowles-volt/) (Verifiable
  Operations Ledger and Trace) and [**WARD**](https://datatracker.ietf.org/doc/draft-cowles-ward/),
  individual Internet-Drafts, not IETF standards: hash-chained records and
  content-free witnessing.
- **RFC 8785 (JCS)**: deterministic JSON canonicalization, so signatures
  verify across platforms.
- Academic work on third-party recording and Merkle-batched, on-chain-anchored
  agent logs ("flight recorders").
- **EU AI Act Article 12** (record-keeping) and **ISO/IEC 42001**. Sheaf
  receipts can serve as logs under these. Sheaf is not a compliance product
  and does not certify anything.

## Packages

| Package | Purpose | npm |
|---|---|---|
| [`@sheafhq/verify`](./packages/verify) | Zero-dependency verifier: receipts, disclosure sets, Dispute Bundles | ✅ |
| [`@sheafhq/mcp-recorder`](./packages/mcp-recorder) | MCP stdio proxy: hosted recorder, local firewall and ledger | ✅ |
| [`@sheafhq/mcp-tools`](./packages/mcp-tools) | MCP server exposing chain head, proofs and verification to agents | ✅ |
| `sheaf` CLI (repo root) | Dispute Bundle authoring, local export and sync | clone |
| [`packages/s3-gateway`](./packages/s3-gateway) | S3 PUT proxy that records an `s3.put` receipt per write | clone |
| Recorder Worker (repo root) | Hosted recorder, archive, Merkle anchoring (Cloudflare Workers + D1) | — |

## Development

```bash
npm ci            # also installs packages/s3-gateway's dependencies
npm test          # all suites; the browser parity test needs Chrome or
                  # `npx playwright install chromium`
npm run sim       # end-to-end simulation (needs anvil from Foundry)
```

Running the recorder Worker locally, the x402-paid endpoints and test-mode
Stripe checkout are covered in [`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md).

## License

MIT
