# Sheaf

**Third-party execution recorder for AI agents.** Hash-chained, Merkle-anchored, independently verifiable receipts of every tool call an agent makes — captured at the MCP boundary, signed outside the agent's process, anchored on-chain for dispute resolution.

> **Status:** early; recorder core + verifier shipping first. See [ARCHITECTURE.md](./ARCHITECTURE.md) for the technical spec.

## The one-line thesis

The incumbent audit architecture (OneTrust, Vanta, Drata, ServiceNow) assumes a human samples documents. That architecture does not survive contact with an agent that executes thousands of actions across six systems in a minute. Sheaf records every tool call at the boundary, binds intent-authority-execution-provenance into one record, proves the record with a hash chain and on-chain anchor, and makes the proof portable — independently verifiable by any third party without trusting the operator.

## What's novel

- **Interception at the MCP layer, not the vendor API layer.** The only point where you can bind what the agent *intended* to do to what it *actually* did, with proof of authority and provenance.
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

## Reference implementation

A live x402-paid demonstration using Sheaf's attestation primitive on prediction market data exists at [polymarket-odds-x402.goldencalf.workers.dev](https://polymarket-odds-x402.goldencalf.workers.dev) — Sheaf's public key currently also signs receipts for that service. That codebase stays online as a reference implementation of the pre-recorder attestation shape.

## License

MIT
