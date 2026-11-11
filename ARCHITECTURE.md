# Sheaf architecture

This document specifies Sheaf's technical architecture against emerging agent-auditability standards. Everything stated as a contract is versioned and will remain backwards-compatible across spec revisions.

## Design requirements

Derived from the convergent academic and IETF work on agent auditability:

1. **Third-party recording, not self-reporting.** The recorder sits outside the agent's process. Agents do not log themselves; a proxy intercepts tool calls at the MCP boundary and emits records. (AEGIS)
2. **Hash-chained event records.** Each event's canonical form hashes the previous event's hash, forming a chain. Any edit/delete/reorder/fork is detectable. (VOLT)
3. **Merkle batching + compact inclusion proofs.** Events are rolled into epochs; only the 32-byte Merkle root is anchored on-chain. Inclusion proofs are O(log n) in epoch size. No event content touches the chain. (Agent Flight Recorder)
4. **Canonical serialization (RFC 8785 JCS).** The same event serializes to identical bytes across OS and architecture. Signatures verify portably. (GuardClaw)
5. **Content-optional, privacy-first.** Events carry metadata + hashes + content-addressed references, not raw payloads. Explicit redaction support. (NHE)
6. **Semantic event fields.** Eight fields per event: intent, actor, authority, tool, inputs_hash, outputs_hash, result, timestamp. Forensic queries are precise. (AFR)
7. **Agent-native interception at MCP.** The capture point is the tool-call boundary. Any MCP client/server pair can be instrumented transparently. (mcp-audit-otel, mcp-audit-proxy, GuardClaw)
8. **Open verification.** Verifier is a library anyone can run offline against the public key + Base RPC. No dependency on Sheaf's servers to check a receipt.

## Event envelope v1

```json
{
  "v": "arca/1",
  "event": {
    "intent": "string — what the agent was trying to do",
    "actor": "string — agent identifier",
    "authority": "string | null — grant / role / session under which the call was made",
    "tool": "string — MCP tool name (e.g. mcp://filesystem/write)",
    "inputs_hash": "sha256:hex — hash of canonicalized tool arguments",
    "outputs_hash": "sha256:hex | null — hash of tool response (null if call errored)",
    "result": "ok | error | timeout | cancelled",
    "ts": "iso8601 — UTC timestamp at event capture"
  },
  "chain": {
    "chain_id": "string — stable per agent/session/tenant",
    "seq": "integer — monotonic within chain",
    "prev_hash": "sha256:hex | null — null only for seq=0"
  },
  "signatures": {
    "actor": "base64 ed25519 | null — optional; agent-side signature over canonicalized event+chain",
    "recorder": "base64 ed25519 — Sheaf's signature over canonicalized event+chain"
  }
}
```

### Canonicalization

All hashes and signatures are computed over RFC 8785 (JSON Canonicalization Scheme) output of the relevant subtree. Specifically:

- `inputs_hash` = `sha256(jcs(tool_arguments))`
- `outputs_hash` = `sha256(jcs(tool_response))`
- The envelope's `prev_hash` chains to `sha256(jcs(previous_envelope_without_signatures))`
- `signatures.recorder` signs `jcs({v, event, chain})`

A reference JCS implementation is included at `src/canonical.ts`.

### Content-optional fields

Raw `tool_arguments` and `tool_response` are **not stored** by Sheaf's recorder by default. Only their hashes appear in the envelope. Agents retain the raw payloads in their own storage (if at all) and present them alongside the receipt when proving a specific claim. This makes:

- Storage cost bounded (~512 bytes per event)
- No sensitive data in the archive
- Verification cheap (verifier hashes the disclosed payload and compares)

An optional `payload_ref` field may point to a content-addressed external store (IPFS CID, S3 ETag, R2 object hash) if the agent wants Sheaf to hold a reference to the content without storing it.

## Hash chain semantics

Each event in a chain carries `prev_hash` = hash of the previous event's canonical envelope (excluding signatures). This is identical to Git's commit hash model: edit any past event, and every subsequent hash changes, which is immediately detectable.

A chain is identified by `chain_id` — stable per agent, session, or tenant depending on how the interceptor is configured. The first event has `seq=0` and `prev_hash=null`. The chain's current head is queryable via `GET /chains/:chain_id/head`, which returns the latest `seq` and the hash of its envelope.

## Merkle batching + on-chain anchor

Every N minutes (or every N events), Sheaf rolls all events received since the last anchor into a Merkle tree. The 32-byte root is anchored on Base L2 by calling a trivial contract function that emits an event with `(root, prev_anchor_tx, event_count, timestamp)`.

An inclusion proof for any event is `O(log n)` sibling hashes. Any verifier with the root (fetched from the on-chain anchor tx) can prove or disprove that a given event was in that epoch — without trusting Sheaf.

Cost: at the current base gas prices, anchoring one 32-byte root costs ~$0.00005. Even at 1 event per second across all customers (87K events/day), anchoring is <$0.01/day. Storage, not anchor, dominates cost.

## On-chain contract (minimal)

```solidity
contract SheafAnchor {
    event EpochAnchored(uint256 indexed epoch, bytes32 root, bytes32 prev, uint64 eventCount, uint64 ts);
    uint256 public currentEpoch;
    bytes32 public lastRoot;

    function anchor(bytes32 root, uint64 eventCount) external {
        require(msg.sender == arcaAnchorer, "unauthorized");
        emit EpochAnchored(currentEpoch, root, lastRoot, eventCount, uint64(block.timestamp));
        lastRoot = root;
        currentEpoch += 1;
    }
}
```

A verifier reads the `EpochAnchored` events on Base to get the trusted Merkle roots, then checks local inclusion proofs against them.

## Verification protocol

Given a receipt bundle `{envelope, prev_envelope?, inclusion_proof, epoch, anchor_tx_hash}`:

1. Fetch `anchor_tx_hash` from Base. Extract the `root` from the `EpochAnchored` event.
2. Hash the envelope canonically and apply the `inclusion_proof` sibling hashes. Result must equal `root`.
3. If `prev_envelope` is supplied, verify that `envelope.chain.prev_hash == sha256(jcs(prev_envelope_without_signatures))`.
4. Verify `signatures.recorder` against the published Sheaf public key.
5. If `signatures.actor` is present, verify against the actor's claimed public key (looked up from an external identity registry, outside Sheaf's scope).

If all five pass, the receipt is sound: Sheaf recorded this event, it's in the committed Merkle tree, it links to its chain predecessor, and any tampering since issuance is detectable.

A reference verifier (`@sheafhq/verify`) implements all five checks in <500 LoC.

## What Sheaf does NOT do

Explicit non-goals to avoid confusion:

- **Not a GRC platform.** We don't map evidence to SOC 2 / ISO 42001 / EU AI Act controls. Downstream GRC tools (OneTrust, Drata, Vanta) can consume our receipts as their provenance layer, but the mapping logic is theirs.
- **Not an agent runtime.** We don't execute, orchestrate, or sandbox agents. We record the calls they make.
- **Not an identity provider.** We record who the actor claimed to be; we don't issue agent identities. Any verifiable credential / DID / passkey scheme can plug in.
- **Not a mutable store.** Receipts are append-only and anchored on-chain. No "update" or "delete" semantics.

## Versioning + compatibility

- The envelope schema is tagged `v: "arca/1"`. Future revisions get new tags (e.g., `arca/2`). The recorder accepts and stores all known versions forever; the verifier library handles all known versions.
- The on-chain anchor contract is immutable; a new version deploys a separate contract. Verifiers check both.
- The public signing key is rotatable; each rotation publishes a new `key_id` and all historical receipts stay verifiable against the key active at their `ts`.

## References

- [IETF draft: VOLT](https://datatracker.ietf.org/doc/draft-volt/) (hash-chained log transport)
- [IETF draft: AHE / NHE](https://datatracker.ietf.org/) (agent hash envelope, content-optional audit chain)
- Agent Flight Recorder paper (2026)
- AEGIS (2026) — third-party recording requirement
- [GuardClaw](https://github.com/guardclaw) — out-of-process signing daemon reference
- [mcp-audit-proxy](https://github.com/) — reference MCP interceptor
- [mcp-audit-otel](https://github.com/) — SDK middleware for MCP TypeScript SDK
- [RFC 8785: JCS](https://datatracker.ietf.org/doc/rfc8785/) — JSON canonicalization
- EU AI Act Article 12 — automated logging requirements
- ISO/IEC 42001 — AI management systems
