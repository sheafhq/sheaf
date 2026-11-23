# Authoring a Dispute Bundle

This is the merchant-facing workflow. You do not need to read the Sheaf source
to produce a bundle.

The CLI is `sheaf`, from this repo; it is not on npm yet. Build it once:

```bash
git clone https://github.com/sheafhq/sheaf && cd sheaf
npm ci && npm run build:sheaf
alias sheaf="node $PWD/dist-cli/cli.js"
```

Don't run `npx sheaf`: it fetches an unrelated npm package of that name.

```text
sheaf dispute init-case <directory>
sheaf dispute validate --case <directory>/case.json [--archive events.jsonl]
sheaf dispute export --archive events.jsonl --case <directory>/case.json --out bundle.sheaf
sheaf dispute verify bundle.sheaf --offline
sheaf dispute verify bundle.sheaf --rpc <base-rpc>
```

## 1. Scaffold

```bash
sheaf dispute init-case ./CB-2026-0042
```

This creates:

```text
CB-2026-0042/
  case.json
  documents/
    README.md
  payloads/
    README.md
  MAPPING.md
```

`case.json` is a local manifest, not the final bundle. It targets
`sheaf.dispute-bundle/1` and contains placeholders for every required field.
`init-case` refuses a non-empty directory unless you pass `--force`.

## 2. What you must supply

### Case facts (`case.json`)

| Field | What to put there |
|---|---|
| `case.case_id` | Your case/representment ID. |
| `case.card_network` | The network named in the dispute. |
| `case.reason_code.schema` | Exact 2026 guide name the vendor uses. |
| `case.reason_code.value` | The reason code from the vendor's dispute record. Do not invent it. |
| `case.transaction.reference` | Processor/transaction ID. |
| `case.transaction.amount_minor` | Integer minor units, e.g. `12900` for USD 129.00. |
| `case.transaction.currency` | ISO 4217, e.g. `USD`. |
| `case.transaction.occurred_at` | ISO 8601 UTC, e.g. `2026-11-10T16:42:11Z`. |
| `case.merchant` | Merchant id, display name, URL. |
| `case.response_due_at` | Representment deadline, ISO 8601 UTC. |
| `case.dispute_basis.category` | `friendly_fraud`, `unauthorized`, `not_received`, `not_as_described`, `duplicate`, or `other`. |
| `case.dispute_basis.asserted_by` | `merchant`, `payer`, `issuer`, `vendor`, or `other`. |
| `case.dispute_basis.merchant_position` | One-sentence merchant position. Context, not cryptographic proof. |

`subject.from_seq` / `subject.to_seq` are the execution window on the recorded
chain. `subject.disputed_event_seqs` identifies the disputed event(s) inside
that window. `subject.claims` tells the verifier how to read merchant, amount,
currency, agent, and tool from the disclosed event/payloads.

`case.json` is sealed into the final bundle. Do not put secrets in it.

### Documents (`documents/`)

Supply the versioned JSON documents:

- `sheaf.mandate-document/1` — what the agent was authorized to do.
- `sheaf.delegation-document/1` — who authorized the agent and the parent
  authority link.
- `sheaf.consent-document/1` — the payer/merchant consent artifact.

Schemas live in [`schemas/`](../schemas/README.md). They are strict:
`additionalProperties: false` at every object level.

The document hash that binds to the event is:

```text
sha256(UTF-8 bytes of RFC 8785 JCS(document without document_signature))
```

The event’s `inputs_hash` is `sha256:<64 lowercase hex>`. The CLI computes this;
do not hand-edit it.

Optional `document_signature`:

```json
{
  "alg": "Ed25519",
  "key_id": "principal-key-1",
  "public_key_base64": "<raw 32-byte Ed25519 public key>",
  "signature_base64": "<Ed25519 signature over the 32 raw bytes of document hash>"
}
```

`document_signature` is excluded from the hash so signing is not circular.
The recorder records the event whether or not the document is signed; the
eventual bundle distinguishes `principal_signature` / `payer_signature` from
`recorder_observed`.

### Tool payloads (`payloads/`)

For the disputed event, supply the raw JSON that was hashed at record time:

- `payloads/3-args.json` — the tool arguments.
- `payloads/3-result.json` — the tool result.

If the event has a different seq, name the files accordingly. The CLI
canonicalizes each payload with RFC 8785 and checks it against the event’s
`inputs_hash` / `outputs_hash`.

### Archive (`events.jsonl`)

`export` reads the disclosed events and epoch/anchor rows from a local JSONL
archive. This is what keeps export independent of Sheaf’s servers:

```jsonl
{"type":"meta","chain_id":"...","recorder":{...},"anchorer":"0x...","network":"eip155:8453"}
{"type":"epoch","epoch_id":5,"merkle_root":"...","anchor_tx_hash":"0x...","anchor_block":56647675}
{"type":"event","seq":0,"envelope":{...},"envelope_hash":"...","epoch_id":5,"epoch_leaf_idx":0}
```

The export path with `--archive` makes **zero network calls to Sheaf**. It may
call a Base RPC only if you ask for an online `--self-check`; `--offline`
avoids that too.

## 3. Extract and hash payloads for `--payload`

The CLI accepts payload flags in this form:

```bash
--payload <seq>:<kind>=<path>
```

`kind` may be `tool_arguments`, `tool_result`, `args`, or `result`.

From your agent/MCP logs:

1. Find the `tools/call` request and response for the disputed event.
2. Save the raw `arguments` JSON as `payloads/<seq>-args.json`.
3. Save the raw `result` JSON as `payloads/<seq>-result.json`.
4. Do not pretty-print or add fields just for the bundle; the hash must match
   the bytes Sheaf recorded. If you must re-serialize, use RFC 8785 JCS.
5. Let the CLI hash them. If you want to check manually:

```text
hash = sha256(UTF-8 bytes of RFC 8785 JCS(payload))   # lowercase 64-hex
```

For tool arguments, `hash` must equal the event’s `inputs_hash` (after stripping
the optional `sha256:` prefix). For the result, it must equal
`outputs_hash`. The CLI reports `PAYLOAD_HASH_MISMATCH` before writing if it
does not.

You can put payloads in `case.json` instead:

```json
"payloads": [
  { "seq": 3, "kind": "tool_arguments", "path": "payloads/3-args.json" },
  { "seq": 3, "kind": "tool_result",   "path": "payloads/3-result.json" }
]
```

or supply them at export time:

```bash
sheaf dispute export \
  --archive events.jsonl \
  --case CB-2026-0042/case.json \
  --out CB-2026-0042/bundle.sheaf \
  --payload 3:tool_arguments=CB-2026-0042/payloads/3-args.json \
  --payload 3:tool_result=CB-2026-0042/payloads/3-result.json
```

`--payload` paths are resolved from your current working directory;
`case.json` payload paths are resolved relative to `case.json`.

## 4. Validate before export

```bash
sheaf dispute validate --case CB-2026-0042/case.json
```

Add `--archive events.jsonl` to also check:

- each evidence document’s hash against its event’s `inputs_hash`;
- each payload’s hash against the event;
- that every referenced event exists in the archive.

Validation fails on:

- missing required fields;
- remaining `[PLACEHOLDER: ...]` values;
- bad ISO dates, currency codes, integer amounts;
- missing `documents/`, `payloads/`, or `MAPPING.md`;
- unknown document fields or wrong document schemas;
- malformed Ed25519 key/signature lengths;
- `EVIDENCE_DOC_HASH_MISMATCH`;
- `PAYLOAD_HASH_MISMATCH`.

Output:

```text
VALID /path/to/case.json
```

or:

```text
INVALID /path/to/case.json
- case.dispute_basis.category: replace the placeholder value
- ...
```

Exit code is `0` for valid, `1` for invalid.

## 5. Export

```bash
sheaf dispute export \
  --archive events.jsonl \
  --case CB-2026-0042/case.json \
  --out CB-2026-0042/bundle.sheaf \
  --self-check --offline
```

- `--self-check` runs `verifyDisputeBundle` before writing.
- `--policy <path>` attaches a `sheaf.policy/1` document. The bundle hash
  covers the policy, and verification adds `policy_enforced` (check 14).
- `--strict` additionally fails on placeholders, absent/hash-only evidence, or
  a completeness verdict other than `complete`.
- `--offline` keeps the self-check from making any network call.
- `--rpc <url>` is used only when you want the self-check to confirm the Base
  anchor.

## 6. Verify

```bash
sheaf dispute verify CB-2026-0042/bundle.sheaf --offline
sheaf dispute verify CB-2026-0042/bundle.sheaf --rpc https://mainnet.base.org
```

Offline mode proves integrity, not anchor presence, and exits `3` unless you
add `--allow-unconfirmed-anchor`. Online mode checks `eth_chainId` and the
anchor tx through the RPC you supply.

## Anchorer note — production merchants use their own anchorer

The walking-skeleton fixture uses the hosted recorder’s canonical anchorer
`0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100` because no funded separate demo
key was available. That is a demo-chain exception, not the production model.

Production merchants should use a **dedicated anchorer** that they control (or
their recorder operator controls), not Sheaf’s canonical recorder anchorer.
The anchorer address is part of the verifier’s pinned trust material:

- `packages/verify/trust/base-anchorers.json`
- `packages/verify/trust/recorder-keys.json`

Adding or rotating an anchorer or recorder key requires a new
`@sheafhq/verify` release. A bundle cannot bootstrap its own trust, and the
verifier never fetches a key URL from the bundle. The `--trust <path>` CLI flag
is for tests and fixtures only; it is not a production rotation mechanism.

## 7. Reason-code mapping (`MAPPING.md`)

`MAPPING.md` is where the vendor maps their reason-code fields to bundle paths.
Do not invent card-network field names. Copy them from the applicable 2026
guide or the vendor’s intake schema.

The bundle itself intentionally keeps `case.reason_code` opaque. The mapping is
a separate document so the vendor can update it without changing the sealed
artifact.

## 8. Running Sheaf Locally as a Firewall

`@sheafhq/mcp-recorder` can run entirely offline. Local mode makes no HTTP
requests to the Sheaf Worker: the policy engine, Ed25519 signer, hash-chained
ledger, and Merkle tree all live in `./.sheaf`.

```bash
npx @sheafhq/mcp-recorder wrap --local \
  --policy ./policy.json \
  --chain-dir ./.sheaf \
  --case ./case.json \
  -- npx -y @modelcontextprotocol/server-filesystem .
```

From this repo, use `node packages/mcp-recorder/dist/cli.js` instead of `npx`.
`--local` requires `--policy`; the policy is evaluated before any `tools/call`
is forwarded. A blocked call is not forwarded, returns the standard structured
JSON-RPC error (`code: -32001`, `reason_code`), and is recorded with
`result: "blocked"`.

```text
.sheaf/
  local-keys.json       Ed25519 keypair, mode 0600
  ledger.jsonl          append-only signed event chain
  policy.json           copy of the active policy
  payloads/             local argument/result payloads
```

`local-keys.json` is the source of trust for this ledger. It is local, not
synced. If it is lost, the ledger cannot be re-signed.

Export the ledger as a standard bundle:

```bash
sheaf local export \
  --chain-dir ./.sheaf \
  --case ./case.json \
  --out ./bundle.sheaf
```

Local export verifies the ledger chain and signatures, builds a local Merkle
epoch, writes `.sheaf/trust.json`, and assembles the same
`sheaf.dispute-bundle/1` shape as the cloud path. The bundle carries
`anchor.mode: "local"`; `anchor_on_base` is `–` because there is no Base
transaction.

**Local export never signs the mandate, delegation or consent.** The ledger
key is a *recorder* key: it signs envelopes and anchor requests only. A
recorder signature is not the principal's authorisation (security fix S1,
2026-11-17; see `docs/SAP-ARCHITECTURE.md` §13). Documents are copied with the
signatures they already carry. Export refuses a document signed with the
ledger key (`RECORDER_SIGNED_NOT_PRINCIPAL`) or with a signature that no longer
verifies (`DOCUMENT_SIGNATURE_INVALID`).

To make the evidence complete, the **principal** signs each document with
**their own** Ed25519 key (PKCS#8 PEM), before or after the events are
recorded. The signature is excluded from the document hash, so the recorded
event still matches:

```bash
sheaf local sign-document ./mandate.json    --key ./principal.pem --key-id payer-key-1
sheaf local sign-document ./delegation.json --key ./principal.pem --key-id payer-key-1
sheaf local sign-document ./consent.json    --key ./principal.pem --key-id payer-key-1
```

`sign-document` refuses the ledger key and any pinned recorder key
(`SIGNING_KEY_IS_RECORDER_KEY`). Keep the principal key off the agent host.

Verify offline with the local trust file:

```bash
sheaf dispute verify ./bundle.sheaf \
  --offline \
  --trust ./.sheaf/trust.json
```

Expected with principal-signed documents: `VALID (complete)` and, on line 2,
`authorisation: unauthenticated — ...`, plus `[14] policy_enforced ✓`,
`anchor_confirmed: true` and `anchor_mode: local`.

Line 2 is deliberate. `VALID (complete)` means every evidence document carries
a valid signature by a key that is **not** a recorder key. It does **not** mean
the signer was authenticated: the key sits inside the document, and any
freshly generated key would verify the same way.

A relying party that knows the principal's key can pin it, and then gets
`authorisation: verified`:

```bash
cat > signers.json <<'EOF'
{ "schema": "sheaf.trusted-signers/1",
  "signers": [ { "key_id": "payer-key-1", "public_key_base64": "<principal public key>",
                 "party_id": "payer_demo_001", "roles": ["mandate", "delegation", "consent"],
                 "active_from": "2026-01-01T00:00:00Z", "active_until": null } ] }
EOF
sheaf dispute verify ./bundle.sheaf --offline --trust ./.sheaf/trust.json \
  --signers ./signers.json --require-verified-authorisation
```

That pin is the relying party's own assertion, not SAP identity. See
`packages/verify/README.md` → "Signature classification and authorisation".
Without principal signatures: `VALID (partial)` with `mandate_signature`,
`delegation_signature`, `delegation_root` and `consent_signature` listed as
evidence gaps.

Bundles exported **before** this fix carry recorder-signed documents labelled
`principal_signature`. The verifier still accepts their integrity, but reports
`VALID (partial)`, prints `authorisation: recorder-attested only`, and emits
`warning: RECORDER_SIGNED_NOT_PRINCIPAL` for each affected section.

`local sync` computes the same Merkle root, signs the anchor request with the
local key, and POSTs it to the Worker:

```bash
sheaf local sync --chain-dir ./.sheaf
```

It sends only the chain id, Merkle root, event count, local public key, and
calldata. `POST /v1/anchor/local` is x402-paywalled at `$0.01` USDC on Base.
Set `SHEAF_PAYER_PRIVATE_KEY` to a funded Base wallet and the CLI will parse the
402, sign the EIP-3009 authorization, and retry automatically. Without it, sync
fails with a clear `402 Payment Required` message. The Worker verifies the
anchor-request signature, anchors the root on Base L2, and stores the receipt in
`local_anchors`. The command writes `.sheaf/anchor.json`
with the `tx_hash`, `block_number`, `epoch_id`, and anchorer. Re-running export
then uses the Base anchor:

```bash
sheaf local export --chain-dir ./.sheaf --case ./case.json --out ./bundle.sheaf
sheaf dispute verify ./bundle.sheaf --rpc https://mainnet.base.org --trust ./.sheaf/trust.json
```

Expected: `VALID (complete)`, `[12] anchor_on_base ✓`, and `anchor_mode: base`.
Offline verification can still prove integrity, but `anchor_on_base` remains
`–` because no RPC is available to confirm the Base transaction.

Tests:

```bash
npm run test:local       # no child process
npm run test:local:e2e   # dummy MCP server + real local proxy; requires spawn
```

## Limits

- Case-to-chain linkage is merchant-attested, not proven.
- Field-level redaction is not supported in v1; disclosure is whole-envelope
  and whole-payload.
- Offline mode proves integrity, not anchor presence.
- The bundle proves the record; it does not prove delivery, cardholder identity,
  or legal sufficiency.
