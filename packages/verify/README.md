# @sheafhq/verify

Standalone offline verifier for [Sheaf](https://github.com/sheafhq/sheaf) receipts. Checks hash chain + Merkle inclusion + Ed25519 signature + Base L2 anchor. **Zero runtime dependencies.**

The verifier reads only the anchor transaction from a Base RPC — no contact with Sheaf's servers needed to verify a receipt. Receipts survive us.

## Install

```bash
npm install @sheafhq/verify
```

## Usage

```ts
import { verify } from "@sheafhq/verify";

// A ReceiptBundle (what an agent stored alongside a tool call result)
const bundle = {
  envelope: /* the full signed Sheaf envelope */,
  inclusion_proof: /* { leaf, leaf_index, merkle_root, siblings } */,
  anchor_tx_hash: "0x…",            // Base tx hash where the Merkle root was anchored
  prev_envelope: /* optional */,    // if present, chain link is also verified
};

const result = await verify(bundle, {
  base_rpc: "https://mainnet.base.org",       // or any public/private Base RPC
  recorder_public_key_base64:
    "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
  expected_anchorer_address: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
});

if (result.valid) {
  console.log(`✓ valid; anchored in Base block ${result.anchor_block}`);
} else {
  console.log("✗ invalid:", result.reason);
  console.log("per-check breakdown:", result.checks);
}
```

## What it checks

Every call runs these seven invariants and reports them individually:

1. Anchor transaction exists on Base
2. Transaction was sent from (and to) the authorized anchorer address
3. Merkle root in the inclusion proof matches the one encoded in the anchor tx calldata
4. The (leaf, siblings) sequence actually reproduces the Merkle root
5. The hash of the envelope (excluding signatures) equals the leaf in the proof
6. The recorder Ed25519 signature verifies over the canonical (RFC 8785) serialization of {v, event, chain}
7. (Optional) `envelope.chain.prev_hash` equals the hash of `prev_envelope`

If any fails, `verify()` returns `{ valid: false, checks, reason }` with the exact field that broke.

## Dispute mode (selective disclosure)

`verify()` is unchanged for `sheaf-bundle/1`. Dispute mode is an explicit opt-in
for `sheaf-disclosure/1` sets:

```ts
import { verifyDisclosures, defaultTrustStore } from "@sheafhq/verify";

const result = await verifyDisclosures(disclosureSet, {
  mode: "dispute",
  trust: defaultTrustStore(),       // pinned recorder keys + Base anchorers
  base_rpc: "https://mainnet.base.org", // omit for integrity-only
});
```

Dispute mode fails closed on:

- `UNKNOWN_RECORDER_KEY` — the bundle's `recorder.key_id` is not pinned;
- `RECORDER_KEY_MISMATCH` — the bundle's public key differs from the pinned key;
- `UNKNOWN_ANCHORER` — the anchorer is not pinned for the network.

It also rejects an RPC whose `eth_chainId` is not the expected Base network
(`WRONG_CHAIN`), and refuses keys/anchorers outside their active windows.

It never fetches `recorder.public_key_url`. The only network call it can make is
the Base RPC, and only when `base_rpc` is supplied.

The pinned copies are shipped at `trust/recorder-keys.json` and
`trust/base-anchorers.json`. Trust material is versioned with the verifier:
rotating a recorder key or anchorer requires a new `@sheafhq/verify` release.
The verifier selects the pinned key by `key_id` and by the event timestamp; it
never fetches a key URL from a bundle.

The CLI's `--trust <path>` option exists for tests and fixtures only. It is not
a production rotation mechanism. Production callers should upgrade the pinned
verifier package.

## Limitations

- Case-to-chain linkage is merchant-attested, not proven.
- Field-level redaction is not supported in v1; disclosure is whole-envelope and
  whole-payload.
- Offline mode proves integrity, not anchor presence (`anchor_tx_on_chain: null`).

## Dispute Bundle verification

`verifyDisputeBundle(bundle, { trust?, base_rpc? })` verifies a
`sheaf.dispute-bundle/1` artifact and returns both `valid` and `complete`,
a 14-entry `checks[]` array, and `evidence_gaps[]`.

The CLI uses the same function:

```bash
sheaf dispute verify bundle.sheaf --rpc https://mainnet.base.org
sheaf dispute verify bundle.sheaf --offline
```

The browser verifier `dispute-verify.html` in the recorder repo uses the same
formatter, so CLI and browser output cannot diverge. Offline mode leaves
`anchor_on_base` null and exits `3` unless `--allow-unconfirmed-anchor` is set.

Check 14, `policy_enforced`, is optional. When a bundle includes a
`sheaf.policy/1` document, the verifier:

- recomputes `sha256(JCS(policy))` and compares it to `bundle.policy.hash`;
- requires every disclosed `tool_call` to carry the same `event.policy.hash`;
- rejects any non-blocked event with a non-`ALLOW` verdict;
- permits `result: "blocked"` events as evidence that enforcement fired;
- re-evaluates disclosed `tool_arguments` payloads against the policy.

```ts
import { evaluatePolicy, validatePolicy } from "@sheafhq/verify";
```

## Evidence documents

`verifyEvidenceDocument(envelope, document)` is the adjudicating check for
`event.kind` = `mandate`, `delegation`, or `consent`:

- the document schema must match the event kind;
- `sha256(JCS(document without document_signature))` must equal
  `event.inputs_hash`;
- if `document_signature` is present, Ed25519 must verify over the 32 raw bytes
  of that hash.

Mismatch returns `EVIDENCE_DOC_HASH_MISMATCH`. The recorder itself does not
adjudicate documents; it signs whatever it is given. The authoring path is
`src/evidence.ts` in the recorder repo, which validates the strict schema and
sets `inputs_hash` correctly.

`EVIDENCE_DOC_SIGNATURE_MISSING` is **opt-in**, not default. An unsigned
document is valid; callers that require a signed authorization pass
`{ require_document_signature: true }`. The default is `false` so the eventual
bundle can distinguish `authorization_basis: "recorder_observed"` from a signed
principal/policy/payer authorization.

## Primitives

The building blocks are also exported if you want to use them directly:

- `canonicalize(value)` — RFC 8785 JCS
- `sha256Hex(bytes | string)` — SHA-256 → hex
- `computeRootFromProof(leaf, siblings)` — Merkle recompute
- `verifyEd25519(publicKeyB64, sigB64, message)` — Ed25519 verify via WebCrypto
- `fetchAnchorTx(rpcUrl, txHash)` — read + decode Sheaf anchor tx from Base

## Runtime support

- Node 18+
- Cloudflare Workers
- Modern browsers (Chrome 113+, Firefox 130+, Safari 17+ — anywhere WebCrypto's Ed25519 is available)
- Deno
- Bun

## License

MIT
