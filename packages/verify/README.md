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

`sheaf-verify` detects dispute bundles by their `schema` field and uses the
same function, so no flag is needed:

```bash
npx @sheafhq/verify bundle.sheaf                       # checks the anchor on Base
npx @sheafhq/verify bundle.sheaf --rpc https://mainnet.base.org
npx @sheafhq/verify bundle.sheaf --offline             # integrity only
npx @sheafhq/verify bundle.sheaf --signers pins.json   # authenticate principals
```

Try it on the published sample:
`curl -sO https://sheafhq.io/sample-bundle.sheaf && npx @sheafhq/verify sample-bundle.sheaf`.

The recorder repo's `sheaf dispute verify` and the browser verifier
`dispute-verify.html` use the same formatter, so all three print identical
reports. Offline mode leaves `anchor_on_base` null and exits `3` unless
`--allow-unconfirmed-anchor` is set. Exit codes: `0` valid, `1` invalid,
`2` usage or I/O error, `3` valid offline but anchor unconfirmed.

### Claims are checked, never trusted (S2)

`subject.claims` are the bundle author's statements. The verifier re-derives
each claim from the signed data it cites (`event.actor`, `event.tool`, or a
`payload` + `path` on the disputed event's own `tool_arguments`) and fails with
`CLAIM_MISMATCH` if they differ. The mandate scope (check 8) is evaluated only
on derived values; the amount and currency must be derivable from the signed
payload or check 8 fails with `EVIDENCE_GAP`. A merchant given only as the
author's assertion is not compared and adds the gap `merchant_scope`.
Supported paths: `$`, `.name`, `["name"]`, `[n]`.

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

A present `document_signature` must be **canonically encoded**: standard
base64 with padding, no whitespace, zero padding bits, a 32-byte key, and a
64-byte signature. It must also pass **strict Ed25519**, below. Anything else
is `EVIDENCE_DOC_SIGNATURE_INVALID`. One key therefore has exactly one
accepted spelling.

### Strict Ed25519

Every signature this library verifies (recorder, evidence, everything) first
passes a strict profile, identical in every runtime. It is the libsodium rule
set:

- the public key A and the signature's R are canonical encodings (y < p, no
  "negative zero") of points on the curve;
- A and R are **not of small order** (computed: 8·P ≠ identity);
- S < L.

Why this is needed: measured on 2026-11-17, native WebCrypto Ed25519 (Node 22 /
OpenSSL 3.5.9, Node 24 / OpenSSL 3.5.5, Edge 157) **enforces S < L but accepts
small-order public keys**. The identity key, also in its non-canonical
spellings, verifies the keyless signature R = identity, S = 0 for **every**
message; order-8 keys verify it for about 1 message in 8. Without the strict
profile, anyone could attach a "cryptographically valid" signature to any
document **without any private key**.

## Signature classification and authorisation

The verifier keeps five notions apart:

| Notion | Meaning |
|---|---|
| **cryptographically valid** | The signature passes strict Ed25519 over the document hash. Says nothing about who signed |
| **recognised recorder key** | The key's raw bytes equal a recorder key in scope: the bundle's own, the pinned keys, or `--trust`. Counted as **absent** for authorisation (`RECORDER_SIGNED_NOT_PRINCIPAL`) |
| **unrecognised key** | Any other key. **Self-asserted:** it is embedded in the document. Anyone can make one, including a recorder holding a second key. Never authenticates anyone |
| **authenticated principal** | The key is pinned **by the relying party** (`trusted_signers` / `--signers`) to the exact party the document names (mandate principal, delegation issuer, consent payer, or merchant for `merchant_signature`), for that role, and the event time falls in the pin's window. Relative to the relying party's own pins; **not** SAP identity |
| **verified authorisation** | Every authorising document is signed by an authenticated principal, and the delegation root is backed by one of those signatures |

Classification uses raw key bytes, never base64 strings, never `key_id`.
A recorder key can never be a trusted signer; such a pin is ignored with
`TRUSTED_SIGNER_IS_RECORDER`. Malformed or weak pins are ignored with
`TRUSTED_SIGNER_INVALID`.

The **delegation-root attestation** is a claim inside the bundle. It counts
only if backed by a signature that verified in the same bundle: the same key
bytes **and** the identical signature as the mandate's or the first
delegation's. Otherwise it produces `ROOT_ATTESTATION_UNVERIFIED` and the
`delegation_root` gap.

Extra fields inside `document_signature` are ignored and can't change the
classification. A non-object signature is invalid. Extra fields elsewhere
change the document hash (`EVIDENCE_DOC_HASH_MISMATCH`).

The report has two separate axes. Line 1 is the **evidence** verdict; line 2 is
**always** the authorisation tier:

| Label | Means | Does **not** mean |
|---|---|---|
| `VALID (complete)` | Integrity passed; every evidence section is present and signed by a **non-recorder** key; payloads and claims present | That anyone authenticated as the principal. Read line 2 |
| `VALID (partial)` | Integrity passed; at least one `evidence_gaps` entry | Anything about who authorised |
| `VALID (integrity only; anchor unconfirmed)` | Integrity passed offline; the anchor transaction wasn't checked on-chain | That the root is on Base |
| `authorisation: verified` | Every authorising document is signed by a relying-party-pinned signer for the party it names, and the root is backed | SAP identity; it rests on the relying party's pins |
| `authorisation: unauthenticated` | Signatures are cryptographically valid, but by unrecognised keys | That the named principal signed |
| `authorisation: recorder-attested only` | A recorder key signed evidence documents; those count as absent | That the principal did or didn't authorise |
| `authorisation: absent` | An authorising document is missing or unsigned | Anything about authorisation |
| `authorisation: not evaluated` | The bundle isn't valid | — |
| `recorder_observed` (bundle `authorization_basis`) | Producer label: no non-recorder signature backs the document | That anyone authorised it |

`authorization_basis` values inside a bundle (e.g. `principal_signature`)
are the **producer's claims**, kept for compatibility with historical bundles.
The verifier never treats them as authentication; `authorisation` and the
per-signature `signatures[]` entries are authoritative.

Each evidence document also gets a line such as:

```
signature [mandate]: valid signature, key unrecognised (…); names party payer_demo_001; principal not authenticated
```

`--require-verified-authorisation` (CLI) exits 1 unless the tier is
`verified`.

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
