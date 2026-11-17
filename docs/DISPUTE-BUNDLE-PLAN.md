# Dispute Bundle — implementation plan

Status:

- **#1 selective-disclosure primitive — built and passing its exit criteria.**
- **A pinned-key trust model — built alongside #1.**
- **#2 evidence event layer — built and passing its exit criteria.**
- **#3 bundle assembler/verifier/CLI — built and passing its exit criteria.**
- **B browser verifier — built and passing the browser parity test.**
- **C authoring workflow — built and passing the end-to-end merchant test.**

This document is the implementation-facing addendum to the review plan. It
records the added deliverables, the schema addition, the build order, and the
limits that must appear in the README.

## Dependency order

| Order | Build | Includes | Exit criterion |
|---|---|---|---|
| 1 | Selective-disclosure primitive | `discloseRange`, `verifyDisclosures`, cross-epoch/multi-proof support, boundary refs | The eight disclosure cases plus a swapped-key `RECORDER_KEY_MISMATCH` case pass. |
| 1 | A: pinned-key trust model | `trust/recorder-keys.json`, `trust/base-anchorers.json`, fail-closed codes, no `public_key_url` fetch | Unknown key, mismatched key, and unknown anchorer all fail closed; legacy `verify()` is unchanged. |
| 2 | Evidence event layer | Additive `event.kind`; canonical mandate/delegation/consent documents; recording path | A mandate, delegation, and consent can be recorded and hash-bound without invalidating old `arca/1` events. |
| 3 | Bundle assembler + verifier + CLI | `buildDisputeBundle`, `verifyDisputeBundle`, `sheaf dispute export`, `sheaf dispute verify` | A walking-skeleton bundle verifies from a clean machine with the pinned key. |
| 3 | C: authoring workflow | `sheaf dispute init-case`, `docs/AUTHORING.md`, RFC 8785 hashing instructions | A merchant can scaffold a case, hash a payload, and know exactly what to supply. |
| 3 | B: browser verifier | `CB-2026-0042.html` embeds `@sheafhq/verify`, reads the bundle, verifies in-browser, prints the same checks | No network calls except the Base RPC; integrity-only toggle works offline. |
| 4 | Hardening + demo | Adversarial matrix, finality, key rotation, full synthetic case, Base mainnet anchor | Vendor-ready artifact and tamper log. |

**First three things to build:** #1 + A, #2, #3 + B/C.  
**First vendor-showable artifact:** after #3, a one-transaction walking skeleton
with one mandate, one delegation, one execution event, a real Base anchor, and a
clean-machine verification log. The full 30-event demo comes after hardening.

## A. Pinned-key trust model for `@sheafhq/verify`

Built with #1:

- `packages/verify/trust/recorder-keys.json`
- `packages/verify/trust/base-anchorers.json`
- `packages/verify/src/trust.ts` — runtime copy of the pinned data; a test
  asserts the JSON and runtime constants do not drift.
- `verifyDisclosures(..., { mode: "dispute" })` — explicit opt-in.
- Fail-closed codes:
  - `UNKNOWN_RECORDER_KEY`
  - `RECORDER_KEY_MISMATCH`
  - `UNKNOWN_ANCHORER`
  - plus `RECORDER_KEY_NOT_ACTIVE`, `UNSUPPORTED_NETWORK`, `ANCHORER_NOT_ACTIVE`,
    and `WRONG_CHAIN` (RPC `eth_chainId` mismatch) for the same trust boundary.
- Dispute mode never fetches `recorder.public_key_url`; the test stubs
  `globalThis.fetch` to throw and still verifies offline.
- `verify()` and the legacy `sheaf-bundle/1` path are unchanged. The CLI adds
  `--dispute`, `--offline`, and `--trust <path>`; the legacy path keeps its
  existing behavior.

## #2 Evidence event layer

Built:

- Optional `event.kind` added to `arca/1`:
  `"tool_call" | "mandate" | "delegation" | "consent"`.
  Absent means `"tool_call"`; the envelope version stays `arca/1`.
- Versioned, strict JSON Schemas:
  - `schemas/sheaf.mandate-document-1.schema.json`
  - `schemas/sheaf.delegation-document-1.schema.json`
  - `schemas/sheaf.consent-document-1.schema.json`
- Authoring module `src/evidence.ts`:
  - `validateEvidenceDocument` — strict validation, `additionalProperties:false`
    semantics.
  - `canonicalEvidenceDocument` — RFC 8785 JCS of the document without
    `document_signature`.
  - `evidenceDocumentHash` — lowercase 64-hex SHA-256.
  - `buildEvidenceSubmission` — emits an unsigned `arca/1` event with `kind`
    set and `inputs_hash = "sha256:" + document_hash`.
  - `signEvidenceDocument` — optional Ed25519 signature over the 32 raw bytes
    of the unsigned document hash.
- Verifier `packages/verify/src/evidence.ts`:
  - `verifyEvidenceDocument(envelope, document, opts?)`.
  - `EVIDENCE_DOC_HASH_MISMATCH` when `inputs_hash` does not equal
    `sha256(JCS(document without document_signature))`.
  - `EVIDENCE_DOC_SIGNATURE_MISSING` / `EVIDENCE_DOC_SIGNATURE_INVALID` for the
    optional signature.
- `document_signature` lives **inside** the document and is excluded from the
  document hash. This avoids a circular commitment. The event hash covers the
  unsigned document hash; the optional signature covers that same hash.
- The recorder is unchanged: it signs whatever it is given. The authoring
  module is the supported path; the verifier catches mismatches later.

Golden compatibility fixtures captured from the live `smoke-test-1` chain:

- `test/fixtures/arca1-no-kind.smoke-test-1-0.json` — real pre-change envelope
  with no `kind`.
- `test/fixtures/sheaf-bundle-1.smoke-test-1-0.json` — real pre-change
  `sheaf-bundle/1` shape.

## #3 Dispute Bundle assembler, verifier, and CLI

Built:

- `src/dispute.ts` — `buildDisputeBundle(case, disclosures, evidence, anchor, payloads)`.
  - `bundle_id = "sha256:" + sha256(JCS(bundle without bundle_id and verification))`.
  - `case.dispute_basis` is required.
  - `DELEGATION_PARENT_MISMATCH` when `parent_event_ref` does not equal the
    parsed `event.authority`; `authorityRef(chainId, seq)` helper added in
    `src/evidence.ts`.
  - No network I/O, no file I/O.
- `packages/verify/src/dispute.ts` — `verifyDisputeBundle`, returning:
  - `valid`, `complete`, `anchor_confirmed`
  - a 13-entry `checks[]` array
  - `evidence_gaps[]`
- Check names, in order:
  1. `schema_supported`
  2. `bundle_id_matches`
  3. `selection_contiguous`
  4. `chain_links`
  5. `disclosure_signatures_and_proofs`
  6. `anchor_roots_match`
  7. `payload_hashes_match`
  8. `mandate_evidence`
  9. `delegation_authority`
  10. `consent_evidence`
  11. `temporal_order`
  12. `anchor_on_base`
  13. `completeness`
  14. `policy_enforced` (optional policy attachment)
- `formatDisputeVerification()` is the single text formatter used by both CLI
  and browser.
- CLI: `sheaf dispute export` and `sheaf dispute verify`.
  - `--archive` path is local-only; no Sheaf network.
  - `--offline` prints `VALID (integrity only; anchor unconfirmed)` and exits
    `3` unless `--allow-unconfirmed-anchor`.
  - `--strict` fails on placeholders, incomplete evidence, or an invalid bundle.
  - `--self-check` runs `verifyDisputeBundle` before writing.
  - `--policy <path>` attaches a `sheaf.policy/1` document; verification runs
    `policy_enforced`.
  - `--trust <path>` is testing-only.

Walking skeleton fixture:

- Chain `demo-dispute-walking-20261112t213407z`
- Seqs/kinds: `0:mandate`, `1:delegation`, `2:consent`, `3:tool_call`,
  `4:tool_call`
- Base mainnet tx:
  `0x847c6b718e7ebc0ef0efae87f74f10bf58c14ba668832896244dee2bb3a8271a`
- Block `56647675`
- Anchorer: `0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100` (the hosted
  recorder's canonical anchorer; no funded separate demo anchorer key was
  available, so the chain is labelled as a demo and the anchorer is disclosed
  explicitly).

## B. Self-contained browser verifier

Live: **https://api.sheafhq.io/verify**  
Sample: **https://api.sheafhq.io/sample-bundle.sheaf**

Built as `dispute-verify.html`:

- Single file; esbuild inlines `@sheafhq/verify`; no CDN, no remote modules.
- Drag-and-drop plus a file picker.
- Default online via `https://mainnet.base.org`; `?rpc=<url>` overrides it and
  `?offline=1` gives integrity-only mode. The page displays the CORS caveat.
- **Load Sample Bundle** fetches `/sample-bundle.sheaf` and verifies it
  immediately.
- Prints the same `formatDisputeVerification()` output as the CLI.
- Ed25519 uses WebCrypto (`crypto.subtle`), not a bundled `@noble` implementation.
  Browser support: Chrome/Edge 113+, Firefox 130+, Safari 17+ (any browser with
  WebCrypto Ed25519).
- Browser parity test: headless Chromium via Playwright over CDP, drag/drop the
  same bundle, compare `#output` byte-for-byte with the CLI's offline output.

## C. Authoring workflow

Built:

- `sheaf dispute init-case <directory>` scaffolds:
  - `case.json` targeting `sheaf.dispute-bundle/1`, with `case.dispute_basis`
    and placeholders for every required field;
  - `documents/` with a schema pointer README;
  - `payloads/` with a usage README;
  - blank `MAPPING.md`.
- `sheaf dispute validate --case <case.json> [--archive events.jsonl]` checks:
  - required fields, dates, currency, integer amounts, seq range;
  - remaining `[PLACEHOLDER: ...]` values;
  - directory structure (`documents/`, `payloads/`, `MAPPING.md`);
  - strict evidence-document schemas and Ed25519 key/signature lengths;
  - optional document hash vs archive `inputs_hash`;
  - optional payload hash vs archive `inputs_hash` / `outputs_hash`.
- `--payload <seq>:<kind>=<path>` export flag added; `args` / `result`
  shorthand accepted.
- [docs/AUTHORING.md](AUTHORING.md) is the merchant-facing guide. It documents
  extraction and RFC 8785 hashing, the `--payload` flag, validation, export,
  and the **anchorer note**: production merchants use their own dedicated
  anchorers, not Sheaf's canonical recorder anchorer; adding or rotating an
  anchorer/key requires a verifier release.
- `test/authoring.test.mjs` runs init-case → fill template → validate → export →
  verify, plus document-hash-mismatch and `--payload`-flag cases.

## Schema addition: `case.dispute_basis`

Add to the Dispute Bundle case block:

```json
"dispute_basis": {
  "category": "friendly_fraud | unauthorized | not_received | not_as_described | duplicate | other",
  "asserted_by": "merchant | payer | issuer | vendor | other",
  "merchant_position": "One-sentence merchant statement; context, not proof."
}
```

Field notes:

- `category` — generic dispute category, not a card-network field name.
- `asserted_by` — who is making the category claim.
- `merchant_position` — the merchant's plain-language position. This is
  presentation/context and must not be treated as cryptographic evidence.

The case block is sealed by `bundle_id`, so the merchant position is
tamper-evident even though it is not independently proven.

## README limitations

The root README and `packages/verify/README.md` now state:

- **Case-to-chain linkage is merchant-attested, not proven.** The bundle proves
  the signed/anchored record; the merchant's order/PSP records must connect that
  record to the card-network transaction.
- **Field-level redaction is not supported in v1.** An `arca/1` envelope hash
  covers the whole signed subtree; disclosure selects whole envelopes and whole
  payload preimages. Field-level redaction would require a new commitment at
  signing time.
- **Offline mode proves integrity, not anchor presence.** Without a Base RPC,
  `anchor_tx_on_chain` is `null`; the bundle's calldata is checked for internal
  consistency, not for on-chain existence.

## #1 implementation and exit criteria

Implemented:

- `src/disclose.ts` — `discloseRange`, D1 adapter, anchor calldata encoder.
- `packages/verify/src/disclosures.ts` — `verifyDisclosures`, per-check output,
  pinned trust, offline/online anchor handling.
- `packages/verify/src/trust.ts` + `trust/*.json`.
- `test/disclose.test.mjs` — the exit-criteria matrix.
- `packages/verify/test/trust.test.mjs` — trust JSON/constants and opt-in check.

Exit-criteria matrix:

| # | Case | Expected |
|---|---|---|
| 1 | Single event | One range disclosure plus anchored before/after boundaries; valid. |
| 2 | Contiguous range | All seqs present and linked; valid. |
| 3 | Cross-epoch range | Two anchor epochs, both proofs verify; valid. |
| 4 | Odd-leaf tree | 5-leaf epoch, duplicated self sibling; valid. |
| 5 | Before/after boundaries | Both links verify; valid. |
| 6 | Tampered sibling | `MERKLE_PROOF_INVALID`. |
| 7 | Missing event | Builder returns 404 `MISSING_EVENTS`. |
| 8 | Unanchored event | Builder returns 409 `UNANCHORED_EVENTS`. |
| +1 | Swapped key | `RECORDER_KEY_MISMATCH`. |

The selective-disclosure primitive is envelope-level: it discloses whole
signed envelopes and (via the caller) whole payload preimages. It does not
redact fields.

## #2 exit criteria

`test/evidence.test.mjs` covers:

| Case | Expected |
|---|---|
| Pre-change `arca/1` envelope with no `kind` | hashes and signature verify unchanged |
| Pre-change `sheaf-bundle/1` fixture | legacy `verify()` still valid |
| Three schemas | strict JSON, `additionalProperties:false`, fixtures validate |
| Mandate/delegation/consent round-trip | `inputs_hash == sha256:JCS(document)` |
| Three events on one chain | mandate → delegation → consent link correctly |
| Mismatched mandate document | `EVIDENCE_DOC_HASH_MISMATCH` |
| Optional document signature | verifies when present; `null` when absent |
| Unknown/missing fields | strict validation rejects |

The odd-leaf disclosure test uses a **5-leaf** epoch; the 5th leaf is the odd
node and its proof carries its own hash as the right sibling.

## #1 online fetch hosts

`npm test` proves the online dispute-mode path through a stubbed `fetch`. The
only hosts the verifier is designed to contact are:

- the caller-supplied `base_rpc` URL, for `eth_chainId` and
  `eth_getTransactionByHash`;
- nothing else. `recorder.public_key_url` is never fetched.

The tests assert both the RPC method calls and that `public_key_url` is not
contacted.
