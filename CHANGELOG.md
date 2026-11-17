# Changelog

All notable changes to Sheaf packages and the recorder Worker.

## 2026-11-17 — SECURITY (S1): recorder no longer manufactures principal signatures

**Bug:** `sheaf local export` signed the mandate, delegation and consent with
the local ledger (recorder) key, and labelled the delegation root
`principal_signature`. The verifier accepted it as `VALID (complete)` with no
evidence gaps, so a recorder signature was presented as the principal's
authorisation. The hosted bundle builder also inferred `principal_signature`
from the mere presence of a signature, whatever key made it.

**Fix:**
- `src/local.ts`: local export copies case documents **without signing**.
  It refuses recorder-signed documents (`RECORDER_SIGNED_NOT_PRINCIPAL`) and
  documents whose signature no longer verifies (`DOCUMENT_SIGNATURE_INVALID`).
  The root attestation is derived from a real principal signature, otherwise
  `recorder_observed`.
- New `sheaf local sign-document <doc> --key <principal.pem> --key-id <id>`
  signs with a principal-held key. It refuses the ledger key and pinned
  recorder keys (`SIGNING_KEY_IS_RECORDER_KEY`).
- `src/dispute.ts` (builder): a recorder-key signature is never inferred as
  principal or policy authorisation. An explicit such claim fails the build.
- `@sheafhq/verify`: a document signed with any known recorder key (the
  bundle's own, pinned or `--trust`) counts as **unsigned**. The evidence gap is
  added and `complete` is false. The new additive `warnings[]` field and
  formatter lines report `authorisation: recorder-attested only` and
  `warning: RECORDER_SIGNED_NOT_PRINCIPAL [...]`.
- **Historical evidence is preserved:** old bundles stay `valid` for
  integrity; only the authorisation claim is downgraded (`VALID (partial)`).
- `dispute-verify.html` rebuilt with the fix.
- `scripts/build-dispute-verifier.mjs`: a replacer function instead of a
  replacement string. `$`-patterns in the minified JS were splicing template
  text into the script.

**Security review follow-ups (same day):**
- **Key-spelling bypass, fixed.** Classification first compared base64
  *strings*. Lenient decoding (missing padding, whitespace, non-zero padding
  bits) gave one recorder key several spellings that all verified, so a
  re-spelled recorder key classified as a principal key and the legacy bundle
  went back to `VALID (complete)`. Now:
  - document signatures must be canonically encoded, or
    `EVIDENCE_DOC_SIGNATURE_INVALID`;
  - every key comparison (verifier, builder, local export, `sign-document`)
    uses raw key bytes;
  - `key_id` never influences classification.
- **Keyless signatures (strict Ed25519).** Measured: native WebCrypto Ed25519
  (Node 22 / OpenSSL 3.5.9, Node 24 / OpenSSL 3.5.5, Edge 157) enforces S < L
  but **accepts small-order public keys**. The identity key (also in its
  non-canonical spellings) verifies R = identity, S = 0 for every message, so
  any document could carry a "valid" signature with no private key at all.
  `verifyEd25519` now applies a strict profile first, in every runtime:
  canonical, on-curve, non-small-order A and R, and S < L.
  `decodeEd25519Point` no longer mutates its input (`Buffer#slice` is a view).
- **Unverified root attestations.** A `delegation.root.attestation` claiming
  `principal_signature` was accepted on its label. It now counts only when
  backed by a verified signature in the bundle (same key bytes and identical
  signature). Otherwise it adds `ROOT_ATTESTATION_UNVERIFIED` and the
  `delegation_root` gap.
- **Unrecognised keys are never authenticated principals.** New result fields:
  - `authorisation`: `verified | unauthenticated | recorder_attested | absent |
    not_evaluated`, printed on line 2 of every report;
  - `signatures[]`, one per document, with `cryptographically_valid`,
    `key_class` (`recognised_recorder | unrecognised | trusted_signer`),
    `expected_party` and `principal_authenticated`.

  `verified` is only reachable through relying-party signer pins
  (`trusted_signers` / `--signers`, schema `sheaf.trusted-signers/1`), each
  bound to a party, role and time window. Recorder keys can never be pinned.
  The new CLI flag `--require-verified-authorisation` fails closed otherwise.
  `complete` keeps its meaning (evidence present and signed by a non-recorder
  key), so historical bundles keep their evidence verdict. The terminology is
  defined in `packages/verify/README.md`, and the browser trust mechanism in
  `packages/verify/trust/README.md`.
- **Tests:**
  - `test/s1-review.test.mjs`: 43 tests with 29 deterministic adversarial
    variants from `test/s1-variants.mjs`. They cover multiple, mixed, unknown,
    array and extra signatures, renamed key IDs, re-spelled keys, forged
    roots, self-generated keys, keyless and weak keys, malleated S,
    small-order R, and signer pins (valid, wrong party, wrong role, expired,
    unbacked root, recorder key, weak key).
  - They also cover the strict-Ed25519 vectors, determinism, CLI equivalence,
    the fail-closed flag, and wording.
  - The browser suite checks every variant for byte-identical CLI/browser
    output, plus keyless rejection in Edge.

**Behaviour change:** local exports without principal signatures are now
`VALID (partial)`, not `VALID (complete)`. Every report now has an
`authorisation:` line 2 and per-document `signature [...]` lines. Signatures
on small-order keys, non-canonical points or small-order R are now invalid.
See `docs/AUTHORING.md`.

**Tests:**
- `test/local-signing.test.mjs`: 9 tests, including a genuine legacy fixture
  made by the pre-fix code (`test/fixtures/s1/`).
- `test/browser.test.mjs`: 2 browser parity tests.
- `test/local.test.mjs` now signs with a principal key; this is the one
  intentional expectation change.

## 2026-11-17 — Favicon + Reference Simulation (whitepaper)

- Added `src/favicon.svg` (a clump of tall grass: five tapered, swaying
  blades from one base, back blades dimmer; acid `#c8ff6a` on `#0a0b0d`;
  deliberately unbound so it doesn't read as fasces) and `GET /favicon.svg`
  (`image/svg+xml`, 1-day cache). Linked from the landing page, whitepaper and
  dispute verifier (template + built file). Added an `.svg` Text rule to
  `wrangler.jsonc` and `assets.d.ts`.
- Whitepaper §04 Verification: new "Reference Simulation" subsection
  describing the end-to-end local run (policy-blocked €200 purchase, allowed
  €100 purchase, offline notary, rejected forgeries).
- Not yet: the landing "Watch the Machine Economy Run" section waits until the
  simulation is ported onto `sheaf.policy/1` and pushed to GitHub, so its
  `npm run sim` command and docs link work for visitors. See `AGENTS.md`.
- Added `AGENTS.md` / `CLAUDE.md`: shared rules for the multiple agents
  working on this repo.

## 2026-11-13 — Developer Preview

- Added `PREVIEW_MODE=true` on the Worker. `POST /v1/checkout` returns the
  static preview message; the x402 paywall remains active.
- Added the Developer Preview banner to the landing page, receipt page, chain
  page, and verifier.
- Documented local Stripe test mode with the Stripe CLI and test cards.

## 2026-11-13 — Automated monetization and viral loops

- Extended x402 paywall to `POST /v1/anchor/local` and
  `POST /v1/chains/:chain_id/export` at $0.01 USDC on Base.
- Added x402 payer helpers to `@sheafhq/mcp-recorder` and
  `@sheafhq/mcp-tools`; added `sheaf_buy_bundle` and `sheaf_anchor_local`
  MCP tools.
- Added `POST /v1/checkout` (Stripe Checkout) and
  `POST /v1/webhooks/stripe` (signed webhook, Pro account + API key + Resend
  delivery/outbox). Added the landing "Get an API Key" button.
- Added `/r/:chain_id/:seq` receipt page and the “Verified by Sheaf” footer on
  receipt and verifier pages.
- Added `GET /llms.txt` and an LLM-oriented README Quickstart.
- Stripe/Resend secrets are not present in the deployment; checkout returns a
  structured `stripe_not_configured` response until they are configured.

## 2026-11-13 — Sheaf-Vault S3 compliance gateway

- New `packages/s3-gateway`: Express proxy on port 8080 accepting
  `PUT /:bucket/:key`.
- Streams the request body into SHA-256, forwards to an S3-compatible upstream
  with the AWS SDK, and submits a `storage.write` / `s3.put` event to Sheaf.
- Returns `x-sheaf-chain-id`, `x-sheaf-seq`, `x-sheaf-envelope-hash`, and
  `x-sheaf-file-sha256` on success.
- If the upstream write succeeds but the receipt fails, returns
  `502 sheaf_receipt_failed` with `stored: true`.
- Added package tests with fake S3 and Worker endpoints.

## 2026-11-13 — Sheaf Local sync and Base anchoring

- Added `POST /v1/anchor/local`: verifies a signed local anchor request, anchors
  the Merkle root on Base L2 with the existing anchorer, and records
  `(chain_id, merkle_root, tx_hash, block)` in `local_anchors`.
- Added migration `0004_local_anchors.sql`.
- `sheaf local sync` now POSTs the signed request and writes `.sheaf/anchor.json`.
- `sheaf local export` reuses a matching Base anchor and emits
  `anchor_mode: base`; online verification shows `anchor_on_base ✓`.
- Offline verification remains integrity-only (`anchor_on_base –`).

## 2026-11-13 — Sheaf Local (offline firewall & ledger)

- `@sheafhq/mcp-recorder wrap --local` runs with zero HTTP: local Ed25519 key,
  append-only `.sheaf/ledger.jsonl`, local policy enforcement, and blocked
  events recorded with `result: "blocked"`.
- `sheaf local export --chain-dir ./.sheaf --case ./case.json --out bundle.sheaf`
  verifies the local ledger, builds a local Merkle epoch, signs case documents,
  and emits a standard Dispute Bundle with `anchor.mode: "local"`.
- `sheaf local sync --chain-dir ./.sheaf` stages an anchor request; the Worker
  sync endpoint is intentionally not implemented.
- Added `test:local` and the spawn-based `test:local:e2e`.
- Docs: “Running Sheaf Locally as a Firewall” in `docs/AUTHORING.md`.

## 2026-11-13 — Whitepaper and explanatory banners

- Landing page adds the “A .sheaf file, or it didn't happen.” manifesto banner
  and a `/whitepaper` link.
- Browser verifier adds the zero-dependency trust banner.
- New `src/whitepaper.html` covers the trust gap, MCP interception, signing,
  Merkle batching, Base anchoring, selective disclosure, verification, and
  standards alignment.
- `GET /whitepaper` added to the Worker; the existing `**/*.html` text-module
  rule bundles it.
- Deployed to `https://sheafhq.io`.

## 2026-11-13 — Restore apex landing page

- `sheafhq.io` had no apex DNS record and no Worker custom-domain binding; only
  `api.sheafhq.io` was attached.
- Added `sheafhq.io` as a Worker custom domain. Cloudflare provisioned the apex
  A/AAAA records and certificate.
- `https://sheafhq.io/` and `https://sheafhq.io/verify` now serve the landing
  page and verifier. `www.sheafhq.io` still has no DNS record.

## 2026-11-13 — Agent Firewall live demo

- New Base mainnet demo chain `demo-dispute-firewall-20261113t180116z`:
  policy first, then mandate, delegation, consent, an allowed $129 payment, and
  a blocked $200 payment attempt (`result: "blocked"`, `verdict: "BLOCK"`).
- Epoch 11 anchored in Base block `57016675`, tx
  `0x9862358bd78c6c09ede9550ebb2d159b0f1ad37773eff8735cdb2784a7280575`.
- Exported `test/fixtures/dispute-walking/bundle-policy.sheaf`; local verify is
  `VALID (complete)` with `14/14` checks and `policy_enforced: true`.
- Worker serves `GET /sample-bundle-policy.sheaf`.
- Browser verifier has **Load Standard Bundle** and **Load Firewall Bundle**.
- Landing page adds the **Agent Firewall** / **Active Enforcement** bullet.
- Deployed to `https://api.sheafhq.io`.

## 2026-11-13 — Layer 4: runtime policy enforcement

### @sheafhq/mcp-recorder (0.1.1 → 0.2.0)
- `sheaf.policy/1` strict schema and pure evaluator.
- `--policy <path>` enforcement at the MCP boundary.
- `ALLOW` forwards and records `event.policy`.
- `BLOCK` stops the call, records `result: "blocked"`, and returns structured
  JSON-RPC error code `-32001` / `reason_code`.
- `REQUIRE_APPROVAL` stops the call and returns code `-32002`.
- Policy commitment is queued as the first event (`kind: "policy"`).
- `tools/call` `inputs_hash` now hashes `params.arguments` (not the full params).

### @sheafhq/verify (0.4.0 → 0.5.0)
- `sheaf.policy/1` evaluator/validator.
- Dispute Bundles may include `policy`; new check `policy_enforced` verifies
  policy hash, event application, blocked attempts, and payload constraints.

### CLI
- `sheaf dispute export --policy <path>`.

## 2026-11-13 — Root landing page

- `GET /` now serves a dark-mode HTML landing page with the headline
  “Verifiable evidence for what an AI agent actually did.”, MCP-boundary/Base
  explanation, `Test the Live Verifier` CTA, and GitHub link.
- Machine-readable service manifest moved to `GET /manifest`.
- Deployed to `https://api.sheafhq.io`.

## 2026-11-13 — Public dispute verifier and sample bundle

### Worker
- `GET /verify` now serves the single-file Dispute Bundle verifier.
- `GET /sample-bundle.sheaf` serves the Base-anchored walking-skeleton bundle
  as a JSON attachment.
- `wrangler.jsonc` Text module rules for the inlined HTML and `.sheaf` fixture.
- Deployed to `https://api.sheafhq.io`.

### Browser verifier
- Added a **Load Sample Bundle** button that fetches `/sample-bundle.sheaf` and
  verifies it immediately.
- Default anchor RPC is `https://mainnet.base.org`; `?rpc=` overrides it and
  `?offline=1` gives integrity-only mode.
- Live test: `VALID (complete)`, `anchor_confirmed: true`, no evidence gaps.

## 2026-11-13 — Dispute Bundle authoring workflow (C)

### CLI
- `sheaf dispute init-case <directory>` — scaffolds `case.json`, `documents/`,
  `payloads/`, and `MAPPING.md`.
- `sheaf dispute validate --case <case.json> [--archive events.jsonl]` — strict
  local validation before export, including placeholders, document schemas,
  Ed25519 key/signature lengths, and optional document/payload hash checks.
- `--payload <seq>:<kind>=<path>` export flag added.

### Docs
- `docs/AUTHORING.md` — merchant-facing workflow, RFC 8785 payload hashing,
  `--payload` usage, and the dedicated-anchorer note.

### Tests
- End-to-end init-case → fill → validate → export → verify.
- Document hash mismatch is caught by `validate`.
- `--payload` flags can supply payloads without a case.json payload list.

## 2026-11-13 — Dispute Bundle build #3 + browser verifier

### Recorder / CLI
- `src/dispute.ts` — `buildDisputeBundle` for `sheaf.dispute-bundle/1`;
  `bundle_id` seals every section except itself and `verification`.
- `src/archive.ts` — local JSONL archive reader for `--archive` (zero Sheaf
  network).
- `src/cli.ts` — `sheaf dispute export` / `sheaf dispute verify`, including
  `--offline`, `--strict`, `--self-check`, `--allow-unconfirmed-anchor`, and
  testing-only `--trust`.
- `authorityRef()` helper and `DELEGATION_PARENT_MISMATCH`.

### @sheafhq/verify
- `verifyDisputeBundle` with 13 named checks, `valid`, `complete`,
  `anchor_confirmed`, and `evidence_gaps`.
- Shared `formatDisputeVerification` output used by CLI and browser.

### B
- `dispute-verify.html` — single-file browser verifier; WebCrypto Ed25519;
  drag/drop; default offline; `?rpc=` online mode with CORS caveat.

### Tests
- Local-archive export/verify with zero Sheaf network.
- `BUNDLE_ID_MISMATCH` for every sealed section.
- Consent-removed and unsigned-mandate `valid_partial` cases.
- Real Base mainnet walking skeleton (5 events, tx
  `0x847c6b718e7ebc0ef0efae87f74f10bf58c14ba668832896244dee2bb3a8271a`).
- Playwright headless Chromium byte-for-byte parity with the CLI.

## 2026-11-12 — Dispute Bundle build #2: evidence event layer

### Recorder
- Optional `event.kind`: `tool_call` (default when absent), `mandate`,
  `delegation`, `consent`. Envelope version stays `arca/1`.
- `schemas/` — strict versioned JSON Schemas for
  `sheaf.mandate-document/1`, `sheaf.delegation-document/1`, and
  `sheaf.consent-document/1`.
- `src/evidence.ts` — strict document validation, RFC 8785 hash, optional
  Ed25519 document signature, and `buildEvidenceSubmission()`.
- The recorder is unchanged; it signs whatever it is given.

### @sheafhq/verify
- `verifyEvidenceDocument()` — schema/kind match, document hash binding, and
  optional document signature check.
- New `EVIDENCE_DOC_HASH_MISMATCH` failure for a document that does not hash to
  the event's `inputs_hash`.

### Tests
- Golden pre-change `arca/1` envelope and `sheaf-bundle/1` fixture.
- Three-schema round-trip, hash-linked mandate/delegation/consent chain, strict
  validation, and `EVIDENCE_DOC_HASH_MISMATCH`.

## 2026-11-12 — Dispute Bundle build #1: selective disclosure + pinned trust

### Recorder
- `src/disclose.ts` — `discloseRange` primitive: contiguous window + anchored
  before/after boundaries, one Merkle inclusion proof per event, multi-epoch
  support, D1 adapter.
- No event-schema change and no Worker route yet; this is the primitive only.

### @sheafhq/verify (0.1.2 → 0.2.0)
- `verifyDisclosures(..., { mode: "dispute" })` — opt-in dispute mode; legacy
  `verify()` and `sheaf-bundle/1` behavior unchanged.
- Pinned trust files `trust/recorder-keys.json` and `trust/base-anchorers.json`.
- Fail-closed `UNKNOWN_RECORDER_KEY`, `RECORDER_KEY_MISMATCH`,
  `UNKNOWN_ANCHORER`; never fetches `recorder.public_key_url`.
- Offline mode reports `anchor_tx_on_chain: null`; online mode checks the Base
  tx through a caller-supplied RPC.
- CLI: `--dispute`, `--offline`, `--trust <path>`.

### Tests
- Eight disclosure cases plus cross-epoch, D1-adapter, online-anchor, and
  fail-closed trust cases.
- Swapped-key bundle fails with `RECORDER_KEY_MISMATCH`.

## 2026-11-11 — WP1 custom domain

### Worker (sheaf-recorder)
- Route: `api.sheafhq.io` added as the canonical host. Legacy `sheaf-recorder.goldencalf.workers.dev` kept live (`workers_dev: true`) — no redirect, additive only.
- `GET /` now advertises `canonical_base_url` and `legacy_base_url`.
- `/verify` and `/.well-known/sheaf-public-key` serve identically on both hosts.

### @sheafhq/mcp-recorder (0.1.0 → 0.1.1)
- Default recorder URL list: `[https://api.sheafhq.io, https://sheaf-recorder.goldencalf.workers.dev]`. Primary first, fallback on fetch error.
- `SHEAF_RECORDER_URL` env still accepts a single override; when set, no fallback (trust the user's choice).
- Config field renamed `recorderUrl` → `recorderUrls: string[]`.

### @sheafhq/mcp-tools (0.1.1 → 0.1.2)
- Same fallback behavior and config rename as mcp-recorder.
- All three tools (`sheaf_chain_head`, `sheaf_get_proof_for`, `sheaf_verify_bundle`) report the URL that actually served the response as `source_url`.

### @sheafhq/verify (0.1.1 → 0.1.2)
- CLI tries `https://api.sheafhq.io` first when resolving the recorder public key, falls back to `sheaf-recorder.goldencalf.workers.dev` on error.

## 2026-11-12 — Fix A+B: convert agent 400s on /bundle to actionable retries

### Observed demand signal
Analytics Engine + on-chain data (2026-11-11): ~30 agent requests in 2 hours hit `/bundle` with unsubstituted path templates (`:chain_id`, `{chain_id}`, `:seq`, `{seq}`). Current response was HTTP 400 "seq must be a non-negative integer" — accurate but useless. One agent that did substitute real values paid $0.001 USDC successfully (tx `0xe7cef1076cf92e2326f407a94f1c740b4fcd5de0c8a484ec33388446686787aa` from wallet `0xa1d1c0cf7174...`). First external paid call on either product. Demand exists; the UX was blocking conversion.

### Fix A — concrete working examples in root /
`GET /` now returns a `quickstart.try_this` field with a literal paid-bundle URL, plus per-endpoint `example` fields with real substituted values. Agents parsing the service manifest get working URLs, not patterns to substitute.

### Fix B — detect unsubstituted path parameters at /bundle
Pre-paywall middleware on `/bundle/:chain_id/:seq` now detects five template-placeholder patterns and returns a structured 400 with `you_sent`, `try_this` (a working example URL), and a plain-English `hint`. Agents parsing the error body self-correct on retry.

Four test cases verified live:
- `:chain_id/:seq` → structured 400 with hint
- `{chain_id}/{seq}` → structured 400 with hint
- `smoke-test-1/:seq` (one substituted) → structured 400
- `smoke-test-1/0` → 402 payment-required (unchanged, correct)

### Measurement
7-day window on Analytics Engine: watch the ratio of `/bundle/*` 400s → 402s → 201s. If retries materialize as paid calls, the conversion hypothesis holds and Sheaf audit is the product to double down on.

## 2026-11-12 — Coherence weekend experiment (parallel vertical, zero-promotion test)

Separate primitive from the AI-agent audit product. Shares the Sheaf brand (mathematically — cellular sheaves over pipeline graphs) but has its own buyer (DevOps/platform engineer) and its own distribution (GitHub Actions Marketplace + npm search).

### Reference implementation
- `packages/coherence/cert.py` — 250-line pure-Python coherence engine, zero deps. Builds the cell complex, constructs δ⁰, computes H¹ rank via Gauss-Jordan, reports per-edge seams. Fixtures for coherent and incoherent-artifact-drift cases.
- `packages/coherence/action.yml` — composite GH Action, uses in-tree as `sheafhq/sheaf/packages/coherence@main`.
- `packages/coherence/BLOG.md` — technical writeup, serves as the project's landing page when discovered.

### Passive discovery surfaces
- **npm**: `@sheafhq/coherence@0.1.0` (zero-dep TypeScript port, keywords for sheaf / coherence / cohomology / ci-cd / github-actions / slsa / attestation / provenance).
- **GitHub Actions Marketplace**: dedicated repo `sheafhq/sheaf-coherence-action` with v0.1.0 tag. **One manual publish-click still pending** from Alexander on the release page to add it to the Marketplace catalog.

### Measurement
30-day window. ZERO promotion (no HN, no Twitter, no outreach). If any organic star/fork/install/issue appears, the primitive has a hands-off buyer and we build v0.2 (fan-in fixture + proper sparse SVD + Rust engine). Flat = reconciliation primitive thesis fails.

## 2026-11-11 — WP7b distribution surface

### packages/anchor-action (GitHub Action, new)
- Composite action `sheafhq/sheaf/packages/anchor-action@main`. Inputs: `api-key` (required), `chain-id`, `recorder-url`, `intent`, `write-summary`. Outputs: `verify-url`, `badge-url`, `sheaf-seq`, `envelope-hash`.
- On each workflow run: hashes a canonical JSON of `{repo, run_id, run_number, sha, ref, actor, event_name, workflow, job, started_at}`, submits as a Sheaf event (one event = one run), writes job summary with badge + verify link.
- Default chain: `gh-{owner}-{repo}` (per-repo). Override for shared / cross-repo anchoring.
- Zero runtime deps beyond curl + jq (standard on ubuntu-latest).
- Planned: split to `sheafhq/anchor-action` for GitHub Actions Marketplace listing once API stabilizes.

### packages/claude-plugin (Claude Code plugin, new)
- Installs `@sheafhq/mcp-tools` MCP server (three Sheaf read tools) in Claude Code.
- `.claude-plugin/plugin.json` manifest + `.mcp.json` server config.
- Repo-level `.claude-plugin/marketplace.json` makes the repo discoverable via `/plugin marketplace add sheafhq/sheaf`.
- README documents the pattern for wrapping other MCP servers with `@sheafhq/mcp-recorder` for transparent capture.

## 2026-11-11 — WP7a external anchoring adapters

### @sheafhq/anchor-signet (0.1.0, new)
- CLI `sheaf-anchor-signet`. Reads a Signet `records.jsonl` audit log (default: `~/.signet/records.jsonl`), computes head (record count + last-line hash + whole-file hash), submits one Sheaf event documenting the snapshot. Does not modify Signet state. Positions Sheaf as the neutral anchoring layer above Signet (Apache-2.0 / MIT).
- Smoke-tested against synthetic log on live recorder.

### @sheafhq/anchor-agent-receipts (0.1.0, new)
- CLI `sheaf-anchor-agent-receipts`. Reads an Agent Receipts (obsigna) NDJSON export, extracts W3C VC-shaped head metadata (last `credentialSubject.action` + hash), submits one Sheaf event. Works independently of the obsigna daemon.
- Smoke-tested against synthetic W3C VC log on live recorder.

### Spec check (done before building)
- Agent Receipts: local SQLite + Ed25519, no on-chain anchoring. License undisclosed on landing page. Repo at agent-receipts/obsigna.
- Signet: local JSONL + Ed25519 + SHA-256 hash chain, no blockchain. Apache-2.0 + MIT. Repo at prismer-ai/signet.
- Neither offers third-party public anchoring today. Brief's stop-and-report condition does not apply.

## 2026-11-11 — WP3 anchor metering + limits

### Worker (sheaf-recorder)
- `anchorPending()` groups unanchored events by (account, chain). Chains over their plan's monthly anchor cap are excluded from the epoch — their events stay un-anchored until month rollover or plan upgrade. Recording still succeeds unconditionally; only anchoring is gated.
- `anchor_usage_monthly` incremented per (account, chain, month) on each successful anchor tx.
- Plan caps: free = 30 anchors/chain/month, pro = 720, legacy-public = unlimited (keeps pre-WP2 demo chains anchoring forever).
- `GET /usage` — new. Bearer-authed. Returns `{account_id, plan, month, anchor_limit_per_chain, chains: [{chain_id, anchors_this_month, anchors_remaining, over_quota}]}`.
- `POST /events` response sets `x-sheaf-anchor-usage: N/limit` and (at ≥80%) `x-sheaf-anchor-quota: warning`, (at 100%) `x-sheaf-anchor-quota: exceeded`. Recorder client will surface these in WP6.
- `/admin/anchor` + cron now return `skipped: [{account_id, chain_id, plan, current, limit}]` when some chains were held back.

## 2026-11-11 — WP5 verification page + badge

### Worker (sheaf-recorder)
- `GET /c/:chain_id` — public verification page. Server-rendered HTML: stats (events / on-chain anchors / account), latest anchor details with basescan link, recent 5 events (seq / tool / result / when / anchor), paste-ready badge markdown, in-browser "verify latest anchored event" button that runs `@sheafhq/verify@0.1.2` via esm.sh against a free Base RPC — zero payment, zero signup.
- `GET /badge/:chain_id.svg` — shields.io-style SVG. Green when anchored (`sheaf: N anchors`), grey when unused. Content-Type `image/svg+xml`, 60s cache.
- Both endpoints public and free. No private-chain gating yet (Pro-tier feature, future WP).

## 2026-11-11 — WP2 accounts + chain ownership

### Worker (sheaf-recorder)
- D1 migration `0003_accounts.sql`: `accounts`, `api_keys` (hashed), `anchor_usage_monthly`, `chains.account_id` with backfill to singleton `legacy-public` account.
- `POST /accounts` — new. Creates an account + first API key (shown once). Optional email.
- `POST /events` — chain-ownership check added. New chain requires `Authorization: Bearer <sk_live_...>`. Existing legacy chains (pre-WP2) grandfather unauthenticated writes. Account-mismatch returns 403.
- Acceptance tested: account creation, auth-required new chain, grandfather legacy chain, invalid-key rejection.

### Test account for this session's smoke
- `acct_c9b45092ae73950f` — burned test account; its API key is in this transcript. Not sensitive (test data only).

## 2026-11-11 — self-serve brief rev 2

Pricing axis switched from events/month to anchors per chain per month. See `claude/sheaf-self-serve-brief.md` for the full rev 2 deltas.
