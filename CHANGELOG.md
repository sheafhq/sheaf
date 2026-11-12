# Changelog

All notable changes to Sheaf packages and the recorder Worker.

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
