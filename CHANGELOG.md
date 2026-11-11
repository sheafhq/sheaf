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
