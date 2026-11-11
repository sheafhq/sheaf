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
