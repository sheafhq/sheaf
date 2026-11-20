# AGENTS.md: rules for every agent working on Sheaf

Several AI agents (Claude Code, DeepSeek harness, Codex, Cline, …) work on this
project, often in **different working copies at the same time**. Read this
before you change code, publish a package, or deploy.

## Why this file exists

On 2026-11-17 we found two diverged, **uncommitted** copies of this repo:

- `~/sheaf` (WSL): simulation, `@sheafhq/mcp-recorder` 0.3.0 `--local`
  (already published to npm), anchor fix
- `the production working copy (Windows)`:
  the source of what is LIVE (landing page, whitepaper, Stripe billing,
  dispute verifier, apex domain route) and its own firewall work

GitHub `main` had neither. Deploying from `~/sheaf` would have silently
deleted the live landing page, whitepaper, checkout and verifier. A release
had already gone to npm from a copy that didn't match production.

## The rules

1. **GitHub `sheafhq/sheaf` `main` is the only source of truth.** A local copy
   is a scratch space until its work is committed and pushed.
2. **Start every session with:** `git fetch && git status && git log --oneline -1 origin/main`.
   If your copy is behind, pull. If it holds uncommitted work you didn't make,
   **stop and ask the human**. Never overwrite or "clean up" another agent's work.
3. **Commit early, push often.** Uncommitted work is invisible to every other
   agent. Never leave a session with significant uncommitted changes. If you
   can't push, say so in your final report.
4. **Deploy only from a clean checkout of pushed `main`:**
   `git status` must be empty and `HEAD` must equal `origin/main`.
5. **Before any `wrangler deploy`, diff production against your tree.** Fetch
   `https://api.sheafhq.io/`, `/how-it-works` and `/verify` and compare them with
   `src/landing.html`, `src/how-it-works.html` and `dispute-verify.html`
   (`/whitepaper` 301-redirects to `/how-it-works` since 2026-11-20). If live
   has something your tree doesn't, **do not deploy**: someone deployed from
   elsewhere. Find that source and ask the human.
6. **Publish npm packages only from pushed `main`,** after the release gate
   (`npm test` + `npm run sim`), using `scripts/release/` (see its README).
   Releasable packages: `@sheafhq/mcp-recorder`, `@sheafhq/mcp-tools`,
   `@sheafhq/verify`. Never publish the root or `simulation/`.
7. **Secrets never go in chat, files or commits.** Tokens and 2FA codes are
   entered by the human in a popup dialog. The npm token is DPAPI-encrypted and
   used only through `scripts/release/publish.ps1`; never decrypt or print it.
8. **Windows ARM64 can't run `wrangler`/`workerd`.** Build, test and deploy
   from WSL (Ubuntu). This tree's wrangler 4 needs **Node ≥ 22.12**: use
   `~/.local/node22`. `~/.local/node` (v20) is for `~/sheaf`.
   Deploy only through `scripts/deploy/deploy.ps1 -Mode check|dry-run|deploy`.
   It uses the DPAPI-stored Cloudflare token (`scripts/deploy/cf-token.ps1`);
   never decrypt or print it.
   Push to GitHub only through `scripts/deploy/gh-push.ps1` (fast-forward,
   default `main:main`, `-DryRun` to test). It uses the DPAPI-stored GitHub
   token (`scripts/deploy/gh-token.ps1 -Save|-Status|-Clear`, expires
   2026-12-11); never decrypt or print it.
9. **Leave a trail.** Add a `CHANGELOG.md` entry for anything user-visible,
   and end with a handoff note: what changed, what's committed or pushed, what's
   deployed or published, and what's still open.

## Known conflict (open as of 2026-11-17)

There are **two independent "Sheaf Local" firewalls** in `@sheafhq/mcp-recorder`:

- **production copy, v0.4.0 (unpublished):** `sheaf.policy/1` (`schemas/sheaf.policy-1.schema.json`):
  ALLOW/BLOCK/REQUIRE_APPROVAL with constraints. `--local` = local signing +
  `/v1/anchor/local`. Checked by `@sheafhq/verify` 0.5.0.
- **`~/sheaf`, v0.3.0 (published to npm 2026-11-17):** `sheaf-policy/1`:
  allow/deny rules. `--local` = firewall proxy to the hosted recorder. Used by
  `simulation/`.

**Decision (human, 2026-11-17): the production copy's firewall (0.4.0,
`sheaf.policy/1`) is canonical.** The `~/sheaf` simulation will be ported onto
it, and the `sheaf-policy/1` engine in 0.3.0 retired. Don't build on
`sheaf-policy/1`.
Note that npm `latest` for `mcp-recorder`, `mcp-tools` and `verify` currently
points at versions built from `~/sheaf` (0.3.0 / 0.1.3 / 0.1.3), while the
production copy has 0.4.0 / 0.2.0 / 0.5.0 locally.

## In design: Sheaf Authority Protocol (SAP)

`docs/SAP-ARCHITECTURE.md` is at **revision 2** (2026-11-17): Phase 1 is
approved in principle, and the owner's six requirements are incorporated.
Approved and open decisions are in §19. **Do not implement SAP yet.**

**S1** (§13), the fix for local mode signing principal documents with the
recorder key, is **implemented in this working tree (2026-11-17)** with
regression tests: `test/local-signing.test.mjs` and the S1 cases in
`test/browser.test.mjs`. It is **not yet committed, deployed, or published**.

- **The rule:** never sign mandate/delegation/consent documents with a
  recorder or ledger key. Principals use `sheaf local sign-document`.
- **The fixture:** don't regenerate `test/fixtures/s1/legacy-recorder-signed.sheaf`;
  it is a frozen artifact of the buggy code.
- **The isolated change:** `..\patches\0001-security-S1-*.patch`, outside this
  repo, 23 files, with SHA-256 in `S1-SHA256SUMS.txt`. Commit S1 **on its
  own**, never mixed with other uncommitted work. The patch has been checked
  to apply onto the pre-S1 state of the tree, to reproduce this tree exactly,
  and to pass every suite.

## Working copies (keep this list current)

| Path | Status (update when it changes) |
|---|---|
| `the production working copy (Windows)` | Production source as of 2026-11-17. Being reconciled with `~/sheaf`, then pushed to `main`. |
| `~/sheaf` (WSL) | Simulation + mcp-recorder 0.3.0 work, being merged into the copy above. Not a git repo; do not deploy from it. |

| `~/deploy-staging/sheaf` (WSL) | Throwaway Linux build copy of the production source (rsync without `node_modules`/`.git`). Used for the 2026-11-17 deploy. Re-sync it from the production copy before every deploy; never edit it directly. |

Once both are merged and pushed, every agent should work from a fresh clone of
`main` (or a branch of it) and this table should list only that.

## Deploy log

| When (UTC) | Version ID | From | What | Notes |
|---|---|---|---|---|
| 2026-11-17 | `41446b6b-afe6-4530-a7af-b78c87912522` | production copy → `~/deploy-staging/sheaf` | favicon (`/favicon.svg`, linked on landing/whitepaper/verifier) + whitepaper "Reference Simulation" | **Exception to rule 4**, approved by the human: deployed from uncommitted work. Pre-deploy diff showed live == tree apart from these additions. Smoke test passed (manifest, llms.txt, keys, chain/receipt pages, `/bundle` still 402). |

Still open: commit + push this tree to `main`, port the simulation onto
`sheaf.policy/1`, then add the landing "Watch the Machine Economy Run" section
(its `npm run sim` command and docs link must work for visitors first).
