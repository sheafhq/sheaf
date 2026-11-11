# Sheaf self-serve: build brief for Claude Code

Written 2026-11-11 (rev 1). Owner: Alexander. Read this whole file before changing anything.

**Rev 2 (same date):** Pricing axis, WP order, funnel, and quality bars revised after DeepSeek critique (see "Rev 2 deltas" at end for audit trail). Changes marked `[rev2]` inline.

## Goal

Turn Sheaf from a free recorder with a $0.001 pay-per-bundle endpoint into a product a developer can find, install, hit a limit on, and pay for by subscription, with no human contact at any step.

Success gate `[rev2]`, split by week for diagnosis instead of one 8-week check:

| Week | Question | Pass signal | What a failure diagnoses |
|---|---|---|---|
| 2 | Did anyone find us? | 20+ installs from registries / plugin marketplace | Distribution problem — listing metadata is wrong |
| 4 | Did anyone wire us in? | 5+ chains with ≥3 anchors | Product problem — doesn't fit a workflow |
| 6 | Did anyone hit the limit? | 3+ users hitting the free anchor cap | Free tier too generous, or usage too low |
| 8 | Did anyone pay? | 3+ paying accounts | Pricing or value problem |

Collapsing into one gate tells you something failed but not what.

## What exists (do not break)

- Cloudflare Worker (Hono) + D1 at `sheaf-recorder.goldencalf.workers.dev`; tables `events`, `chains`, `epochs`.
- Custom domain `api.sheafhq.io` added (WP1 in progress) — workers.dev stays live.
- 15-minute cron that Merkle-batches events and anchors the root on Base mainnet.
- npm packages `@sheafhq/mcp-recorder`, `@sheafhq/mcp-tools`, `@sheafhq/verify`.
- x402 paid endpoint `GET /bundle/:chain_id/:seq` (per-bundle, $0.001). Stays as the free-tier escape hatch for ad-hoc bundle generation.

Hard constraints:

1. The wire format `arca/1`, the bundle format `sheaf-bundle/1` and the anchor calldata layout are frozen. Every receipt and bundle issued so far must still pass all seven `@sheafhq/verify` checks.
2. The recorder stays fail-open. No billing, quota or network failure may ever break or delay the agent's tool call. **Recording and verification are always free and unlimited. Metering lives on anchoring, not on event ingestion.** `[rev2]`
3. Verification stays free and works offline, with no account.
4. The existing workers.dev URLs keep working after the custom domain is added.
5. Never put secrets in the repo. Alexander sets them with `wrangler secret put`.

## Plans `[rev2]` — meter on anchors per chain per month, not events

Anchoring cost is driven by epoch frequency, not event count. A 50-event chain anchoring every 15 min costs more L2 gas than a 50,000-event chain anchoring daily. Metering by anchors aligns price with cost and gives a developer-readable cap: "you've hit 30 anchors this month."

| | Free | Pro ($29–49/month, price TBD) | Compliance (waitlist, see WP8) |
|---|---|---|---|
| Anchors per chain per month | 30 (~daily) | 720 (~hourly) | Unlimited |
| Event recording | unlimited | unlimited | unlimited |
| Retention of proofs and envelopes | 7 days of unanchored events; anchored proofs kept forever | 90 days of unanchored events; anchored proofs kept forever | 1 year unanchored + yearly export |
| Chains | 1, public | 10, public or private | unlimited |
| Verification page and badge | yes | yes | yes |
| Ad-hoc paid bundle download (x402 $0.001) | yes | included free | included free |
| Monthly evidence export (JSON + printable HTML) | no | yes | yes + 1yr tape |
| Private chains (read token needed to fetch envelopes) | no | yes | yes |

Anchor over-quota behavior: recording continues; chain accumulates unanchored events; the *next scheduled anchor* skips the chain until month rollover or upgrade. No events are lost.

The Compliance tier's waitlist CTA must name the regulation to be meaningful: **"Join waitlist for the compliance pack (EU AI Act Article 12 evidence export)"**. Do not build the Compliance product itself.

## Work packages, revised order `[rev2]`

Order changed per DeepSeek: the public verification page is distribution, not marketing. Build it after accounts land but before the money loop.

Finish each one with tests passing and a short note in `CHANGELOG.md` before starting the next.

### WP0. Recon — ✅ delivered 2026-11-11.

### WP1. Custom domain — in progress
Worker routed on `api.sheafhq.io`. `/.well-known/sheaf-public-key` served on both hosts. Package defaults updated to the new URL with workers.dev as fallback after DNS confirms live.

### WP2. Accounts, keys, chain ownership
- D1 migrations: `accounts`, `api_keys` (store only a hash), `chains.account_id`, `anchor_usage_monthly(account_id, chain_id, month, anchor_count)` `[rev2]`.
- `POST /accounts` creates an account and returns an API key once. Email is optional.
- New chains require an API key. Existing chains grandfathered onto a `legacy-public` singleton account with no key issued (public read, no new writes via normal path).
- Done when: a new chain cannot be written without its owner's key, old chains still accept events, pre-existing demo chains still serve reads.

### WP5. Public verification page + badge `[rev2 — promoted]`
Built here because it is the distribution primitive. Badges without a page to land on are useless.
- `GET /c/:chain_id`: chain status, event count, latest anchored epoch with explorer link, in-browser verify button that drops a bundle from this chain into the verifier. Private chains show status and anchor count only; never envelopes.
- `GET /badge/:chain_id.svg`: "tool calls anchored by Sheaf". Links to `/c/:chain_id`, not to a signup page `[rev2]`.
- Every page footer links to signup.
- Page must be fast, correct, and obviously useful to someone who has never heard of Sheaf. Build this before any generated pages or site.

### WP3. Metering, limits, anchor-cap behavior `[rev2 — scope changed]`
- Count anchors per account per chain per calendar month via `anchor_usage_monthly`. Increment inside `anchorPending` when a chain's events are included in a sealed epoch.
- Over the free limit, the cron skips that chain in the next epoch. Chain accumulates unanchored events until month rollover or upgrade.
- `POST /events` **always accepts** — recording is never gated. Over-quota accounts see a `x-sheaf-anchor-quota: exceeded` response header + a one-time stderr warning via the recorder client.
- Warn on stderr at 80% of the anchor limit.
- No "gap event" primitive needed here — the honest-about-the-hole semantic is served by the chain's visible backlog of unanchored events.

### WP4. Stripe billing
- Stripe Checkout for Pro, webhook to set the plan, customer portal link for cancel and card changes. Build and test in Stripe test mode only.
- `GET /upgrade?account=...` redirects to Checkout.
- Stripe Tax on, seller is the legal entity Alexander names.
- Done when: a test-mode payment flips an account to Pro within a minute, and a cancellation flips it back at period end.

### WP6. One-command onboarding
`npx @sheafhq/mcp-recorder init`:
1. Creates an account and stores the key in a local config file with user-only permissions.
2. Asks one optional question, "What are you auditing agents for?"
3. Prints ready-to-paste MCP config for Claude Code and Claude Desktop wrapping an existing server.
4. Prints the verification page URL and badge markdown.

After every successful event submission the CLI prints the chain's `/c/:chain_id` verification URL as a one-liner `[rev2]` — the CLI equivalent of a badge.

Done when: a clean machine goes from nothing to a first anchored event in under five minutes using only the README.

### WP7a. Adapters for competing anchoring consumers `[rev2 — before generated pages]`
Publish `@sheafhq/anchor-agent-receipts` and `@sheafhq/anchor-signet`. These are thin tools that read chain heads from Agent Receipts (agentreceipts.ai) and Signet (prismer-ai/signet) and anchor them via Sheaf's recorder.

First read their current specs and licenses. **If either already offers third-party public anchoring, stop and report** — that changes the plan.

Positions Sheaf as the neutral anchoring layer rather than a competitor. Costs a weekend. Lives on npm where their users already search.

### WP7b. Distribution packages
- Claude Code plugin that wraps the recorder.
- GitHub Action (`sheafhq/anchor-action`) that anchors a workflow's agent run, drops the bundle as an artifact, posts the verification link in the job summary, and publishes the badge SVG for README embed.

### WP8. Site
- Landing page, pricing page (with the Compliance waitlist tier CTA naming EU AI Act Art. 12), docs.
- `llms.txt` and `ai-catalog.json` on `sheafhq.io` root `[rev2]` — not just the API host. Half your readers are agents; registries and plugin marketplace crawlers look here.
- Generated how-to pages for the most-used MCP servers, **gated by a quality bar** `[rev2]`: every page must contain a working install command, a real verification example, and at least one thing the reader could not get from the competitor's own docs. If a page can't meet that bar, don't publish it. Ten good pages beat fifty thin ones.
- Comparison page against the tools in WP7a, factual and linked. Comparisons invite direct rebuttal from the named competitors; hold to the same quality bar.
- Wording rule: Sheaf "produces evidence that supports" EU AI Act Art. 12, ISO 42001 or SOC 2 work. Never write that it makes anyone compliant.

### WP9. Funnel analytics `[rev2 — staged gates]`
- Record to Analytics Engine: install (init run), first event, first anchor, 80% warning, limit hit, checkout opened, paid, cancelled, repeat-anchor-in-month.
- Weekly staged funnel script that prints the four signals from the Goal gate table as markdown.
- One-question prompt in the Stripe cancellation flow.

### WP10. x402 subscription (last, optional)
Add a per-chain monthly Pro pass payable over x402, and list it in x402 discovery directories. Keep the per-bundle endpoint for free accounts.

## Needs Alexander, not Claude Code

- Buy the domain and point DNS. `[done — sheafhq.io on Cloudflare Registrar, 2026-11-11]`
- Create the Stripe account and set its secrets.
- Decide the Pro price (recommended range $29–49) and which legal entity sells (Manufutura Lda. or another).
- Approve terms of service and privacy policy drafts.
- Approve every outward action before it happens: `npm publish`, production deploy, pull requests to other projects' repos, registry submissions, launch posts.

## Decision confirmed (pre-WP3) `[rev2]`

Public wording for the free tier:

> **Recording and verification always free and unlimited.** Free tier anchors each chain up to 30 times per month (daily cadence). Pro and Compliance scale up anchoring frequency and retention.

Use everywhere: README, root `/` metadata, landing page, pricing page, CLI output. Proofs for events already anchored are never deleted or put behind payment.

## Out of scope

Evidence pack product (beyond the waitlist CTA), dashboards, ZK or selective disclosure, reliability ratings, enterprise SSO, any automated cold email or direct messages, seeded reviews, any token.

---

## Rev 2 deltas (audit trail)

Changes against the 2026-11-11 original brief, applied the same day after DeepSeek strategic critique.

| What changed | Original | Rev 2 | Why |
|---|---|---|---|
| Metering axis | Events per month | Anchors per chain per month | L2 gas is per-epoch, not per-event. Event metering mis-prices high-frequency low-volume chains. |
| Free tier quota | 1,000 events/month | 30 anchors/chain/month, recording unlimited | Match pricing to cost; honor the "recording free forever" promise literally. |
| Gap event design | Required in WP3 | Deferred / likely unnecessary | With anchor-metering, events never fail for quota. Unanchored events are their own honest signal. |
| WP5 order | After WP4 billing | After WP2 accounts, before WP3 metering | Verification page is the distribution primitive, not marketing. Need it before badges exist. |
| WP7 scope | Single item | Split into 7a (adapters first) and 7b (plugin + GH Action) | Adapters are cheapest leverage; ship before generated pages. |
| WP8 generated pages | 20 how-tos | "Ten good pages, quality-gated" | Thin content on a trust product is a credibility problem. |
| WP8 Compliance CTA | "Evidence pack waitlist" | "EU AI Act Article 12 evidence export waitlist" | Specific CTA tests real pain, not generic upsell interest. |
| WP8 discoverability | Mentioned llms.txt once (WP10) | llms.txt + ai-catalog.json on `sheafhq.io` root | Agents are half the audience; cheapest way to be discoverable by the buyer we're targeting. |
| Success gate | Single 8-week check | Four weekly gates diagnosing different failure modes | A miss has to tell you what to fix, not just that something failed. |
| CLI output | Not specified | Print verify URL after every anchor | CLI-user equivalent of the badge. |
| Badge target | Generic signup | `/c/:chain_id` verification page | Page converts better than a pitch. |
