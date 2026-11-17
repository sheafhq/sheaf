# sheafhq/anchor-action

GitHub Action that anchors every workflow run on-chain via Sheaf. Produces a public verification URL and a badge for your README. Composite action, zero install, no dependencies beyond `curl` + `jq` (preinstalled on runners).

## Quickstart

1. Create a Sheaf account and get an API key — `POST https://api.sheafhq.io/accounts`. Save the `api_key` value (shown once).
2. Add it as a repo secret: **Settings → Secrets and variables → Actions → New repository secret**, name `SHEAF_API_KEY`.
3. Drop this step into any workflow:

```yaml
- uses: sheafhq/sheaf/packages/anchor-action@main
  with:
    api-key: ${{ secrets.SHEAF_API_KEY }}
```

4. First run: the Action creates a chain `gh-{owner}-{repo}` under your account, anchors the run metadata, and writes a verification URL + badge to the job summary.

5. Add the badge to your README:

```markdown
[![Sheaf](https://api.sheafhq.io/badge/gh-your--org-your--repo.svg)](https://api.sheafhq.io/c/gh-your--org-your--repo)
```

(Dashes in chain IDs come from `/` in `{owner}/{repo}` being URL-safe. Replace with your actual repo.)

## Inputs

| Input | Required | Default | Purpose |
| --- | --- | --- | --- |
| `api-key` | yes | — | Sheaf API key. Use `${{ secrets.SHEAF_API_KEY }}`. |
| `chain-id` | no | `gh-{owner}-{repo}` | Override the per-repo chain name. Use e.g. `my-prod-agents` to share one chain across many workflows. |
| `recorder-url` | no | `https://api.sheafhq.io` | Sheaf recorder URL (point to self-hosted or staging for testing). |
| `intent` | no | `github actions workflow run` | Human string stored in the event envelope. |
| `write-summary` | no | `true` | Write badge + verify link to the GitHub job summary. Set `false` for quiet. |

## Outputs

| Output | Example |
| --- | --- |
| `verify-url` | `https://api.sheafhq.io/c/gh-acme-widgets` |
| `badge-url` | `https://api.sheafhq.io/badge/gh-acme-widgets.svg` |
| `sheaf-seq` | `42` |
| `envelope-hash` | `sha256:a1b2c3...` |

Chain them into later steps:

```yaml
- id: anchor
  uses: sheafhq/sheaf/packages/anchor-action@main
  with:
    api-key: ${{ secrets.SHEAF_API_KEY }}

- name: Post verify link
  run: echo "Verified at ${{ steps.anchor.outputs.verify-url }}"
```

## What gets anchored

The event's canonical inputs hash covers:

- Repository (`{owner}/{repo}`)
- Run ID + Run Number
- Commit SHA
- Ref
- Actor who triggered
- Event name (push / pull_request / workflow_dispatch / etc.)
- Workflow name + Job name
- Timestamp (UTC)

Nothing from the workflow's execution (secrets, logs, step outputs) is included. The anchor proves *this run happened at this time with these inputs*, not what it did. Use the output URL to attach additional agent evidence in a follow-up anchor if you're anchoring agent runs specifically.

## Costs

Free tier (Sheaf): 30 anchors per chain per month (~1 per day). Workflows on this repo that run less than daily stay within the free tier; high-frequency CI (e.g., every push on a busy repo) exhausts it fast. See [pricing](https://api.sheafhq.io/) for Pro ($29/mo, 720 anchors/chain/month).

Over-quota anchors are *skipped* by the recorder's cron; the event itself still records to your chain, just doesn't get included in the next on-chain epoch. Chain ownership and signature guarantees unchanged.

## Positioning

Sheaf is MIT-licensed, non-exclusive, and interoperable with other agent audit layers (see `@sheafhq/anchor-signet` and `@sheafhq/anchor-agent-receipts` adapters). This Action is maintained in the main [sheafhq/sheaf](https://github.com/sheafhq/sheaf) repo; it will move to `sheafhq/anchor-action` once we stabilize the API surface and list on the GitHub Actions Marketplace.
