# @sheafhq/anchor-agent-receipts

One-command adapter: anchor an [Agent Receipts (obsigna)](https://agentreceipts.ai) audit log's current head on Sheaf.

```bash
npm install -g @sheafhq/anchor-agent-receipts
export SHEAF_API_KEY=sk_live_...           # from POST /accounts on Sheaf
sheaf-anchor-agent-receipts                # reads ~/.obsigna/receipts.jsonl by default
```

The adapter reads a JSONL export of your Agent Receipts log, computes its current head (receipt count + last-receipt hash + whole-file hash), and submits a single Sheaf event documenting that snapshot. Sheaf's recorder then signs it, hash-chains it, and includes it in the next on-chain anchor on Base mainnet.

Result: your Agent Receipts log gets a public, third-party-verifiable timestamp proving "this log was at this state at this time."

**Note:** Agent Receipts stores receipts primarily in SQLite (`receipts.db`). You need a JSONL export to anchor. Either configure obsigna to append-write a NDJSON log, or export via its CLI, or pipe `sqlite3 receipts.db` output through `jq` into a JSONL file before running this adapter.

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--log <path>` / `AGENT_RECEIPTS_LOG` | `~/.obsigna/receipts.jsonl` | Path to a JSONL / NDJSON export of receipts |
| `--chain <name>` / `SHEAF_CHAIN_ID` | `agent-receipts-<host>-<logname>` | Sheaf chain to append to |
| `SHEAF_API_KEY` | — (required) | Sheaf account API key |
| `SHEAF_RECORDER_URL` | `https://api.sheafhq.io` (falls back to workers.dev) | Recorder override |

## Example output

```
chain:        agent-receipts-myhost-receipts
log:          /home/me/.obsigna/receipts.jsonl
receipts:     42
last hash:    c3e4f5a6b7c8…
last action:  file.write
seq:          1 (prev 26795706c197…)

anchored at Sheaf seq=1 hash=7f8e9d0c1b2a…
anchor quota: 2/30
verify:       https://api.sheafhq.io/c/agent-receipts-myhost-receipts
```

## Scheduling

Hourly anchor via cron:

```cron
0 * * * * SHEAF_API_KEY=sk_live_... /usr/local/bin/sheaf-anchor-agent-receipts >> /var/log/sheaf.log 2>&1
```

Free-tier Sheaf accounts get 30 anchors per chain per month (~daily cadence).

## Relationship to Agent Receipts

Agent Receipts (obsigna) is a standalone W3C Verifiable Credential audit layer by the agent-receipts/obsigna project. It does not require Sheaf and anchoring is entirely optional. This package is maintained independently; it does not modify receipts, signatures, or the obsigna daemon.

## License

MIT.
