# @sheafhq/anchor-signet

One-command adapter: anchor a [Signet](https://github.com/prismer-ai/signet) audit log's current head on Sheaf.

```bash
npm install -g @sheafhq/anchor-signet
export SHEAF_API_KEY=sk_live_...      # from POST /accounts on Sheaf
sheaf-anchor-signet                   # reads ~/.signet/records.jsonl by default
```

The adapter does not modify your Signet setup or its records. It reads the log, computes its current head (record count + last-line hash + whole-file hash), and submits a single Sheaf event documenting that snapshot. Sheaf's recorder then signs it, hash-chains it, and includes it in the next 15-minute on-chain anchor on Base mainnet.

Result: your Signet log gets a public, third-party-verifiable timestamp proving "this log was at this state at this time."

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--log <path>` / `SIGNET_LOG` | `~/.signet/records.jsonl` | Path to the JSONL audit log |
| `--chain <name>` / `SHEAF_CHAIN_ID` | `signet-<host>-<logname>` | Sheaf chain to append to |
| `SHEAF_API_KEY` | — (required) | Sheaf account API key |
| `SHEAF_RECORDER_URL` | `https://api.sheafhq.io` (falls back to workers.dev) | Recorder override |

## Example output

```
chain:        signet-myhost-records
log:          /home/me/.signet/records.jsonl
records:      847
last hash:    a1b2c3d4e5f6…
seq:          3 (prev 8fb991cd26a6…)

anchored at Sheaf seq=3 hash=d5e4c3b2a1f0…
anchor quota: 3/30
verify:       https://api.sheafhq.io/c/signet-myhost-records
badge:        ![sheaf](https://api.sheafhq.io/badge/signet-myhost-records.svg)
```

## Scheduling

Add to crontab for hourly anchoring:

```cron
0 * * * * SHEAF_API_KEY=sk_live_... /usr/local/bin/sheaf-anchor-signet >> /var/log/sheaf.log 2>&1
```

Or a systemd timer, GitHub Action, etc. Free-tier Sheaf accounts get 30 anchors per chain per month (~daily cadence) — enough for one Signet log checked in daily.

## Relationship to Signet

Signet is a standalone Ed25519/hash-chain attestation layer by prismer-ai (Apache-2.0 / MIT). It does not require Sheaf and anchoring is entirely optional. This package is maintained independently; it does not alter Signet's local state or signatures.

## License

MIT.
