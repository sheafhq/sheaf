# Agent Economy in a Box

An end-to-end, **zero-cloud** simulation of an AI agent spending money under a
budget, with a tamper-evident proof of what it did that a third party can check
on their own.

```
┌────────────┐  MCP   ┌─────────────────────┐  MCP   ┌──────────────────┐
│ buyer agent│ stdio  │ sheaf-mcp-recorder  │ stdio  │ merchant-server  │
│ (LLM/mock) ├───────►│  --local            ├───────►│  buy_premium €100│
└────────────┘        │ (policy firewall)   │        │  buy_enterprise  │
                      └─────────┬───────────┘        │             €200 │
                                │ POST /events       └──────────────────┘
                                ▼
                      ┌─────────────────────┐  anchor tx  ┌──────────────┐
                      │ Sheaf recorder      ├────────────►│ anvil        │
                      │ (real Worker,       │  (chain id  │ (local chain)│
                      │  wrangler dev, D1)  │   8453)     └──────▲───────┘
                      └─────────┬───────────┘                    │ reads tx
                                │ export                         │
                                ▼                                │
                      session.sheaf ──────────────────────► notary.ts
```

> **Developer Preview.** The firewall under test is the real, published
> product: [`@sheafhq/mcp-recorder@0.3.0`](https://www.npmjs.com/package/@sheafhq/mcp-recorder/v/0.3.0)
> with `--local`, installed from npm and launched through its `bin`. The
> simulation contains no firewall code of its own.
>
> **Why 0.3.0 is pinned:** `packages/mcp-recorder` in this repo is 0.4.0, whose
> `--local` is a different mode (an offline ledger driven by a
> `sheaf.policy/1` file). The simulation was built and tested against 0.3.0's
> `--local` (a policy firewall in front of the hosted recorder), so it pins
> that exact published version rather than the source in this repo.

## What this proves

1. **An AI agent can be constrained by a local firewall.** The agent is told
   *"Try to buy the enterprise data. If that fails, buy the premium data."*
   Sheaf Local (`sheaf-mcp-recorder --local`) evaluates every `tools/call` against `buyer-policy.json`
   *before* it reaches the merchant. The €200 enterprise purchase breaks the
   €150 budget rule and never leaves the buyer's machine. The agent gets an
   ordinary MCP tool error, adapts, and buys the €100 premium data. The agent
   does not know a firewall exists and cannot get around it, because the
   firewall sits in the transport, not in the prompt.

2. **What happened can be proven cryptographically.** Every decision, allowed
   *and* denied, becomes a hash-chained envelope that the recorder signs with
   Ed25519. The envelope commits to:
   - `authority`: the SHA-256 of the exact policy document in force
   - `intent`: the decision (`policy:deny:deny-over-budget | invoke tool …`)
   - `inputs_hash` / `outputs_hash`: the tool arguments and the result

   The epoch's Merkle root is anchored in a transaction on a chain (here anvil,
   standing in for Base). Raw arguments never go to the recorder, only hashes.

3. **A third party can verify the proof offline.** `notary.ts` needs only the
   exported `.sheaf` file, an RPC for the anchor chain, and the recorder's
   public key and anchorer address. It never contacts Sheaf, the merchant or the
   agent. It does not take the bundle's word for anything:

   | Check | How |
   |---|---|
   | Each receipt is authentic | `@sheafhq/verify`: anchor tx exists, sent by the authorized anchorer, Merkle root matches, inclusion proof reproduces it, envelope hash = leaf, recorder signature valid, `prev_hash` links |
   | Nothing was hidden (**complete**) | one contiguous run of seqs that starts with `session/open` and ends in a signed `session/close`, which commits to the event count and the head hash |
   | The stated policy is the one enforced | policy document hashes to the `authority` in every signed event |
   | Disclosed amounts are real | raw inputs/outputs re-hash to the signed `inputs_hash` / `outputs_hash` |
   | The firewall decided correctly | the notary re-runs the policy on the disclosed inputs and must get the same allow/deny and rule as the signed intent |

   It passes only if the verdict is **`VALID (complete)`** and
   **`policy_enforced: true`** is both present and re-derived. It then prints a
   Notary Certificate with the timeline:

   ```
   2026-11-16 21:04:03Z  Agent attempted €200 purchase (buy_enterprise_data) -> BLOCKED
                         [deny-over-budget: Amount exceeds the max budget of EUR 150]
   2026-11-16 21:04:03Z  Agent purchased €100 (buy_premium_data) -> ALLOWED
                         [allow-premium-data; order ORD-0001]
   ```

The run also feeds the notary six forged versions of the same bundle and
requires every one to be **rejected**: hiding the blocked attempt, dropping the
close event, rewriting the deny as an allow, editing the disclosed amount,
swapping in a looser policy, and unsetting `policy_enforced`.

## Run it

Prerequisites: **Node.js 22.12+** (the recorder runs under wrangler 4) and
[Foundry](https://book.getfoundry.sh/getting-started/installation) (`anvil`).
From the **repo root**:

```bash
npm install                 # repo deps, including wrangler
npm run sim                 # options: npm run sim -- --agent mock|ollama --keep-state
```

On its first run, `npm run sim` also installs the simulation's own
dependencies (`npm install --prefix simulation`: the pinned firewall,
`@sheafhq/verify` and `tsx`).

`npm run sim` runs `simulation/launch.mjs`, which routes by platform:

- **Linux / macOS / WSL** → `simulation/run-sim.sh`
- **Windows** → `simulation/run-sim.ps1` (PowerShell 5.1 or 7). It uses **WSL**
  when the repo lives on the WSL filesystem or the machine is **ARM64** (workerd,
  which `wrangler dev` needs, has no Windows-ARM64 build). Otherwise it runs
  **natively** on x64 with `node` and `anvil.exe` from `PATH`. Force a mode with
  `npm run sim -- --wsl` / `--native`.

If the clone lives *inside* WSL, run `npm run sim` from a WSL shell, or call
the PowerShell launcher directly:
`powershell -ExecutionPolicy Bypass -File \\wsl.localhost\<distro>\…\simulation\run-sim.ps1`.
`cmd.exe`, which `npm` uses on Windows, can't start in a `\\wsl$` directory.

Each run resolves `@sheafhq/mcp-recorder` by package name and prints where it
came from:

```
firewall: @sheafhq/mcp-recorder@0.3.0 (simulation/node_modules/@sheafhq/mcp-recorder) bin sheaf-mcp-recorder --local
```

Exit code `0` means the notary accepted the honest bundle and rejected every
forgery. Each run leaves three files in `simulation/out/`:

| File | What it is |
|---|---|
| `<chain_id>.sheaf` | The exported session: what the buyer hands to an auditor |
| `<chain_id>.trust.json` | The recorder's public key and anchorer address, i.e. what a real recorder publishes. Kept separate so the notary never takes trust roots from the thing it audits |
| `<chain_id>.anvil-state.json` | The local chain, standing in for Base, whose history is public |

### Re-verify later, as the third party

```bash
cd simulation
anvil --chain-id 8453 --port 18545 --load-state out/<chain_id>.anvil-state.json &
npm run notary -- out/<chain_id>.sheaf --trust out/<chain_id>.trust.json
```

Edit a single byte of the `.sheaf` and run it again to watch it fail.

### Agent brains

- `--agent auto` (default): a local LLM through [Ollama](https://ollama.com) if
  `OLLAMA_HOST` (default `http://127.0.0.1:11434`) answers and has a model
  (`SIM_OLLAMA_MODEL` picks one; it needs tool-calling support, e.g.
  `llama3.1`, `qwen2.5`). Otherwise the deterministic mock agent.
- `--agent mock`: always deterministic. Use this in CI.
- `--agent ollama`: require the local LLM and fail if it is unavailable.

## What runs, and what "zero cloud" means here

| Step | Process | Notes |
|---|---|---|
| a | `anvil --chain-id 8453` | Base's chain id, so the recorder's viem/Base anchoring code runs against it unchanged. Anchorer = anvil dev account #0. State is dumped to `out/` every second. |
| b | `wrangler dev` on `../src/index.ts` | The **real** recorder Worker, with local D1 migrated from `../migrations`. Config is generated in `.state/` with an ephemeral Ed25519 key in `.state/.dev.vars`. Your own `.dev.vars` and D1 state are not touched. |
| c | `merchant-server.ts` | Spawned by `sheaf-mcp-recorder --local --policy buyer-policy.json --wrap …` as its wrapped stdio MCP server. |
| d/e | `agent.ts` → `sheaf-mcp-recorder --local` | MCP client → the product's firewall proxy → merchant. |
| f | `POST /admin/anchor`, then the export | Seals the epoch and anchors it on anvil. The export uses only the free `/events` and `/epoch/:id/proof` reads; the x402-paywalled `/bundle` route is never hit. |
| g | `notary.ts` | Honest bundle plus six forgeries. |
| h | teardown | Kills the anvil and wrangler process trees, including on error or Ctrl-C. `.state/` is deleted on success and kept on failure for the logs. |

Every server binds to `127.0.0.1`. The Worker's x402 facilitator URL points at
a dead local port. With a loopback `BASE_RPC_URL`, the recorder's anchor code
skips its public-mainnet fallback RPCs (`src/anchor.ts`). The only network
access is `npm install`.

## Files

| File | Role |
|---|---|
| `merchant-server.ts` | Mock merchant MCP server (stdio). `buy_premium_data` €100, `buy_enterprise_data` €200. It refuses any call whose `amount` ≠ list price, so the agent can't under-declare to slip past the budget rule. |
| `buyer-policy.json` | `sheaf-policy/1`: deny non-EUR, **deny `amount > 150`**, allow `buy_premium_data`, default deny. |
| `agent.ts` | Buyer agent: MCP client with the Ollama and mock brains. |
| `export-session.ts`, `session-format.ts` | Build the `sheaf-session/1` `.sheaf` file from the recorder plus the firewall's `sheaf-journal/1` journal: N standard `sheaf-bundle/1` receipts, the policy, and disclosures. Exports the latest open→close session. |
| `notary.ts` | Offline auditor + Notary Certificate. Re-evaluates decisions with the policy engine exported by `@sheafhq/mcp-recorder`, the same code that enforced them. |
| `run-sim.ts` | Orchestrator (cross-platform). |
| `launch.mjs` | `npm run sim` entry: routes to `run-sim.sh` or `run-sim.ps1`. |
| `run-sim.sh`, `run-sim.ps1` | POSIX and Windows launchers. |

The firewall and the policy engine are those of the published
`@sheafhq/mcp-recorder@0.3.0` (`dist/local-proxy.js`, `dist/policy.js`).

## The `.sheaf` session format

`sheaf-session/1` wraps standard per-event `sheaf-bundle/1` receipts (the same
shape `GET /bundle/:chain/:seq` serves), so any single receipt can also be
checked with `npx @sheafhq/verify`. On top of them it carries:

- `policy_enforced`: a **claim**; the notary re-derives it, never trusts it
- `policy.document` + `policy.authority`: must match every signed `authority`
- `disclosures[]`: raw tool inputs/outputs plus the firewall's decision, each
  checked against the signed hashes

Disclosures are the buyer's choice. Leave them out and the receipts still
prove that N decisions happened under policy X, in order, with nothing
removed. You only lose the ability to show the amounts.
