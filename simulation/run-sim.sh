#!/usr/bin/env bash
# Agent Economy in a Box: POSIX launcher (Linux, macOS, WSL).
# Usually invoked via `npm run sim` from the repo root; args pass through:
#   bash simulation/run-sim.sh --agent mock --keep-state
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.foundry/bin:$PATH"

command -v node >/dev/null || { echo "node not found (install Node.js 22.12+)"; exit 2; }
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=12)?0:1)' || {
  echo "Node.js $(node -v) is too old: the recorder runs under wrangler 4, which needs Node.js 22.12+"; exit 2; }
command -v anvil >/dev/null || {
  echo "anvil not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
  exit 2
}

# The repo root provides wrangler (the recorder Worker runs from src/).
if [ ! -e node_modules/wrangler ]; then
  echo "installing repo dependencies (npm install)..."
  npm install --no-fund --no-audit
fi
# The simulation has its own dependencies: the published
# @sheafhq/mcp-recorder@0.3.0 firewall, @sheafhq/verify and tsx.
if [ ! -e simulation/node_modules/@sheafhq/mcp-recorder ] || [ ! -e simulation/node_modules/tsx ]; then
  echo "installing simulation dependencies (npm install --prefix simulation)..."
  npm install --prefix simulation --no-fund --no-audit
fi

cd simulation
exec node --import tsx run-sim.ts "$@"
