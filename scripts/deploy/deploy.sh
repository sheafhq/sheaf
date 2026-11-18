#!/usr/bin/env bash
# Deploy the Sheaf Worker from THIS repo checkout (WSL; wrangler 4 needs Node 22).
# Normally invoked by deploy.ps1, which supplies $CLOUDFLARE_API_TOKEN in memory.
#
#   deploy.sh check     wrangler whoami (auth + account only)
#   deploy.sh dry-run   build + validate, upload nothing
#   deploy.sh deploy    wrangler deploy  (PRODUCTION)
#   deploy.sh d1-list   list D1 migrations applied/pending on PRODUCTION (read-only)
#   deploy.sh d1-apply  apply pending D1 migrations to PRODUCTION (run d1-list first)
#
# Read AGENTS.md rules 4-5 before deploying: the live site must not contain
# anything this tree lacks.
set -uo pipefail
MODE=${1:-check}
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$HOME/.local/node22/bin:$HOME/.local/node/bin:$PATH"
export WRANGLER_SEND_METRICS=false

[ -n "${CLOUDFLARE_API_TOKEN:-}" ] || { echo "NO_TOKEN: CLOUDFLARE_API_TOKEN not received"; exit 5; }
cd "$REPO"
[ -d node_modules/wrangler ] || { echo "installing dependencies..."; npm ci --no-fund --no-audit || exit 3; }

echo "node $(node -v), wrangler $(npx wrangler --version 2>/dev/null | tail -1), repo $REPO"
who=$(npx wrangler whoami 2>&1)
if echo "$who" | grep -qiE 'not authenticated|invalid|error'; then
  echo "TOKEN_REJECTED:"; echo "$who" | grep -iE 'error|authenticated|invalid' | head -4; exit 4
fi
# Show the account name/id, never anything token-shaped or e-mail-shaped.
echo "$who" | grep -E '│|\|' | grep -viE 'token|scope' | sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/<email>/g' | head -6

case "$MODE" in
  check)   exit 0 ;;
  dry-run) npx tsc --noEmit || exit 6; npx wrangler deploy --dry-run --outdir /tmp/sheaf-dry-run 2>&1 | tail -25 ;;
  deploy)  npx tsc --noEmit || exit 6; npx wrangler deploy 2>&1 | tail -30 ;;
  d1-list) npx wrangler d1 migrations list DB --remote 2>&1 | tail -30 ;;
  d1-apply) CI=true npx wrangler d1 migrations apply DB --remote 2>&1 | tail -30 ;;
  *)       echo "unknown mode $MODE"; exit 2 ;;
esac
exit ${PIPESTATUS[0]}
