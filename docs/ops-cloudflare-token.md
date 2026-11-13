# Cloudflare API token scopes for Sheaf ops

Root cause of the 2026-11-12 D1 workaround (the "add a Worker endpoint because the token can't query D1 directly" incident): the token that deploys the Worker was created via the `Edit Cloudflare Workers` template, which does **not** include D1 query permission. Direct `wrangler d1 execute --remote` returns HTTP 7403.

Fix: use a custom token with the full scope set below.

## Required scopes

Create at https://dash.cloudflare.com/profile/api-tokens → **Create Token** → **Create Custom Token**.

| Permission group | Resource | Access | Why |
| --- | --- | --- | --- |
| Account | Workers Scripts | Edit | `wrangler deploy` |
| Account | Workers Scripts | Read | `wrangler whoami`, script introspection |
| Account | Workers Tail | Read | `wrangler tail` for live logs |
| Account | **D1** | **Edit** | **`wrangler d1 execute --remote`, migrations, incident queries** |
| Account | Account Settings | Read | Account metadata needed by wrangler |
| Account | Account Analytics | Read | Analytics Engine SQL API (`/analytics_engine/sql`) |
| Zone | DNS | Edit | Custom domain route provisioning (`routes[].custom_domain: true`) |
| Zone | Zone | Read | Zone discovery for the custom domain |
| User | User Details | Read | `wrangler whoami` |

**Account Resources:** limit to the single Sheaf-owning account (not "All accounts").

**Zone Resources:** limit to `sheafhq.io` (not "All zones").

**TTL:** no expiration. If you prefer expiration, use 1 year and rotate annually; shorter cycles pay too much in friction for a tool used on every deploy.

## Verification

After creating the token, confirm each capability works:

```bash
export CLOUDFLARE_API_TOKEN=<new-token>
cd ~/sheaf

# Workers deploy path
npx wrangler whoami

# D1 query path (was broken with Edit-Cloudflare-Workers template)
npx wrangler d1 execute arca-events --remote --command="SELECT 1 AS alive"

# Analytics Engine path (already worked under the old token)
curl -sS -X POST \
  "https://api.cloudflare.com/client/v4/accounts/a525e839bf274216e8faf5f960b13007/analytics_engine/sql" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -d 'SELECT 1'

# DNS route path (dry-run equivalent: list zones)
curl -sS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=sheafhq.io" | python3 -m json.tool
```

All four should return non-error responses.

## Rotation protocol

When rotating this token:
1. Create the new token first (both can be active simultaneously).
2. Update your local shell env + any CI secrets.
3. Verify with the four commands above.
4. Revoke the old token at https://dash.cloudflare.com/profile/api-tokens.

Never pre-revoke before creating the replacement — a long deploy window with no working token is worse than a short overlap window with two active tokens.

## Why not scope-down further

The temptation is to split into deploy-only vs ops-only tokens. For a one-person project, the overhead of maintaining two tokens exceeds the risk reduction. If the project grows (multiple ops people), split then — one token per human — and shorten TTLs.
