# Development

Running the recorder Worker locally. Build, test and deploy from Linux or WSL:
`wrangler`/`workerd` do not run on Windows ARM64. Wrangler 4 needs Node 22.12+.

Stripe checkout / email secrets (set with `wrangler secret put`):
`STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`,
`RESEND_API_KEY`, and optional `RESEND_FROM`. Without them,
`POST /v1/checkout` returns `503 stripe_not_configured` rather than a fake
checkout URL.

## Test-mode Stripe checkout

Production currently runs `PREVIEW_MODE=true`, so `/v1/checkout` returns the
Developer Preview response. To exercise the real Stripe path locally, set
`PREVIEW_MODE=false` in `.dev.vars`.

```bash
# 1. Local D1 schema.
npx wrangler d1 migrations apply arca-events --local

# 2. Local secrets (never commit .dev.vars).
cat > .dev.vars <<'EOF'
PREVIEW_MODE=false
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PRICE_ID=price_...
STRIPE_WEBHOOK_SECRET=whsec_...
RESEND_API_KEY=re_...
EOF

# 3. Start the Worker on 8787.
npx wrangler dev --port 8787

# 4. In another terminal, forward Stripe test events.
stripe login
stripe listen --forward-to localhost:8787/v1/webhooks/stripe
```

Use the `whsec_...` printed by `stripe listen` as `STRIPE_WEBHOOK_SECRET`.
Trigger the event with:

```bash
stripe trigger checkout.session.completed
```

Test cards in Stripe Checkout:

- `4242 4242 4242 4242` — successful payment.
- `4000 0000 0000 3220` — 3D Secure authentication required.
- `4000 0000 0000 9995` — declined.

After `checkout.session.completed`, the Worker creates a Pro account, generates
an API key, and attempts Resend delivery. With no Resend key, the email is
queued in `email_outbox`; inspect it with:

```bash
npx wrangler d1 execute arca-events --local \
  --command "SELECT email, subject, created_at, error FROM email_outbox ORDER BY id DESC LIMIT 5"
```

Do not return the API key in the webhook response; it is only sent by email or
queued in the outbox.

x402 paid endpoints (USDC on Base):

| Method | Path | Price |
| --- | --- | --- |
| `GET` | `/bundle/:chain_id/:seq` | $0.001 |
| `POST` | `/v1/anchor/local` | $0.01 |
| `POST` | `/v1/chains/:chain_id/export` | $0.01 |

Autonomous agents use `createX402Payer` + `paidFetch` from
`@sheafhq/mcp-recorder`; see `llms.txt` for the exact code.
