-- WP2: accounts, API keys, chain ownership, anchor usage tracking.
-- Safe to apply after 0001 and 0002. Backfills existing chains to a
-- singleton 'legacy-public' account so pre-WP2 writes keep working.

-- Accounts: one per paying customer (or free user who went through onboarding).
CREATE TABLE IF NOT EXISTS accounts (
  account_id TEXT PRIMARY KEY,
  email TEXT,
  plan TEXT NOT NULL DEFAULT 'free',          -- 'free' | 'pro' | 'legacy-public'
  created_at INTEGER NOT NULL,
  stripe_customer_id TEXT,                     -- set in WP4
  stripe_subscription_id TEXT,                 -- set in WP4
  plan_valid_until INTEGER                     -- unix seconds; null = current
);

-- API keys: multiple per account. Only the SHA-256 hash is stored.
-- Key format shown to the user once: sk_live_<64 hex chars>.
CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY,                   -- sha256(key) hex
  account_id TEXT NOT NULL,
  label TEXT,                                   -- user-provided, optional
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,                           -- null = active
  FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);
CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(account_id);

-- Chain ownership. New column; existing chains backfill to legacy-public.
ALTER TABLE chains ADD COLUMN account_id TEXT;
UPDATE chains SET account_id = 'legacy-public' WHERE account_id IS NULL;

-- Singleton legacy account. No API key will ever be issued for this account;
-- its chains accept events during the WP2 transition period (grandfather),
-- and the anchor-metering in WP3 will treat them as a shared pool.
INSERT OR IGNORE INTO accounts (account_id, email, plan, created_at)
  VALUES ('legacy-public', NULL, 'legacy-public', strftime('%s', 'now'));

-- Anchor usage tracked per (account, chain, calendar month).
-- Incremented inside anchorPending() when an epoch seals events for a chain.
-- Used by WP3 to enforce free-tier anchor cap (30/chain/month default).
CREATE TABLE IF NOT EXISTS anchor_usage_monthly (
  account_id TEXT NOT NULL,
  chain_id TEXT NOT NULL,
  month TEXT NOT NULL,                          -- 'YYYY-MM' format
  anchor_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, chain_id, month)
);
CREATE INDEX IF NOT EXISTS idx_anchor_usage_month ON anchor_usage_monthly(month);
CREATE INDEX IF NOT EXISTS idx_chains_account ON chains(account_id);
