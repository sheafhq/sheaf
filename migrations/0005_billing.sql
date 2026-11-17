-- Stripe checkout idempotency + email outbox for self-serve Pro keys.

CREATE TABLE IF NOT EXISTS billing_events (
  event_id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  account_id TEXT,
  email TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS email_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  sent_at INTEGER,
  error TEXT
);

CREATE INDEX IF NOT EXISTS idx_email_outbox_pending
  ON email_outbox(sent_at, created_at);
