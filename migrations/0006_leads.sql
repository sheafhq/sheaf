-- Developer Preview waitlist (POST /v1/lead). One row per email.
-- Identical to LEADS_DDL in src/leads.ts, which creates the table on first
-- use; this migration is therefore a no-op wherever the Worker already ran.
-- Data minimisation: no IP address or request metadata is stored.

CREATE TABLE IF NOT EXISTS leads (email TEXT PRIMARY KEY, use_case TEXT NOT NULL DEFAULT '', tier_interest TEXT NOT NULL CHECK (tier_interest IN ('local','compliance','dispute','other')), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, submissions INTEGER NOT NULL DEFAULT 1);
