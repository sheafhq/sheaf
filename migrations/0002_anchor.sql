-- Phase 3: Merkle epochs + on-chain anchor records.

CREATE TABLE IF NOT EXISTS epochs (
  epoch_id INTEGER PRIMARY KEY,
  merkle_root TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  first_received_at INTEGER NOT NULL,
  last_received_at INTEGER NOT NULL,
  sealed_at INTEGER NOT NULL,
  anchor_tx_hash TEXT,                  -- null until on-chain tx confirmed
  anchor_block INTEGER,
  anchor_submitted_at INTEGER,
  anchor_confirmed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_epochs_sealed ON epochs(sealed_at);
