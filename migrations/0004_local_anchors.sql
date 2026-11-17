-- Local mode: anchor roots produced by `sheaf local sync`.
-- The local ledger itself stays on the user's machine; this table is only the
-- public commitment receipt (chain_id -> Base tx).

CREATE TABLE IF NOT EXISTS local_anchors (
  epoch_id INTEGER PRIMARY KEY,
  chain_id TEXT NOT NULL,
  merkle_root TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  public_key_base64 TEXT NOT NULL,
  anchor_tx_hash TEXT NOT NULL,
  anchor_block INTEGER,
  anchor_submitted_at INTEGER NOT NULL,
  anchor_confirmed_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE (chain_id, merkle_root)
);

CREATE INDEX IF NOT EXISTS idx_local_anchors_chain
  ON local_anchors(chain_id, created_at);
CREATE INDEX IF NOT EXISTS idx_local_anchors_root
  ON local_anchors(merkle_root);
