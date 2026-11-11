-- Sheaf event store v1
-- Append-only hash-chained events, keyed by (chain_id, seq).
-- Content-optional: we store the envelope (with hashes) but never the raw
-- tool arguments or responses.

CREATE TABLE IF NOT EXISTS events (
  chain_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,      -- full canonical JSON envelope including signatures
  envelope_hash TEXT NOT NULL,      -- sha256 of canonical envelope w/o signatures (what prev_hash of the NEXT event will reference)
  prev_hash TEXT,                   -- null for seq=0
  actor TEXT NOT NULL,              -- for querying by agent identity
  tool TEXT NOT NULL,               -- for querying by tool
  result TEXT NOT NULL,             -- ok / error / timeout / cancelled
  ts INTEGER NOT NULL,              -- unix epoch seconds (from envelope.event.ts, normalized)
  received_at INTEGER NOT NULL,     -- unix epoch seconds when the recorder received it
  epoch_id INTEGER,                 -- null until Phase 3 anchors this event into a Merkle epoch
  epoch_leaf_idx INTEGER,           -- position within the epoch's Merkle tree
  PRIMARY KEY (chain_id, seq)
);

-- Head of each chain for fast GET /chains/:id/head
CREATE TABLE IF NOT EXISTS chains (
  chain_id TEXT PRIMARY KEY,
  head_seq INTEGER NOT NULL,
  head_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  event_count INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_actor_ts ON events(actor, ts);
CREATE INDEX IF NOT EXISTS idx_events_tool_ts  ON events(tool, ts);
CREATE INDEX IF NOT EXISTS idx_events_epoch    ON events(epoch_id);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);
