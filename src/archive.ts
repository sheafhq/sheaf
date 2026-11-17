// Local archive reader for the `sheaf dispute export --archive events.jsonl`
// path. The archive is intentionally simple JSONL so a merchant can export it
// from their own storage and the CLI can assemble a bundle with zero network
// calls to Sheaf.

import type {
  DisclosureEpochRow,
  DisclosureEventRow,
  DisclosureSource,
  RecorderIdentity,
} from "./disclose.js";

export type ArchiveMeta = {
  chain_id: string;
  recorder: RecorderIdentity;
  anchorer: string;
  network: string;
  created_at?: string;
};

export type Archive = {
  meta: ArchiveMeta;
  source: DisclosureSource;
  events: DisclosureEventRow[];
  epochs: DisclosureEpochRow[];
};

type ArchiveEventLine = {
  type: "event";
  seq: number;
  envelope: unknown;
  envelope_hash: string;
  epoch_id: number | null;
  epoch_leaf_idx: number | null;
};

type ArchiveLine =
  | ({ type: "meta" } & ArchiveMeta)
  | ArchiveEventLine
  | ({
      type: "epoch";
    } & DisclosureEpochRow);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`archive: ${field} must be a non-empty string`);
  }
  return value;
}

function requireInt(value: unknown, field: string, min = 0): number {
  if (!Number.isInteger(value) || (value as number) < min) {
    throw new Error(`archive: ${field} must be an integer >= ${min}`);
  }
  return value as number;
}

export function parseArchiveJsonl(text: string): Archive {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  let meta: ArchiveMeta | null = null;
  const events: DisclosureEventRow[] = [];
  const epochs: DisclosureEpochRow[] = [];

  for (let i = 0; i < lines.length; i++) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(lines[i]!);
    } catch (err) {
      throw new Error(`archive line ${i + 1}: invalid JSON: ${(err as Error).message}`);
    }
    if (!isRecord(parsed)) {
      throw new Error(`archive line ${i + 1}: object required`);
    }
    const line = parsed as unknown as ArchiveLine;
    if (line.type === "meta") {
      if (meta) throw new Error("archive: duplicate meta line");
      if (!isRecord(line.recorder)) {
        throw new Error("archive meta.recorder is required");
      }
      meta = {
        chain_id: requireString(line.chain_id, "meta.chain_id"),
        recorder: {
          name: requireString(line.recorder.name, "meta.recorder.name"),
          key_id: requireString(line.recorder.key_id, "meta.recorder.key_id"),
          public_key_base64: requireString(
            line.recorder.public_key_base64,
            "meta.recorder.public_key_base64",
          ),
          public_key_url:
            typeof line.recorder.public_key_url === "string"
              ? line.recorder.public_key_url
              : "",
        },
        anchorer: requireString(line.anchorer, "meta.anchorer"),
        network: requireString(line.network, "meta.network"),
        ...(typeof line.created_at === "string"
          ? { created_at: line.created_at }
          : {}),
      };
    } else if (line.type === "event") {
      if (!isRecord(line.envelope)) {
        throw new Error(`archive line ${i + 1}: event.envelope is required`);
      }
      events.push({
        seq: requireInt(line.seq, "event.seq"),
        envelope_json: JSON.stringify(line.envelope),
        envelope_hash: requireString(line.envelope_hash, "event.envelope_hash"),
        epoch_id:
          line.epoch_id === null
            ? null
            : requireInt(line.epoch_id, "event.epoch_id"),
        epoch_leaf_idx:
          line.epoch_leaf_idx === null
            ? null
            : requireInt(line.epoch_leaf_idx, "event.epoch_leaf_idx"),
      });
    } else if (line.type === "epoch") {
      epochs.push({
        epoch_id: requireInt(line.epoch_id, "epoch.epoch_id"),
        merkle_root: requireString(line.merkle_root, "epoch.merkle_root"),
        anchor_tx_hash:
          line.anchor_tx_hash === null
            ? null
            : requireString(line.anchor_tx_hash, "epoch.anchor_tx_hash"),
        anchor_block:
          line.anchor_block === null
            ? null
            : requireInt(line.anchor_block, "epoch.anchor_block"),
      });
    } else {
      throw new Error(`archive line ${i + 1}: unknown type ${String((line as any).type)}`);
    }
  }

  if (!meta) throw new Error("archive: meta line is required");
  if (events.length === 0) throw new Error("archive: no events");
  if (epochs.length === 0) throw new Error("archive: no epochs");

  const sortedEvents = [...events].sort((a, b) => a.seq - b.seq);
  const epochById = new Map(epochs.map((e) => [e.epoch_id, e]));

  const source: DisclosureSource = {
    async listEvents(chainId, fromSeq, toSeq) {
      if (chainId !== meta!.chain_id) return [];
      return sortedEvents.filter((e) => e.seq >= fromSeq && e.seq <= toSeq);
    },
    async getEvent(chainId, seq) {
      if (chainId !== meta!.chain_id) return null;
      return sortedEvents.find((e) => e.seq === seq) ?? null;
    },
    async getEpoch(epochId) {
      return epochById.get(epochId) ?? null;
    },
    async listEpochLeaves(epochId) {
      return sortedEvents
        .filter((e) => e.epoch_id === epochId)
        .sort((a, b) => (a.epoch_leaf_idx ?? 0) - (b.epoch_leaf_idx ?? 0))
        .map((e) => e.envelope_hash);
    },
  };

  return { meta, source, events: sortedEvents, epochs };
}
