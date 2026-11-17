// Selective disclosure primitive.
//
// Given a chain and a contiguous seq window, return the full signed envelopes
// for that window (plus the adjacent boundary envelopes when they are anchored)
// with one Merkle inclusion proof per disclosed event. The output is deliberately
// unaware of disputes, mandates, or card-network reason codes: it is the
// primitive the Dispute Bundle will wrap.
//
// The primitive does NOT redact fields. An `arca/1` envelope hash covers the
// whole {v,event,chain} subtree, so field-level redaction would invalidate the
// recorder signature. Disclosure chooses *which envelopes* to reveal; payload
// preimages are disclosed separately by the caller and checked against the
// event's inputs_hash/outputs_hash.

import { hashCanonical } from "./canonical.js";
import { buildMerkleTree, inclusionProof } from "./merkle.js";
import type { Envelope } from "./types.js";

export const DISCLOSURE_VERSION = "sheaf-disclosure/1";
export const MAX_DISCLOSURE_EVENTS = 50;

export type EventRef = {
  chain_id: string;
  seq: number;
};

export type RecorderIdentity = {
  name: string;
  key_id: string;
  public_key_base64: string;
  public_key_url: string;
};

export type DisclosureEventRow = {
  seq: number;
  envelope_json: string;
  envelope_hash: string;
  epoch_id: number | null;
  epoch_leaf_idx: number | null;
};

export type DisclosureEpochRow = {
  epoch_id: number;
  merkle_root: string;
  anchor_tx_hash: string | null;
  anchor_block: number | null;
};

/**
 * Storage contract for the primitive. The Worker uses `d1DisclosureSource`;
 * tests and local archives can provide their own implementation.
 */
export type DisclosureSource = {
  listEvents(
    chainId: string,
    fromSeq: number,
    toSeq: number,
  ): Promise<DisclosureEventRow[]>;
  getEvent(chainId: string, seq: number): Promise<DisclosureEventRow | null>;
  getEpoch(epochId: number): Promise<DisclosureEpochRow | null>;
  listEpochLeaves(epochId: number): Promise<string[]>;
};

export type DisclosureProof = {
  type: "merkle-inclusion/v1";
  siblings: Array<{ hash: string; side: "left" | "right" }>;
  root: string;
};

export type Disclosure = {
  event_ref: EventRef;
  envelope: Envelope;
  envelope_hash: string;
  epoch_id: number;
  leaf_index: number;
  proof: DisclosureProof;
};

export type AnchorEpoch = {
  epoch_id: number;
  merkle_root: string;
  tx_hash: string;
  block_number: number | null;
  block_hash: string | null;
  calldata: string;
  explorer: string | null;
};

export type DisclosureSet = {
  version: typeof DISCLOSURE_VERSION;
  chain_id: string;
  from_seq: number;
  to_seq: number;
  recorder: RecorderIdentity;
  disclosures: Disclosure[];
  anchor: {
    /** `local` is an offline Merkle commitment, not a Base transaction. */
    mode?: "base" | "local";
    network: string;
    anchorer: string;
    epochs: AnchorEpoch[];
  };
  before_ref: EventRef | null;
  after_ref: EventRef | null;
  warnings: string[];
};

export type DiscloseOptions = {
  recorder: RecorderIdentity;
  anchorer: string;
  network?: string;
  /** Optional block hashes keyed by epoch id; the primitive itself does not
   *  make RPC calls, so the caller can enrich the artifact with them. */
  blockHashes?: Record<number, string>;
  maxEvents?: number;
  includeBoundaries?: boolean;
};

export type DiscloseFailureCode =
  | "INVALID_OPTIONS"
  | "INVALID_RANGE"
  | "RANGE_TOO_LARGE"
  | "MISSING_EVENTS"
  | "UNANCHORED_EVENTS"
  | "EPOCH_NOT_ANCHORED"
  | "EPOCH_NOT_FOUND"
  | "MERKLE_ROOT_MISMATCH"
  | "INVALID_ENVELOPE";

export type DiscloseFailure = {
  ok: false;
  status: 400 | 404 | 409 | 500;
  code: DiscloseFailureCode;
  error: string;
  detail?: unknown;
};

export type DiscloseResult =
  | { ok: true; disclosure: DisclosureSet }
  | DiscloseFailure;

function fail(
  status: DiscloseFailure["status"],
  code: DiscloseFailureCode,
  error: string,
  detail?: unknown,
): DiscloseFailure {
  return { ok: false, status, code, error, detail };
}

/** Normalize a SHA-256 hash to lowercase 64-hex, accepting `sha256:` and `0x`
 *  prefixes so callers can pass values from either side of the stack. */
export function normalizeHash(value: string): string {
  const clean = value
    .trim()
    .replace(/^sha256:/i, "")
    .replace(/^0x/i, "")
    .toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`invalid SHA-256 hash: ${value}`);
  }
  return clean;
}

/** Encode the live 44-byte anchor calldata:
 *  magic "ARCA" (4 bytes) || uint64 BE epoch id (8 bytes) || root (32 bytes). */
export function encodeAnchorCalldata(epochId: number, rootHex: string): string {
  if (!Number.isInteger(epochId) || epochId < 0) {
    throw new Error(`epoch id must be a non-negative integer, got ${epochId}`);
  }
  const root = normalizeHash(rootHex);
  const epoch = BigInt(epochId).toString(16).padStart(16, "0");
  if (epoch.length > 16) throw new Error(`epoch id does not fit uint64: ${epochId}`);
  return `0x41524341${epoch}${root}`;
}

function refOf(envelope: Envelope): EventRef {
  return { chain_id: envelope.chain.chain_id, seq: envelope.chain.seq };
}

function sortBySeq(rows: DisclosureEventRow[]): DisclosureEventRow[] {
  return [...rows].sort((a, b) => a.seq - b.seq);
}

/**
 * Build the disclosure set. All events in [fromSeq, toSeq] must already be
 * anchored. Adjacent boundary events are included only when they exist and are
 * anchored; an unanchored boundary produces a warning and a null ref, not a
 * hard failure, because the disputed window itself is still fully proven.
 */
export async function discloseRange(
  source: DisclosureSource,
  chainId: string,
  fromSeq: number,
  toSeq: number,
  opts: DiscloseOptions,
): Promise<DiscloseResult> {
  if (
    !opts ||
    !opts.recorder ||
    typeof opts.recorder.key_id !== "string" ||
    typeof opts.recorder.public_key_base64 !== "string" ||
    typeof opts.anchorer !== "string" ||
    !opts.anchorer
  ) {
    return fail(
      400,
      "INVALID_OPTIONS",
      "recorder identity and anchorer address are required",
    );
  }
  if (!chainId || typeof chainId !== "string") {
    return fail(400, "INVALID_RANGE", "chain_id is required");
  }
  if (
    !Number.isInteger(fromSeq) ||
    !Number.isInteger(toSeq) ||
    fromSeq < 0 ||
    toSeq < fromSeq
  ) {
    return fail(
      400,
      "INVALID_RANGE",
      `invalid range: from_seq=${fromSeq}, to_seq=${toSeq}`,
    );
  }
  const maxEvents = opts.maxEvents ?? MAX_DISCLOSURE_EVENTS;
  if (!Number.isInteger(maxEvents) || maxEvents <= 0) {
    return fail(400, "INVALID_OPTIONS", `maxEvents must be a positive integer`);
  }
  if (toSeq - fromSeq + 1 > maxEvents) {
    return fail(
      400,
      "RANGE_TOO_LARGE",
      `range has ${toSeq - fromSeq + 1} events; maximum is ${maxEvents}`,
    );
  }

  const rangeRows = sortBySeq(await source.listEvents(chainId, fromSeq, toSeq));
  const bySeq = new Map(rangeRows.map((r) => [r.seq, r]));
  const missing: number[] = [];
  for (let seq = fromSeq; seq <= toSeq; seq++) {
    if (!bySeq.has(seq)) missing.push(seq);
  }
  if (missing.length > 0) {
    return fail(404, "MISSING_EVENTS", "events missing from range", {
      chain_id: chainId,
      from_seq: fromSeq,
      to_seq: toSeq,
      missing,
    });
  }

  const range = [...bySeq.values()].sort((a, b) => a.seq - b.seq);
  const unanchored = range
    .filter((r) => r.epoch_id === null || r.epoch_leaf_idx === null)
    .map((r) => r.seq);
  if (unanchored.length > 0) {
    return fail(
      409,
      "UNANCHORED_EVENTS",
      "disclosure requires every event in the range to be anchored",
      { chain_id: chainId, seqs: unanchored },
    );
  }

  const warnings: string[] = [];
  const boundaryRows: DisclosureEventRow[] = [];
  if (opts.includeBoundaries !== false) {
    if (fromSeq > 0) {
      const before = await source.getEvent(chainId, fromSeq - 1);
      if (before) {
        if (before.epoch_id === null || before.epoch_leaf_idx === null) {
          warnings.push(
            `before boundary seq ${before.seq} exists but is not anchored; omitted`,
          );
        } else {
          boundaryRows.push(before);
        }
      }
    }
    const after = await source.getEvent(chainId, toSeq + 1);
    if (after) {
      if (after.epoch_id === null || after.epoch_leaf_idx === null) {
        warnings.push(
          `after boundary seq ${after.seq} exists but is not anchored; omitted`,
        );
      } else {
        boundaryRows.push(after);
      }
    }
  }

  // De-duplicate in case the caller asks for a range whose boundary overlaps
  // (not possible with from-1/to+1, but cheap to guarantee).
  const allRows = sortBySeq(
    [...boundaryRows, ...range].filter(
      (row, idx, arr) => arr.findIndex((r) => r.seq === row.seq) === idx,
    ),
  );

  const epochIds = [
    ...new Set(allRows.map((r) => r.epoch_id as number)),
  ].sort((a, b) => a - b);

  const epochCache = new Map<
    number,
    { root: string; levels: string[][]; row: DisclosureEpochRow }
  >();

  for (const epochId of epochIds) {
    const epochRow = await source.getEpoch(epochId);
    if (!epochRow) {
      return fail(500, "EPOCH_NOT_FOUND", `epoch ${epochId} not found`, {
        epoch_id: epochId,
      });
    }
    if (!epochRow.anchor_tx_hash) {
      return fail(
        409,
        "EPOCH_NOT_ANCHORED",
        `epoch ${epochId} has no anchor transaction`,
        { epoch_id: epochId },
      );
    }
    let leaves: string[];
    try {
      leaves = (await source.listEpochLeaves(epochId)).map(normalizeHash);
    } catch (err) {
      return fail(500, "INVALID_ENVELOPE", `epoch ${epochId} has invalid leaves`, {
        epoch_id: epochId,
        message: (err as Error).message,
      });
    }
    const { root, levels } = await buildMerkleTree(leaves);
    let storedRoot: string;
    try {
      storedRoot = normalizeHash(epochRow.merkle_root);
    } catch (err) {
      return fail(
        500,
        "MERKLE_ROOT_MISMATCH",
        `epoch ${epochId} has an invalid stored root`,
        { epoch_id: epochId, message: (err as Error).message },
      );
    }
    if (root !== storedRoot) {
      return fail(
        500,
        "MERKLE_ROOT_MISMATCH",
        `rebuilt root for epoch ${epochId} does not match stored root`,
        { epoch_id: epochId, stored: storedRoot, rebuilt: root },
      );
    }
    epochCache.set(epochId, { root, levels, row: epochRow });
  }

  const disclosures: Disclosure[] = [];
  for (const row of allRows) {
    const epochId = row.epoch_id as number;
    const leafIndex = row.epoch_leaf_idx as number;
    const cached = epochCache.get(epochId);
    if (!cached) {
      return fail(500, "EPOCH_NOT_FOUND", `epoch ${epochId} not cached`, {
        epoch_id: epochId,
      });
    }
    if (leafIndex < 0 || leafIndex >= cached.levels[0]!.length) {
      return fail(
        500,
        "INVALID_ENVELOPE",
        `epoch ${epochId} leaf index ${leafIndex} is out of bounds`,
      );
    }

    let envelope: Envelope;
    let computedHash: string;
    try {
      envelope = JSON.parse(row.envelope_json) as Envelope;
      computedHash = await hashCanonical({
        v: envelope.v,
        event: envelope.event,
        chain: envelope.chain,
      });
    } catch (err) {
      return fail(
        500,
        "INVALID_ENVELOPE",
        `event ${chainId}/${row.seq} has an unreadable envelope`,
        { seq: row.seq, message: (err as Error).message },
      );
    }

    let storedHash: string;
    try {
      storedHash = normalizeHash(row.envelope_hash);
    } catch (err) {
      return fail(
        500,
        "INVALID_ENVELOPE",
        `event ${chainId}/${row.seq} has an invalid envelope hash`,
        { seq: row.seq, message: (err as Error).message },
      );
    }

    if (computedHash !== storedHash) {
      return fail(
        500,
        "INVALID_ENVELOPE",
        `event ${chainId}/${row.seq} envelope hash does not match stored leaf`,
        { seq: row.seq, stored: storedHash, computed: computedHash },
      );
    }
    if (
      envelope.chain.chain_id !== chainId ||
      envelope.chain.seq !== row.seq
    ) {
      return fail(
        500,
        "INVALID_ENVELOPE",
        `event ${chainId}/${row.seq} envelope chain/seq mismatch`,
        {
          seq: row.seq,
          envelope_chain: envelope.chain.chain_id,
          envelope_seq: envelope.chain.seq,
        },
      );
    }

    const proof = inclusionProof(cached.levels, leafIndex);
    disclosures.push({
      event_ref: refOf(envelope),
      envelope,
      envelope_hash: storedHash,
      epoch_id: epochId,
      leaf_index: leafIndex,
      proof: {
        type: "merkle-inclusion/v1",
        siblings: proof.siblings,
        root: cached.root,
      },
    });
  }

  const beforeRef =
    boundaryRows.find((r) => r.seq === fromSeq - 1) !== undefined
      ? { chain_id: chainId, seq: fromSeq - 1 }
      : null;
  const afterRef =
    boundaryRows.find((r) => r.seq === toSeq + 1) !== undefined
      ? { chain_id: chainId, seq: toSeq + 1 }
      : null;

  const anchorEpochs: AnchorEpoch[] = epochIds.map((epochId) => {
    const cached = epochCache.get(epochId)!;
    const txHash = cached.row.anchor_tx_hash as string;
    return {
      epoch_id: epochId,
      merkle_root: cached.root,
      tx_hash: txHash,
      block_number: cached.row.anchor_block ?? null,
      block_hash: opts.blockHashes?.[epochId] ?? null,
      calldata: encodeAnchorCalldata(epochId, cached.root),
      explorer: txHash ? `https://basescan.org/tx/${txHash}` : null,
    };
  });

  return {
    ok: true,
    disclosure: {
      version: DISCLOSURE_VERSION,
      chain_id: chainId,
      from_seq: fromSeq,
      to_seq: toSeq,
      recorder: opts.recorder,
      disclosures,
      anchor: {
        network: opts.network ?? "eip155:8453",
        anchorer: opts.anchorer,
        epochs: anchorEpochs,
      },
      before_ref: beforeRef,
      after_ref: afterRef,
      warnings,
    },
  };
}

/**
 * D1 adapter for the hosted Worker. The SQL is intentionally limited to the
 * three tables the disclosure primitive needs: events, epochs, and (implicitly)
 * the chain identity carried inside each envelope.
 */
type Db = {
  prepare(query: string): {
    bind(...args: unknown[]): {
      all(): Promise<{ results: Array<Record<string, unknown>> }>;
      first(): Promise<Record<string, unknown> | null>;
    };
  };
};

export function d1DisclosureSource(db: Db): DisclosureSource {
  return {
    async listEvents(chainId, fromSeq, toSeq) {
      const rows = await db
        .prepare(
          `SELECT seq, envelope_json, envelope_hash, epoch_id, epoch_leaf_idx
           FROM events
           WHERE chain_id = ? AND seq >= ? AND seq <= ?
           ORDER BY seq ASC`,
        )
        .bind(chainId, fromSeq, toSeq)
        .all();
      return rows.results as unknown as DisclosureEventRow[];
    },

    async getEvent(chainId, seq) {
      const row = await db
        .prepare(
          `SELECT seq, envelope_json, envelope_hash, epoch_id, epoch_leaf_idx
           FROM events
           WHERE chain_id = ? AND seq = ?`,
        )
        .bind(chainId, seq)
        .first();
      return (row as unknown as DisclosureEventRow) ?? null;
    },

    async getEpoch(epochId) {
      const row = await db
        .prepare(
          `SELECT epoch_id, merkle_root, anchor_tx_hash, anchor_block
           FROM epochs
           WHERE epoch_id = ?`,
        )
        .bind(epochId)
        .first();
      return (row as unknown as DisclosureEpochRow) ?? null;
    },

    async listEpochLeaves(epochId) {
      const rows = await db
        .prepare(
          `SELECT envelope_hash
           FROM events
           WHERE epoch_id = ?
           ORDER BY epoch_leaf_idx ASC`,
        )
        .bind(epochId)
        .all();
      return (rows.results as Array<{ envelope_hash: string }>).map(
        (r) => r.envelope_hash,
      );
    },
  };
}
