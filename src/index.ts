import { Hono } from "hono";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { envelopeHash, signingInput } from "./chain.js";
import { importRecorderKey, b64encode, signEd25519 } from "./crypto.js";
import { ACTIVE_KEY_ID, KEY_RING, activeKey } from "./keys.js";
import { buildMerkleTree, inclusionProof, EMPTY_ROOT } from "./merkle.js";
import { anchorRoot } from "./anchor.js";
import { buildBundle, BUNDLE_VERSION } from "./bundle.js";
import { buildCreateAuthHeaders, extractPayer } from "./x402.js";
import { VERIFY_HTML } from "./verify-page.js";
import {
  anchorLimitForPlan,
  createAccount,
  currentMonth,
  getChainOwner,
  LEGACY_ACCOUNT_ID,
  lookupAccountByKey,
  parseBearer,
  type Plan,
} from "./accounts.js";
import { renderChainPage, type ChainSummary } from "./chain-page.js";
import { renderBadge } from "./badge.js";
import type {
  ChainHead,
  Envelope,
  SubmissionReceipt,
  UnsignedSubmission,
} from "./types.js";

type Env = {
  ISSUER: string;
  KEY_ID: string;
  ANCHOR_CONTRACT: string;
  ANCHOR_NETWORK: string;
  RECORDER_PRIVATE_KEY?: string;
  ANCHORER_PRIVATE_KEY?: string;
  ANCHORER_ADDRESS?: string;
  ADMIN_TOKEN?: string;
  // Authenticated Base RPC (Alchemy / QuickNode / Infura). Preferred over
  // the public pool because CF-egress IPs get rate-limited by mainnet.base.org.
  BASE_RPC_URL?: string;
  // x402 paid-surface config
  PAYOUT_ADDRESS: string;
  NETWORK: string;
  FACILITATOR_URL: string;
  CDP_API_KEY_NAME?: string;
  CDP_API_KEY_SECRET?: string;
  ANALYTICS?: {
    writeDataPoint(event: {
      blobs?: string[];
      doubles?: number[];
      indexes?: string[];
    }): void;
  };
  DB?: {
    prepare(query: string): {
      bind(
        ...args: unknown[]
      ): {
        all(): Promise<{ results: Array<Record<string, unknown>> }>;
        first(): Promise<Record<string, unknown> | null>;
        run(): Promise<{ meta: { last_row_id: number } }>;
      };
    };
  };
};

const app = new Hono<{ Bindings: Env }>();

const ONE_DAY_CACHE = "public, max-age=86400, s-maxage=86400";

// Lightweight request logger: Analytics Engine only (D1 writes stay on the
// envelope hot path). Captures paid vs unpaid, payer wallet, latency, status.
app.use(async (c, next) => {
  const t0 = Date.now();
  await next();
  const latency = Date.now() - t0;
  const paymentHeader =
    c.req.header("PAYMENT-SIGNATURE") ??
    c.req.header("payment-signature") ??
    c.req.header("X-PAYMENT") ??
    c.req.header("x-payment");
  const paid = Boolean(paymentHeader);
  const payer = extractPayer(paymentHeader);
  try {
    c.env.ANALYTICS?.writeDataPoint({
      blobs: [
        c.req.path,
        paid ? "paid" : "unpaid",
        String(c.res.status),
        payer ?? "",
      ],
      doubles: [latency],
      indexes: [c.req.path.split("/")[1] ?? "other"],
    });
  } catch {}
});

app.get("/", (c) =>
  c.json({
    service: "sheaf",
    description:
      "Third-party execution recorder for AI agents. Hash-chained, Merkle-anchored, independently verifiable receipts.",
    status: "live — recorder, anchor, bundle",
    repo: "https://github.com/sheafhq/sheaf",
    architecture_doc: "https://github.com/sheafhq/sheaf/blob/main/ARCHITECTURE.md",
    canonical_base_url: "https://api.sheafhq.io",
    legacy_base_url: "https://sheaf-recorder.goldencalf.workers.dev",
    endpoints: {
      free: [
        "POST /events — submit a signed envelope; recorder co-signs and chains it",
        "GET /events/:chain_id/:seq — fetch stored envelope",
        "GET /chains/:chain_id/head — current head of a chain",
        "GET /epoch/:epoch_id/proof/:chain_id/:seq — Merkle inclusion proof",
        "GET /.well-known/sheaf-public-key — issuer public keys",
        "GET /verify — browser drag-drop verifier (HTML page)",
      ],
      paid: [
        "GET /bundle/:chain_id/:seq — self-contained verifiable .sheaf bundle ($0.001)",
      ],
    },
    issuer: c.env.ISSUER,
    key_id: c.env.KEY_ID,
    anchor_network: c.env.ANCHOR_NETWORK,
    payment: {
      protocol: "x402",
      protocol_version: 2,
      network: c.env.NETWORK,
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      asset_symbol: "USDC",
      pay_to: c.env.PAYOUT_ADDRESS,
      facilitator: c.env.FACILITATOR_URL,
    },
  }),
);

// Browser-based drag-drop verifier. Pure static HTML; verification runs
// client-side against a public Base RPC + the recorder public key embedded
// in the bundle. One shareable URL for the "try verifying my receipt" moment.
app.get("/verify", (c) => {
  c.header("Content-Type", "text/html; charset=utf-8");
  c.header("Cache-Control", "public, max-age=3600, s-maxage=3600");
  return c.body(VERIFY_HTML);
});

// Public verification page for a specific chain. Server-renders chain state
// and seeds a browser-side verifier so any reader can prove the latest
// anchored event without paying or signing up. See chain-page.ts.
async function loadChainSummary(
  db: Env["DB"],
  chainId: string,
): Promise<ChainSummary> {
  if (!db) throw new Error("DB binding missing");
  const chainRow = (await db
    .prepare(
      "SELECT chain_id, head_seq, head_hash, event_count, created_at, updated_at, account_id FROM chains WHERE chain_id = ?",
    )
    .bind(chainId)
    .first()) as
    | {
        chain_id: string;
        head_seq: number;
        head_hash: string;
        event_count: number;
        created_at: number;
        updated_at: number;
        account_id: string | null;
      }
    | null;
  if (!chainRow) {
    return {
      chain_id: chainId,
      head_seq: null,
      head_hash: null,
      event_count: 0,
      created_at: null,
      updated_at: null,
      account_id: LEGACY_ACCOUNT_ID,
      anchor_count: 0,
      latest_anchor: null,
      recent_events: [],
    };
  }
  const anchorCountRow = (await db
    .prepare(
      "SELECT COUNT(DISTINCT epoch_id) AS n FROM events WHERE chain_id = ? AND epoch_id IS NOT NULL",
    )
    .bind(chainId)
    .first()) as { n: number } | null;
  const latestAnchor = (await db
    .prepare(
      `SELECT ep.epoch_id, ep.merkle_root, ep.anchor_tx_hash, ep.anchor_block, ep.sealed_at
       FROM events e JOIN epochs ep ON ep.epoch_id = e.epoch_id
       WHERE e.chain_id = ? AND e.epoch_id IS NOT NULL
       ORDER BY e.epoch_id DESC LIMIT 1`,
    )
    .bind(chainId)
    .first()) as
    | {
        epoch_id: number;
        merkle_root: string;
        anchor_tx_hash: string | null;
        anchor_block: number | null;
        sealed_at: number;
      }
    | null;
  const recent = await db
    .prepare(
      "SELECT seq, tool, result, ts, epoch_id FROM events WHERE chain_id = ? ORDER BY seq DESC LIMIT 5",
    )
    .bind(chainId)
    .all();
  return {
    chain_id: chainRow.chain_id,
    head_seq: chainRow.head_seq,
    head_hash: chainRow.head_hash,
    event_count: chainRow.event_count,
    created_at: chainRow.created_at,
    updated_at: chainRow.updated_at,
    account_id: chainRow.account_id ?? LEGACY_ACCOUNT_ID,
    anchor_count: anchorCountRow?.n ?? 0,
    latest_anchor: latestAnchor,
    recent_events: (recent.results as Array<{
      seq: number;
      tool: string;
      result: string;
      ts: number;
      epoch_id: number | null;
    }>).map((e) => ({
      seq: e.seq,
      tool: e.tool,
      result: e.result,
      ts: e.ts,
      epoch_id: e.epoch_id,
    })),
  };
}

app.get("/c/:chain_id", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const chainId = c.req.param("chain_id");
  if (!chainId) return c.json({ error: "chain_id required" }, 400);
  const base = new URL(c.req.url).origin;
  const summary = await loadChainSummary(c.env.DB, chainId);
  c.header("Content-Type", "text/html; charset=utf-8");
  c.header("Cache-Control", "public, max-age=30, s-maxage=30");
  return c.body(renderChainPage(summary, base));
});

app.get("/badge/:slug", async (c) => {
  if (!c.env.DB) return c.body("", 500);
  const slug = c.req.param("slug");
  if (!slug || !slug.endsWith(".svg")) return c.body("", 400);
  const chainId = decodeURIComponent(slug.slice(0, -4));
  if (!chainId) return c.body("", 400);
  const summary = await loadChainSummary(c.env.DB, chainId);
  const value =
    summary.head_seq === null
      ? "unused"
      : `${summary.anchor_count} anchor${summary.anchor_count === 1 ? "" : "s"}`;
  const svg = renderBadge({
    label: "sheaf",
    value,
    anchored: summary.anchor_count > 0,
  });
  c.header("Content-Type", "image/svg+xml; charset=utf-8");
  c.header("Cache-Control", "public, max-age=60, s-maxage=60");
  return c.body(svg);
});

app.get("/.well-known/sheaf-public-key", (c) => {
  c.header("Cache-Control", ONE_DAY_CACHE);
  return c.json({
    issuer: c.env.ISSUER,
    active_key_id: ACTIVE_KEY_ID,
    keys: KEY_RING,
    verification_note:
      "The recorder signature covers the canonical JSON (RFC 8785) of {v, event, chain}. Base64-decode the signature and verify with the public key whose active window covers envelope.event.ts.",
    verifier_lib: "https://www.npmjs.com/package/@sheafhq/verify (phase 4)",
  });
});

// Basic shape validation. Returns null on error message if valid.
function validateSubmission(x: unknown): string | null {
  if (!x || typeof x !== "object") return "body must be a JSON object";
  const o = x as Record<string, unknown>;
  if (o.v !== "arca/1") return "v must be 'arca/1'";
  if (!o.event || typeof o.event !== "object") return "event required";
  if (!o.chain || typeof o.chain !== "object") return "chain required";
  if (!o.signatures || typeof o.signatures !== "object")
    return "signatures required";
  const ev = o.event as Record<string, unknown>;
  for (const k of [
    "intent",
    "actor",
    "tool",
    "inputs_hash",
    "result",
    "ts",
  ]) {
    if (typeof ev[k] !== "string") return `event.${k} must be a string`;
  }
  if (!["ok", "error", "timeout", "cancelled"].includes(ev.result as string))
    return "event.result must be ok|error|timeout|cancelled";
  if (
    ev.outputs_hash !== null &&
    typeof ev.outputs_hash !== "string"
  )
    return "event.outputs_hash must be string or null";
  if (ev.authority !== null && typeof ev.authority !== "string")
    return "event.authority must be string or null";
  const ch = o.chain as Record<string, unknown>;
  if (typeof ch.chain_id !== "string") return "chain.chain_id must be a string";
  if (typeof ch.seq !== "number" || !Number.isInteger(ch.seq) || ch.seq < 0)
    return "chain.seq must be a non-negative integer";
  if (ch.prev_hash !== null && typeof ch.prev_hash !== "string")
    return "chain.prev_hash must be a string or null";
  return null;
}

// Account-signup endpoint (WP2). Takes an optional email, returns one-time
// API key. The plaintext key is NEVER stored or retrievable — only its
// SHA-256 hash is persisted. Clients that lose the key create a new one
// and revoke the old one (revocation endpoint added in WP6).
app.post("/accounts", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  let body: { email?: string } = {};
  try {
    const raw = await c.req.text();
    if (raw.trim()) body = JSON.parse(raw) as { email?: string };
  } catch {
    return c.json({ error: "invalid JSON body" }, 400);
  }
  const email =
    typeof body.email === "string" && body.email.includes("@")
      ? body.email.trim()
      : null;
  try {
    const { account, api_key } = await createAccount(c.env.DB, email);
    return c.json(
      {
        ok: true,
        account_id: account.account_id,
        api_key,
        plan: account.plan,
        created_at: account.created_at,
        note: "api_key is shown ONCE. Store it now; it cannot be retrieved later. Use in POST /events as `Authorization: Bearer <api_key>`.",
      },
      201,
    );
  } catch (e) {
    return c.json(
      { error: `account creation failed: ${(e as Error).message}` },
      500,
    );
  }
});

app.post("/events", async (c) => {
  if (!c.env.DB)
    return c.json({ error: "DB binding missing on this Worker" }, 500);
  if (!c.env.RECORDER_PRIVATE_KEY)
    return c.json({ error: "recorder key missing" }, 500);

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid JSON body" }, 400);
  }
  const err = validateSubmission(body);
  if (err) return c.json({ error: err }, 400);

  const submission = body as UnsignedSubmission;
  const { chain_id, seq, prev_hash } = submission.chain;

  // --- WP2 chain-ownership check -----------------------------------------
  // Rules:
  //   1. If chain exists AND is owned by a real account: Bearer key required
  //      and must match that account.
  //   2. If chain exists AND is owned by 'legacy-public': accept without
  //      auth (grandfather — writes to pre-WP2 chains keep working).
  //   3. If chain is new: Bearer key required; new chain inherits caller's
  //      account_id.
  const bearer = parseBearer(c.req.header("Authorization"));
  const account = bearer ? await lookupAccountByKey(c.env.DB, bearer) : null;
  if (bearer && !account) {
    return c.json({ error: "invalid or revoked API key" }, 401);
  }
  const existingOwner = await getChainOwner(c.env.DB, chain_id);
  let chainAccountId: string;
  if (existingOwner === null) {
    // New chain — require auth.
    if (!account) {
      return c.json(
        {
          error:
            "new chains require an API key. Create one via POST /accounts, then send Authorization: Bearer <key>.",
        },
        401,
      );
    }
    chainAccountId = account.account_id;
  } else if (existingOwner === LEGACY_ACCOUNT_ID) {
    // Grandfather: legacy chains accept writes with or without auth.
    chainAccountId = LEGACY_ACCOUNT_ID;
  } else {
    // Real-owner chain — require matching auth.
    if (!account || account.account_id !== existingOwner) {
      return c.json(
        { error: `chain ${chain_id} is owned by a different account` },
        403,
      );
    }
    chainAccountId = existingOwner;
  }

  // Check chain head. seq must equal head_seq+1 (or be 0 if no head).
  const head = await c.env.DB.prepare(
    "SELECT head_seq, head_hash FROM chains WHERE chain_id = ?",
  )
    .bind(chain_id)
    .first();

  if (!head) {
    if (seq !== 0)
      return c.json({ error: `chain ${chain_id} has no head; seq must be 0` }, 409);
    if (prev_hash !== null)
      return c.json({ error: "seq=0 must have prev_hash=null" }, 400);
  } else {
    const expectedSeq = (head.head_seq as number) + 1;
    if (seq !== expectedSeq)
      return c.json(
        {
          error: `seq must be ${expectedSeq} (current head is ${head.head_seq})`,
          current_head_seq: head.head_seq,
          current_head_hash: head.head_hash,
        },
        409,
      );
    if (prev_hash !== head.head_hash)
      return c.json(
        {
          error: "prev_hash does not match current chain head",
          expected_prev_hash: head.head_hash,
        },
        409,
      );
  }

  // Sign the envelope (minus signatures) with the recorder key.
  const unsignedCore = {
    v: submission.v,
    event: submission.event,
    chain: submission.chain,
  };
  const sigKey = await importRecorderKey(c.env.RECORDER_PRIVATE_KEY);
  const sigBytes = await signEd25519(sigKey, signingInput(unsignedCore));
  const recorderSig = b64encode(sigBytes);

  const envelope: Envelope = {
    ...unsignedCore,
    signatures: {
      actor: submission.signatures.actor ?? null,
      recorder: recorderSig,
    },
  };
  const env_hash = await envelopeHash(unsignedCore);

  const nowSec = Math.floor(Date.now() / 1000);
  let tsSec = Math.floor(new Date(submission.event.ts).getTime() / 1000);
  if (!Number.isFinite(tsSec)) tsSec = nowSec;

  // Persist event + update chain head. D1 doesn't support real transactions
  // yet in Workers; the uniqueness constraint on (chain_id, seq) prevents
  // double-insert, and we update chains after the insert succeeds.
  try {
    await c.env.DB.prepare(
      `INSERT INTO events
        (chain_id, seq, envelope_json, envelope_hash, prev_hash, actor, tool, result, ts, received_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        chain_id,
        seq,
        JSON.stringify(envelope),
        env_hash,
        prev_hash,
        submission.event.actor,
        submission.event.tool,
        submission.event.result,
        tsSec,
        nowSec,
      )
      .run();
  } catch (e) {
    return c.json(
      {
        error: `insert failed (chain head may have moved): ${(e as Error).message}`,
      },
      409,
    );
  }

  await c.env.DB.prepare(
    `INSERT INTO chains (chain_id, head_seq, head_hash, created_at, updated_at, event_count, account_id)
     VALUES (?, ?, ?, ?, ?, 1, ?)
     ON CONFLICT(chain_id) DO UPDATE SET
       head_seq = excluded.head_seq,
       head_hash = excluded.head_hash,
       updated_at = excluded.updated_at,
       event_count = chains.event_count + 1`,
  )
    .bind(chain_id, seq, env_hash, nowSec, nowSec, chainAccountId)
    .run();

  // WP3: flag quota status in the response header so the recorder client
  // can emit a stderr warning at 80% / 100%. Reads the current month's
  // usage for this (account, chain) tuple + looks up plan limit.
  try {
    const usageRow = (await c.env.DB.prepare(
      "SELECT anchor_count FROM anchor_usage_monthly WHERE account_id = ? AND chain_id = ? AND month = ?",
    )
      .bind(chainAccountId, chain_id, currentMonth())
      .first()) as { anchor_count: number } | null;
    const accountRow = (await c.env.DB.prepare(
      "SELECT plan FROM accounts WHERE account_id = ?",
    )
      .bind(chainAccountId)
      .first()) as { plan: Plan } | null;
    const plan = accountRow?.plan ?? "free";
    const used = usageRow?.anchor_count ?? 0;
    const limit = anchorLimitForPlan(plan);
    if (used >= limit) {
      c.header("x-sheaf-anchor-quota", "exceeded");
      c.header(
        "x-sheaf-anchor-usage",
        `${used}/${limit === Number.MAX_SAFE_INTEGER ? "unlimited" : limit}`,
      );
    } else if (used >= limit * 0.8) {
      c.header("x-sheaf-anchor-quota", "warning");
      c.header("x-sheaf-anchor-usage", `${used}/${limit}`);
    } else {
      c.header("x-sheaf-anchor-usage", `${used}/${limit === Number.MAX_SAFE_INTEGER ? "unlimited" : limit}`);
    }
  } catch {
    // Header-setting must never break event ingestion. Fail silent.
  }

  const receipt: SubmissionReceipt = {
    ok: true,
    chain_id,
    seq,
    envelope_hash: env_hash,
    envelope,
  };
  return c.json(receipt, 201);
});

app.get("/chains/:chain_id/head", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const chain_id = c.req.param("chain_id");
  const row = await c.env.DB.prepare(
    "SELECT head_seq, head_hash, event_count, created_at, updated_at FROM chains WHERE chain_id = ?",
  )
    .bind(chain_id)
    .first();
  if (!row) return c.json({ chain_id, head: null }, 404);
  const head: ChainHead = {
    chain_id,
    head_seq: row.head_seq as number,
    head_hash: row.head_hash as string,
    event_count: row.event_count as number,
    created_at: row.created_at as number,
    updated_at: row.updated_at as number,
  };
  return c.json(head);
});

app.get("/events/:chain_id/:seq", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const chain_id = c.req.param("chain_id");
  const seqStr = c.req.param("seq");
  const seq = Number.parseInt(seqStr, 10);
  if (!Number.isInteger(seq) || seq < 0)
    return c.json({ error: "seq must be a non-negative integer" }, 400);

  const row = await c.env.DB.prepare(
    "SELECT envelope_json, envelope_hash, epoch_id, epoch_leaf_idx FROM events WHERE chain_id = ? AND seq = ?",
  )
    .bind(chain_id, seq)
    .first();
  if (!row) return c.json({ error: "not found" }, 404);
  return c.json({
    envelope: JSON.parse(row.envelope_json as string),
    envelope_hash: row.envelope_hash,
    epoch_id: row.epoch_id,
    epoch_leaf_idx: row.epoch_leaf_idx,
    inclusion_proof: null, // populated in phase 3
  });
});

// Core anchor flow — shared by the HTTP admin endpoint and the cron
// scheduled handler. Seals all un-anchored events into a new epoch, builds
// the Merkle tree, submits the anchor tx on Base, persists the epoch row,
// and stamps each event with (epoch_id, leaf_idx). Idempotent only in the
// sense that if there are no un-anchored events it is a no-op; otherwise
// each call creates exactly one new epoch.
type SkippedChain = {
  account_id: string;
  chain_id: string;
  plan: Plan;
  current: number;
  limit: number;
};
type AnchorFlowResult =
  | {
      ok: true;
      epoch_id: number;
      merkle_root: string;
      event_count: number;
      anchor_tx_hash: string;
      skipped: SkippedChain[];
    }
  | { ok: false; status: number; reason: string; detail?: unknown };

async function anchorPending(env: Env): Promise<AnchorFlowResult> {
  if (!env.DB) return { ok: false, status: 500, reason: "DB binding missing" };
  if (!env.ANCHORER_PRIVATE_KEY)
    return { ok: false, status: 500, reason: "ANCHORER_PRIVATE_KEY secret missing" };

  const month = currentMonth();

  // Fetch unanchored events joined with chain ownership + current month's
  // anchor usage. Everything needed to decide which chains to include in
  // this epoch.
  const unanchored = await env.DB.prepare(
    `SELECT e.rowid AS rowid, e.chain_id, e.seq, e.envelope_hash, e.received_at,
            c.account_id, a.plan,
            COALESCE((SELECT u.anchor_count FROM anchor_usage_monthly u
                      WHERE u.account_id = c.account_id
                        AND u.chain_id = e.chain_id
                        AND u.month = ?), 0) AS current_anchors
     FROM events e
     JOIN chains c ON c.chain_id = e.chain_id
     JOIN accounts a ON a.account_id = c.account_id
     WHERE e.epoch_id IS NULL
     ORDER BY e.received_at, e.chain_id, e.seq`,
  )
    .bind(month)
    .all();

  type Row = {
    rowid: number;
    chain_id: string;
    seq: number;
    envelope_hash: string;
    received_at: number;
    account_id: string;
    plan: Plan;
    current_anchors: number;
  };
  const rows = unanchored.results as Row[];
  if (rows.length === 0)
    return { ok: false, status: 200, reason: "no un-anchored events" };

  // Decide quota per unique (account, chain). An over-cap chain is skipped
  // entirely — its events stay un-anchored until the next month rollover
  // or the operator upgrades.
  const decisions = new Map<string, { include: boolean; plan: Plan; current: number; limit: number }>();
  for (const r of rows) {
    const key = `${r.account_id}::${r.chain_id}`;
    if (decisions.has(key)) continue;
    const limit = anchorLimitForPlan(r.plan);
    decisions.set(key, {
      include: r.current_anchors < limit,
      plan: r.plan,
      current: r.current_anchors,
      limit,
    });
  }
  const skipped: SkippedChain[] = [];
  for (const [key, d] of decisions) {
    if (!d.include) {
      const [account_id, chain_id] = key.split("::");
      skipped.push({ account_id: account_id!, chain_id: chain_id!, plan: d.plan, current: d.current, limit: d.limit });
    }
  }

  const includedRows = rows.filter(
    (r) => decisions.get(`${r.account_id}::${r.chain_id}`)?.include,
  );
  if (includedRows.length === 0) {
    return {
      ok: false,
      status: 200,
      reason:
        "all un-anchored chains are at or over their monthly anchor cap",
      detail: { month, skipped },
    };
  }

  const prev = await env.DB.prepare(
    "SELECT epoch_id FROM epochs ORDER BY epoch_id DESC LIMIT 1",
  )
    .bind()
    .first();
  const epochId = ((prev?.epoch_id as number | undefined) ?? -1) + 1;

  const leaves = includedRows.map((r) => r.envelope_hash);
  const { root } = await buildMerkleTree(leaves);

  const nowSec = Math.floor(Date.now() / 1000);
  const firstReceived = includedRows[0]?.received_at ?? nowSec;
  const lastReceived =
    includedRows[includedRows.length - 1]?.received_at ?? nowSec;

  let anchorTxHash: string;
  try {
    const result = await anchorRoot(
      env.ANCHORER_PRIVATE_KEY,
      epochId,
      root,
      env.BASE_RPC_URL,
    );
    anchorTxHash = result.tx_hash;
  } catch (err) {
    return {
      ok: false,
      status: 502,
      reason: `anchor tx failed: ${(err as Error).message}`,
      detail: { epoch_id_attempted: epochId, event_count: includedRows.length, root },
    };
  }

  await env.DB.prepare(
    `INSERT INTO epochs (epoch_id, merkle_root, event_count, first_received_at,
     last_received_at, sealed_at, anchor_tx_hash, anchor_submitted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      epochId,
      root,
      includedRows.length,
      firstReceived,
      lastReceived,
      nowSec,
      anchorTxHash,
      nowSec,
    )
    .run();

  for (let i = 0; i < includedRows.length; i++) {
    const r = includedRows[i]!;
    await env.DB.prepare(
      "UPDATE events SET epoch_id = ?, epoch_leaf_idx = ? WHERE chain_id = ? AND seq = ?",
    )
      .bind(epochId, i, r.chain_id, r.seq)
      .run();
  }

  // Increment anchor_usage_monthly for each (account, chain) included.
  const uniqueChains = new Set(
    includedRows.map((r) => `${r.account_id}::${r.chain_id}`),
  );
  for (const key of uniqueChains) {
    const [account_id, chain_id] = key.split("::");
    await env.DB.prepare(
      `INSERT INTO anchor_usage_monthly (account_id, chain_id, month, anchor_count)
       VALUES (?, ?, ?, 1)
       ON CONFLICT (account_id, chain_id, month) DO UPDATE SET anchor_count = anchor_count + 1`,
    )
      .bind(account_id, chain_id, month)
      .run();
  }

  return {
    ok: true,
    epoch_id: epochId,
    merkle_root: root,
    event_count: includedRows.length,
    anchor_tx_hash: anchorTxHash,
    skipped,
  };
}

// Admin: trigger the anchor flow manually. Cron handler below calls the
// same `anchorPending` without auth.
app.post("/admin/anchor", async (c) => {
  if (!c.env.ADMIN_TOKEN)
    return c.json({ error: "ADMIN_TOKEN secret missing" }, 500);
  const auth = c.req.header("Authorization");
  if (auth !== `Bearer ${c.env.ADMIN_TOKEN}`)
    return c.json({ error: "unauthorized" }, 401);

  const result = await anchorPending(c.env);
  if (!result.ok) {
    return c.json(
      { ok: false, reason: result.reason, detail: result.detail },
      result.status as 200 | 500 | 502,
    );
  }
  return c.json({
    ok: true,
    epoch_id: result.epoch_id,
    merkle_root: result.merkle_root,
    event_count: result.event_count,
    anchor_tx_hash: result.anchor_tx_hash,
    base_explorer: `https://basescan.org/tx/${result.anchor_tx_hash}`,
    skipped: result.skipped,
  });
});

// Usage dashboard: callers see their own per-chain anchor counts for the
// current month. Requires Bearer API key. Returns one row per chain this
// account owns, plus the plan's anchor limit for context.
app.get("/usage", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const bearer = parseBearer(c.req.header("Authorization"));
  if (!bearer) return c.json({ error: "Bearer API key required" }, 401);
  const account = await lookupAccountByKey(c.env.DB, bearer);
  if (!account) return c.json({ error: "invalid or revoked API key" }, 401);
  const month = currentMonth();
  const limit = anchorLimitForPlan(account.plan);
  const chainRows = await c.env.DB.prepare(
    "SELECT chain_id FROM chains WHERE account_id = ?",
  )
    .bind(account.account_id)
    .all();
  const usageRows = await c.env.DB.prepare(
    "SELECT chain_id, anchor_count FROM anchor_usage_monthly WHERE account_id = ? AND month = ?",
  )
    .bind(account.account_id, month)
    .all();
  const usageMap = new Map(
    (usageRows.results as Array<{ chain_id: string; anchor_count: number }>).map(
      (r) => [r.chain_id, r.anchor_count],
    ),
  );
  const chains = (chainRows.results as Array<{ chain_id: string }>).map((r) => {
    const used = usageMap.get(r.chain_id) ?? 0;
    return {
      chain_id: r.chain_id,
      anchors_this_month: used,
      anchors_remaining: Math.max(0, limit - used),
      over_quota: used >= limit,
    };
  });
  return c.json({
    account_id: account.account_id,
    plan: account.plan,
    month,
    anchor_limit_per_chain: limit,
    chains,
  });
});

// Inclusion proof for a specific event's leaf within its epoch.
app.get("/epoch/:epoch_id/proof/:chain_id/:seq", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const epochIdStr = c.req.param("epoch_id");
  const chainId = c.req.param("chain_id");
  const seqStr = c.req.param("seq");
  const epochId = Number.parseInt(epochIdStr, 10);
  const seq = Number.parseInt(seqStr, 10);
  if (!Number.isInteger(epochId) || !Number.isInteger(seq))
    return c.json({ error: "epoch_id and seq must be integers" }, 400);

  const event = await c.env.DB.prepare(
    "SELECT envelope_hash, epoch_leaf_idx FROM events WHERE chain_id = ? AND seq = ? AND epoch_id = ?",
  )
    .bind(chainId, seq, epochId)
    .first();
  if (!event)
    return c.json({ error: "event not found in that epoch" }, 404);

  const epoch = await c.env.DB.prepare(
    "SELECT merkle_root, event_count, anchor_tx_hash, anchor_block, sealed_at, anchor_submitted_at FROM epochs WHERE epoch_id = ?",
  )
    .bind(epochId)
    .first();
  if (!epoch)
    return c.json({ error: "epoch not found" }, 404);

  // Rebuild the tree from all leaves in this epoch (ordered by leaf_idx)
  const leafRows = await c.env.DB.prepare(
    "SELECT envelope_hash, epoch_leaf_idx FROM events WHERE epoch_id = ? ORDER BY epoch_leaf_idx",
  )
    .bind(epochId)
    .all();
  const leaves = (leafRows.results as Array<{ envelope_hash: string }>).map(
    (r) => r.envelope_hash,
  );
  const { root, levels } = await buildMerkleTree(leaves);
  if (root !== (epoch.merkle_root as string))
    return c.json(
      {
        error: "internal: rebuilt root does not match stored root",
        stored: epoch.merkle_root,
        rebuilt: root,
      },
      500,
    );

  const leafIdx = event.epoch_leaf_idx as number;
  const proof = inclusionProof(levels, leafIdx);

  return c.json({
    chain_id: chainId,
    seq,
    epoch_id: epochId,
    leaf: event.envelope_hash,
    leaf_index: leafIdx,
    merkle_root: epoch.merkle_root,
    siblings: proof.siblings,
    anchor: {
      tx_hash: epoch.anchor_tx_hash,
      block: epoch.anchor_block,
      submitted_at: epoch.anchor_submitted_at,
      explorer: epoch.anchor_tx_hash
        ? `https://basescan.org/tx/${epoch.anchor_tx_hash}`
        : null,
    },
    verification_note:
      "Hash leaf+siblings bottom-up (each sibling.side tells you whether it concatenates on the left or right of your running accumulator). The result must equal merkle_root. Then verify the anchor tx on Base: tx.from == tx.to == anchorer_address, tx.input starts with 0x41524341 (ARCA), bytes 12..44 of tx.input equal merkle_root.",
  });
});

// --- Paid bundle surface ---------------------------------------------------
// Self-contained verifiable artifact for one specific event. Priced at
// $0.001 via x402. Only served after the event has been anchored (epoch_id
// non-null and the Merkle root is on Base).

const bundleDiscovery = declareDiscoveryExtension({
  pathParamsSchema: {
    type: "object",
    properties: {
      chain_id: {
        type: "string",
        description:
          "Chain identifier the event lives in (same chain_id the recorder was writing to).",
      },
      seq: {
        type: "string",
        description:
          "Sequence number of the event within its chain (non-negative integer, as a string in the URL).",
      },
    },
    required: ["chain_id", "seq"],
  },
  output: {
    example: {
      version: BUNDLE_VERSION,
      envelope: {
        v: "arca/1",
        event: {
          intent: "invoke tool write_file",
          actor: "agent-123",
          authority: null,
          tool: "mcp://tool/write_file",
          inputs_hash: "sha256:...",
          outputs_hash: "sha256:...",
          result: "ok",
          ts: "2026-11-11T00:00:00Z",
        },
        chain: { chain_id: "demo", seq: 0, prev_hash: null },
        signatures: { actor: null, recorder: "base64-ed25519-signature" },
      },
      envelope_hash:
        "sha256:a1b2c3...",
      chain: { chain_id: "demo", seq: 0 },
      anchor: {
        epoch_id: 0,
        leaf_index: 0,
        merkle_root: "sha256:...",
        siblings: [],
        tx_hash: "0x...",
        block: 55369354,
        network: "eip155:8453",
        explorer: "https://basescan.org/tx/0x...",
      },
      issuer: {
        name: "sheaf",
        key_id: "sheaf-ed25519-2026-11-09",
        public_key_base64: "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
        public_key_url:
          "https://sheaf-recorder.goldencalf.workers.dev/.well-known/sheaf-public-key",
      },
      verification: {
        lib: "@sheafhq/verify",
        cmd: "npx -y @sheafhq/verify <save-this-bundle.json>",
      },
    },
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: [
        "version",
        "envelope",
        "envelope_hash",
        "chain",
        "anchor",
        "issuer",
        "verification",
      ],
      properties: {
        version: { type: "string", const: BUNDLE_VERSION },
        envelope: { type: "object" },
        envelope_hash: { type: "string" },
        chain: {
          type: "object",
          required: ["chain_id", "seq"],
          properties: {
            chain_id: { type: "string" },
            seq: { type: "integer", minimum: 0 },
          },
        },
        anchor: {
          type: "object",
          required: [
            "epoch_id",
            "leaf_index",
            "merkle_root",
            "siblings",
            "tx_hash",
            "network",
          ],
          properties: {
            epoch_id: { type: "integer", minimum: 0 },
            leaf_index: { type: "integer", minimum: 0 },
            merkle_root: { type: "string" },
            siblings: {
              type: "array",
              items: {
                type: "object",
                required: ["hash", "side"],
                properties: {
                  hash: { type: "string" },
                  side: { type: "string", enum: ["left", "right"] },
                },
              },
            },
            tx_hash: { type: ["string", "null"] },
            block: { type: ["integer", "null"] },
            network: { type: "string" },
            explorer: { type: ["string", "null"] },
          },
        },
        issuer: {
          type: "object",
          required: ["name", "key_id", "public_key_base64", "public_key_url"],
          properties: {
            name: { type: "string" },
            key_id: { type: "string" },
            public_key_base64: { type: "string" },
            public_key_url: { type: "string" },
          },
        },
        verification: { type: "object" },
      },
    },
  },
});

// Pre-paywall validator: if the event doesn't exist or isn't anchored yet,
// return the error without charging. If it's ready, build the bundle and
// stash it in context for the handler to return.
app.use("/bundle/:chain_id/:seq", async (c, next) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const chainId = c.req.param("chain_id");
  const seqStr = c.req.param("seq");
  const seq = Number.parseInt(seqStr, 10);
  if (!Number.isInteger(seq) || seq < 0) {
    return c.json({ error: "seq must be a non-negative integer" }, 400);
  }
  const publicKeyUrl =
    new URL(c.req.url).origin + "/.well-known/sheaf-public-key";
  const result = await buildBundle(
    c.env.DB,
    c.env.ISSUER,
    publicKeyUrl,
    chainId,
    seq,
  );
  if (!result.ok) {
    return c.json(
      { error: result.error, detail: result.detail },
      result.status,
    );
  }
  (c as unknown as { set(k: string, v: unknown): void }).set(
    "bundle",
    result.bundle,
  );
  await next();
});

// x402 wiring. paymentMiddleware is cached at module scope keyed by the
// first env it sees (env is stable across requests on the same Worker).
let cachedPaymentMw:
  | ReturnType<typeof paymentMiddleware>
  | null = null;
function getPaymentMiddleware(env: Env) {
  if (cachedPaymentMw) return cachedPaymentMw;
  const network = env.NETWORK as `${string}:${string}`;
  const facilitator = new HTTPFacilitatorClient({
    url: env.FACILITATOR_URL,
    createAuthHeaders: buildCreateAuthHeaders(env),
  });
  const resourceServer = new x402ResourceServer(facilitator).register(
    network,
    new ExactEvmScheme(),
  );
  cachedPaymentMw = paymentMiddleware(
    {
      "GET /bundle/:chain_id/:seq": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.001",
            network,
            payTo: env.PAYOUT_ADDRESS,
          },
        ],
        description:
          "Self-contained verifiable Sheaf bundle for one event: full signed envelope + Merkle inclusion proof + on-chain anchor reference + issuer public key. Verify offline with `npx @sheafhq/verify` + any Base RPC. Only returned after the event's epoch is anchored; otherwise 409 'not yet anchored' with no payment taken.",
        mimeType: "application/json",
        serviceName: "sheaf",
        tags: [
          "audit",
          "attestation",
          "evidence",
          "agent-receipts",
          "mcp",
          "merkle-proof",
          "compliance",
        ],
        extensions: { ...bundleDiscovery },
      },
    },
    resourceServer,
  );
  return cachedPaymentMw;
}

// Route-scoped: only the bundle path goes through the paywall.
app.use(async (c, next) => {
  if (!c.req.path.startsWith("/bundle/")) return next();
  return getPaymentMiddleware(c.env)(c, next);
});

app.get("/bundle/:chain_id/:seq", (c) =>
  c.json(
    (c as unknown as { get(k: string): unknown }).get("bundle"),
  ),
);

app.get("/epoch/:epoch_id", async (c) => {
  if (!c.env.DB) return c.json({ error: "DB binding missing" }, 500);
  const epochId = Number.parseInt(c.req.param("epoch_id"), 10);
  if (!Number.isInteger(epochId))
    return c.json({ error: "epoch_id must be an integer" }, 400);
  const row = await c.env.DB.prepare(
    "SELECT * FROM epochs WHERE epoch_id = ?",
  )
    .bind(epochId)
    .first();
  if (!row) return c.json({ error: "not found" }, 404);
  return c.json(row);
});

// CF Workers entry. Dispatches HTTP to Hono, cron to the anchor flow.
export default {
  fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Response | Promise<Response> {
    return app.fetch(request, env, ctx);
  },
  async scheduled(
    event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(
      (async () => {
        try {
          const result = await anchorPending(env);
          if (result.ok) {
            console.log(
              `scheduled anchor: epoch=${result.epoch_id} events=${result.event_count} tx=${result.anchor_tx_hash}`,
            );
          } else if (result.reason === "no un-anchored events") {
            // No-op path; keep logs quiet.
          } else {
            console.error(
              `scheduled anchor failed: ${result.reason}`,
              result.detail,
            );
          }
        } catch (err) {
          console.error("scheduled anchor threw:", (err as Error).message);
        }
      })(),
    );
  },
};
