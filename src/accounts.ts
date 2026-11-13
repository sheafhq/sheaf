// Account + API-key primitives. The Worker only stores SHA-256 hashes of
// keys; the plaintext key is shown to the user exactly once at creation
// time. If they lose it, they create a new key and revoke the old one.
//
// Key format: sk_live_<64 hex chars>. Readable prefix helps grep for leaks
// (same convention as Stripe, Resend, etc.).

import { sha256Hex } from "./canonical.js";

export type Plan = "free" | "pro" | "legacy-public";

/** Monthly anchor cap per chain for a given plan. See brief rev 2.
 *  Free: 30 anchors/chain/month (~daily cadence).
 *  Pro:  720 (~hourly).
 *  legacy-public: no cap — keeps pre-WP2 demo chains alive indefinitely. */
export function anchorLimitForPlan(plan: Plan): number {
  switch (plan) {
    case "pro":
      return 720;
    case "legacy-public":
      return Number.MAX_SAFE_INTEGER;
    case "free":
    default:
      return 30;
  }
}

/** Current UTC calendar month as YYYY-MM for the anchor_usage_monthly key. */
export function currentMonth(): string {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

export type Account = {
  account_id: string;
  email: string | null;
  plan: Plan;
  created_at: number;
};

type Db = {
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

export const LEGACY_ACCOUNT_ID = "legacy-public";

function randomHex(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

export function generateAccountId(): string {
  return "acct_" + randomHex(8);
}

/** Sheaf key prefix. Changed 2026-11-12 from `sk_live_` to `shf_live_` so
 *  the key cannot be mistaken for a Stripe secret key in logs / search /
 *  scrubbers. Old `sk_live_` keys still authenticate (lookup hashes the key
 *  as-is and the stored hash still matches) — only new keys mint as shf_. */
export const KEY_PREFIX = "shf_live_";

/** Any key format Sheaf has ever issued. Lookup accepts either; generator
 *  emits only the current KEY_PREFIX. */
export const ACCEPTED_KEY_PREFIXES = ["shf_live_", "sk_live_"] as const;

/** Is this plaintext a well-formed Sheaf API key? */
export function isValidKeyShape(s: string): boolean {
  for (const pfx of ACCEPTED_KEY_PREFIXES) {
    if (s.startsWith(pfx) && /^[a-f0-9]{64}$/.test(s.slice(pfx.length))) {
      return true;
    }
  }
  return false;
}

/** Generate an API key + its storage hash. The key is shown to the user once.
 *
 * KEYSPACE SEMANTICS (important — read before refactoring):
 *
 * The hash is computed over the WHOLE key string including the prefix.
 * That means `sk_live_<suffix>` and `shf_live_<suffix>` hash to DIFFERENT
 * values and are DIFFERENT keys — not the same key displayed two ways.
 * The prefix is NOT display-only; it carries hash-domain separation.
 *
 * Consequence:
 *   - A key issued historically as `sk_live_...` continues to authenticate
 *     because the stored hash was computed with the sk_live_ prefix, and
 *     the client presents the key with that same prefix. lookupAccountByKey
 *     hashes whatever bearer string arrives.
 *   - A new key issued today comes out as `shf_live_...` with a hash
 *     derived from the shf_live_ prefix.
 *   - You CANNOT swap prefixes on a key: `sk_live_X` and `shf_live_X` are
 *     not the same credential, even with identical suffixes.
 *
 * If you ever want prefix-independent lookup (to let `sk_live_X` and
 * `shf_live_X` be the same credential), you must either (a) backfill all
 * existing api_keys rows with a new prefix-stripped hash, or (b) do a
 * dual-lookup on the lookup path. Both are deliberate migrations; do not
 * sneak them in by changing this function alone. */
export async function generateApiKey(): Promise<{ key: string; hash: string }> {
  const key = KEY_PREFIX + randomHex(32);
  const hash = await sha256Hex(key);
  return { key, hash };
}

/** Parse Authorization: Bearer <token> header. Returns null if missing/malformed. */
export function parseBearer(headerValue: string | null | undefined): string | null {
  if (!headerValue) return null;
  const m = headerValue.match(/^Bearer\s+(.+)$/i);
  return m ? m[1]!.trim() : null;
}

/** Look up an account via an API key (plaintext). Returns null if invalid or revoked. */
export async function lookupAccountByKey(
  db: Db,
  plaintextKey: string,
): Promise<Account | null> {
  const keyHash = await sha256Hex(plaintextKey);
  const row = await db
    .prepare(
      `SELECT a.account_id, a.email, a.plan, a.created_at
       FROM api_keys k
       JOIN accounts a ON a.account_id = k.account_id
       WHERE k.key_hash = ? AND k.revoked_at IS NULL`,
    )
    .bind(keyHash)
    .first();
  if (!row) return null;
  // Best-effort last_used_at update; don't fail the auth path if this errors.
  try {
    await db
      .prepare("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?")
      .bind(Math.floor(Date.now() / 1000), keyHash)
      .run();
  } catch {}
  return {
    account_id: row.account_id as string,
    email: (row.email as string | null) ?? null,
    plan: row.plan as Plan,
    created_at: row.created_at as number,
  };
}

/** Create a new account + first API key. Returns the key plaintext (once). */
export async function createAccount(
  db: Db,
  email: string | null,
): Promise<{ account: Account; api_key: string }> {
  const accountId = generateAccountId();
  const createdAt = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      "INSERT INTO accounts (account_id, email, plan, created_at) VALUES (?, ?, 'free', ?)",
    )
    .bind(accountId, email, createdAt)
    .run();
  const { key, hash } = await generateApiKey();
  await db
    .prepare(
      "INSERT INTO api_keys (key_hash, account_id, label, created_at) VALUES (?, ?, 'initial', ?)",
    )
    .bind(hash, accountId, createdAt)
    .run();
  return {
    account: {
      account_id: accountId,
      email,
      plan: "free",
      created_at: createdAt,
    },
    api_key: key,
  };
}

// TODO (post-WP4): admin-authenticated revoke path. Current `revokeKey` is
// only reachable through `POST /accounts/me/keys/revoke`, which requires
// possession of the key being revoked. If an operator loses the key (lost
// laptop, accidental deletion, forgotten rotation) or has it stolen without
// detecting the compromise, they have no way to revoke it. Need either:
//   (a) email-based reset (requires accounts.email to be set — currently
//       optional; Stripe-billed Pro accounts in WP4 will have it mandatory)
//   (b) stripe_customer_id-based admin action gated by a Stripe-verified
//       support session
//   (c) manual ops channel (dangerous — SSRF-prone)
// Build when a real operator actually asks. Until then, the self-revoke
// path is the only revocation method and that is documented as a limitation.

/** Soft-revoke an API key (sets revoked_at = now). Returns true if a row was
 *  updated, false if the key wasn't found or was already revoked. Preserves
 *  the chain + audit history; only disables future authentication. */
export async function revokeKey(
  db: Db,
  plaintextKey: string,
): Promise<{ revoked: boolean; already_revoked: boolean; account_id: string | null; revoked_at_unix: number | null }> {
  const keyHash = await sha256Hex(plaintextKey);
  const now = Math.floor(Date.now() / 1000);
  const existing = (await db
    .prepare(
      "SELECT account_id, revoked_at FROM api_keys WHERE key_hash = ?",
    )
    .bind(keyHash)
    .first()) as { account_id: string; revoked_at: number | null } | null;
  if (!existing) {
    return { revoked: false, already_revoked: false, account_id: null, revoked_at_unix: null };
  }
  if (existing.revoked_at !== null) {
    return {
      revoked: false,
      already_revoked: true,
      account_id: existing.account_id,
      revoked_at_unix: existing.revoked_at,
    };
  }
  await db
    .prepare("UPDATE api_keys SET revoked_at = ? WHERE key_hash = ?")
    .bind(now, keyHash)
    .run();
  return { revoked: true, already_revoked: false, account_id: existing.account_id, revoked_at_unix: now };
}

/** Look up the owner of an existing chain. Returns null if chain doesn't exist. */
export async function getChainOwner(
  db: Db,
  chainId: string,
): Promise<string | null> {
  const row = await db
    .prepare("SELECT account_id FROM chains WHERE chain_id = ?")
    .bind(chainId)
    .first();
  return row ? ((row.account_id as string | null) ?? LEGACY_ACCOUNT_ID) : null;
}
