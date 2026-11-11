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

/** Generate an API key + its storage hash. The key is shown to the user once. */
export async function generateApiKey(): Promise<{ key: string; hash: string }> {
  const key = "sk_live_" + randomHex(32);
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
