// Developer Preview intent capture: POST /v1/lead stores a waitlist lead in
// the D1 table `leads` (one row per email; resubmitting updates it).
//
// Data minimisation: only the email, the selected use case and tier
// interest, and timestamps are stored. No IP address, user agent or other
// request metadata.
//
// The table is created on first use (CREATE TABLE IF NOT EXISTS), the same
// statement as migrations/0006_leads.sql, because the deploy token has no D1
// migration permission. Applying the migration later is a no-op.

export const TIER_INTERESTS = ["local", "compliance", "dispute", "other"] as const;
export type TierInterest = (typeof TIER_INTERESTS)[number];

export type Lead = { email: string; use_case: string; tier_interest: TierInterest };

type D1 = {
  prepare(query: string): {
    bind(...args: unknown[]): { run(): Promise<unknown> };
  };
};

export const LEADS_DDL =
  "CREATE TABLE IF NOT EXISTS leads (" +
  "email TEXT PRIMARY KEY, " +
  "use_case TEXT NOT NULL DEFAULT '', " +
  "tier_interest TEXT NOT NULL CHECK (tier_interest IN ('local','compliance','dispute','other')), " +
  "created_at INTEGER NOT NULL, " +
  "updated_at INTEGER NOT NULL, " +
  "submissions INTEGER NOT NULL DEFAULT 1)";

const MAX_BODY_BYTES = 4096;
const MAX_EMAIL = 254;
const MAX_USE_CASE = 500;
const EMAIL_RE = /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[^\s@<>()",;:]{2,}$/;

export type LeadParse =
  | { ok: true; lead: Lead; honeypot: boolean }
  | { ok: false; error: string };

/** Validate a raw request body. Never throws. */
export function parseLead(raw: string): LeadParse {
  if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
    return { ok: false, error: "request body too large" };
  }
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return { ok: false, error: "invalid JSON body" };
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "JSON object required" };
  }
  const b = body as Record<string, unknown>;
  const email = typeof b.email === "string" ? b.email.trim().toLowerCase() : "";
  if (!email || email.length > MAX_EMAIL || !EMAIL_RE.test(email)) {
    return { ok: false, error: "a valid email is required" };
  }
  const useCase = b.use_case === undefined ? "" : b.use_case;
  if (typeof useCase !== "string" || useCase.length > MAX_USE_CASE) {
    return { ok: false, error: `use_case must be a string of at most ${MAX_USE_CASE} characters` };
  }
  const tier = b.tier_interest;
  if (typeof tier !== "string" || !(TIER_INTERESTS as readonly string[]).includes(tier)) {
    return { ok: false, error: `tier_interest must be one of: ${TIER_INTERESTS.join(", ")}` };
  }
  // Hidden form field that people never fill in; bots often do.
  const honeypot = typeof b.website === "string" && b.website.trim() !== "";
  return {
    ok: true,
    honeypot,
    lead: { email, use_case: useCase.trim(), tier_interest: tier as TierInterest },
  };
}

let tableReady = false;

/** Insert or update the lead. Throws on database errors. */
export async function storeLead(db: D1, lead: Lead, nowSec: number): Promise<void> {
  if (!tableReady) {
    await db.prepare(LEADS_DDL).bind().run();
    tableReady = true;
  }
  await db
    .prepare(
      "INSERT INTO leads (email, use_case, tier_interest, created_at, updated_at, submissions) " +
        "VALUES (?, ?, ?, ?, ?, 1) " +
        "ON CONFLICT(email) DO UPDATE SET use_case = excluded.use_case, " +
        "tier_interest = excluded.tier_interest, updated_at = excluded.updated_at, " +
        "submissions = leads.submissions + 1",
    )
    .bind(lead.email, lead.use_case, lead.tier_interest, nowSec, nowSec)
    .run();
}
