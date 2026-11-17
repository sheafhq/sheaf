// Stripe Checkout + webhook signature verification + Resend delivery.
// No Stripe SDK dependency: the Worker uses Stripe's REST API directly.

export type BillingEnv = {
  STRIPE_SECRET_KEY?: string;
  STRIPE_PRICE_ID?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  RESEND_API_KEY?: string;
  RESEND_FROM?: string;
};

export type CheckoutResult =
  | { ok: true; url: string; session_id: string }
  | {
      ok: false;
      status: number;
      error: string;
      missing?: string[];
    };

export async function createCheckoutSession(
  env: BillingEnv,
  origin: string,
  email?: string | null,
): Promise<CheckoutResult> {
  const missing = [
    ...(env.STRIPE_SECRET_KEY ? [] : ["STRIPE_SECRET_KEY"]),
    ...(env.STRIPE_PRICE_ID ? [] : ["STRIPE_PRICE_ID"]),
  ];
  if (missing.length > 0) {
    return {
      ok: false,
      status: 503,
      error: "stripe_not_configured",
      missing,
    };
  }

  const body = new URLSearchParams();
  body.set("mode", "subscription");
  body.set("line_items[0][price]", env.STRIPE_PRICE_ID!);
  body.set("line_items[0][quantity]", "1");
  body.set(
    "success_url",
    `${origin}/?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
  );
  body.set("cancel_url", `${origin}/?checkout=cancelled`);
  body.set("allow_promotion_codes", "true");
  body.set("metadata[product]", "sheaf_pro");
  body.set("subscription_data[metadata][product]", "sheaf_pro");
  if (email && email.includes("@")) body.set("customer_email", email);

  const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const data = (await response.json()) as {
    id?: string;
    url?: string;
    error?: { message?: string };
  };
  if (!response.ok || !data.url || !data.id) {
    return {
      ok: false,
      status: response.status === 401 ? 502 : 502,
      error: data.error?.message ?? "stripe_checkout_failed",
    };
  }
  return { ok: true, url: data.url, session_id: data.id };
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Verify Stripe's `t=...,v1=...` HMAC-SHA256 signature. */
export async function verifyStripeSignature(
  payload: string,
  header: string | null,
  secret: string,
  toleranceSeconds = 300,
): Promise<boolean> {
  if (!header) return false;
  const parts = header.split(",");
  const timestamp = parts.find((p) => p.startsWith("t="))?.slice(2);
  const signatures = parts
    .filter((p) => p.startsWith("v1="))
    .map((p) => p.slice(3));
  if (!timestamp || signatures.length === 0) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSeconds) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${timestamp}.${payload}`),
  );
  const expected = hex(new Uint8Array(signature));
  return signatures.some((candidate) => constantTimeEqual(candidate, expected));
}

export async function sendResendEmail(
  env: BillingEnv,
  to: string,
  apiKey: string,
): Promise<{ ok: boolean; error?: string }> {
  if (!env.RESEND_API_KEY) {
    return { ok: false, error: "RESEND_API_KEY not configured" };
  }
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: env.RESEND_FROM ?? "Sheaf <keys@sheafhq.io>",
      to: [to],
      subject: "Your Sheaf Pro API key",
      text: [
        "Thanks for subscribing to Sheaf Pro.",
        "",
        `API key: ${apiKey}`,
        "",
        "Store it now. Sheaf only stores a hash and cannot retrieve it later.",
        "Use it as `Authorization: Bearer <key>` on POST /events.",
        "",
        "Docs: https://sheafhq.io/llms.txt",
      ].join("\n"),
    }),
  });
  if (!response.ok) {
    const text = await response.text();
    return { ok: false, error: `resend ${response.status}: ${text.slice(0, 300)}` };
  }
  return { ok: true };
}
