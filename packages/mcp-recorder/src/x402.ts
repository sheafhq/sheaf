// Autonomous x402 payer for Sheaf HTTP endpoints.
//
// Agents can wrap a fetch with `createX402Payer` + `paidFetch`:
//
//   const payer = createX402Payer(process.env.SHEAF_PAYER_PRIVATE_KEY);
//   const response = await paidFetch("https://sheafhq.io/v1/anchor/local", {
//     method: "POST",
//     body: JSON.stringify(request),
//     headers: { "content-type": "application/json" },
//   }, payer);
//
// The helper probes once without payment. On 402 it parses PAYMENT-REQUIRED,
// signs the exact EIP-3009 authorization with the local viem account, and
// retries with the x402 payment header. It does not need a Sheaf account.

import { x402Client } from "@x402/core/client";
import { x402HTTPClient } from "@x402/core/http";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

export type X402Payer = {
  http: x402HTTPClient;
  address: `0x${string}`;
  client: x402Client;
};

export function createX402Payer(privateKey: string): X402Payer {
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error("x402 payer private key must be 0x-prefixed 32-byte hex");
  }
  const account = privateKeyToAccount(privateKey as Hex);
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account });
  return {
    http: new x402HTTPClient(client),
    address: account.address,
    client,
  };
}

function mergeHeaders(
  init: RequestInit | undefined,
  extra: Record<string, string>,
): Headers {
  const headers = new Headers(init?.headers);
  for (const [key, value] of Object.entries(extra)) headers.set(key, value);
  return headers;
}

/**
 * Fetch an x402-protected resource, paying a 402 response automatically.
 * The request body is replayed; callers should pass a string/Uint8Array body.
 */
export async function paidFetch(
  url: string,
  init: RequestInit,
  payer: X402Payer,
): Promise<Response> {
  const first = await fetch(url, init);
  if (first.status !== 402) return first;

  const body = await first
    .clone()
    .json()
    .catch(() => undefined);
  const required = payer.http.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    body,
  );
  const payload = await payer.http.createPaymentPayload(required);
  const paymentHeaders = payer.http.encodePaymentSignatureHeader(payload);
  const retry = await fetch(url, {
    ...init,
    headers: mergeHeaders(init, paymentHeaders),
  });
  return retry;
}
