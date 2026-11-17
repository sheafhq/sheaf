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

/** Fetch a resource, paying a 402 with the local wallet and retrying once. */
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
  const headers = new Headers(init.headers);
  for (const [key, value] of Object.entries(
    payer.http.encodePaymentSignatureHeader(payload),
  )) {
    headers.set(key, value);
  }
  return fetch(url, { ...init, headers });
}
