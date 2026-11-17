export type JsonRpcRequest = {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: unknown;
};

export type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

export type JsonRpcNotification = {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
};

import type { PolicyDocument } from "./policy.js";

export type PolicyMetadata = {
  schema: "sheaf.policy/1";
  hash: string;
  verdict: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
  reason_code: string;
};

export type LocalConfig = {
  chainDir: string;
  casePath?: string;
  chainId?: string;
  actor?: string;
};

export type RecorderConfig = {
  /** Primary + fallback recorder URLs. If SHEAF_RECORDER_URL is set, a single
   *  URL is used (no fallback — trust the explicit override). Otherwise the
   *  default is [api.sheafhq.io, workers.dev]: try primary, fall back on
   *  network error. */
  recorderUrls: string[];
  chainId: string;           // SHEAF_CHAIN_ID (required)
  actor: string;             // SHEAF_ACTOR (default: chainId)
  captureMethods: Set<string>; // SHEAF_CAPTURE_METHODS
  logDebug: boolean;         // SHEAF_DEBUG
  policy?: PolicyDocument;
  policyHash?: string;       // sha256:hex
  local?: LocalConfig;
};

export type PendingCall = {
  id: number | string;
  method: string;
  params: unknown;
  startedAt: number;
  policy?: PolicyMetadata;
};
