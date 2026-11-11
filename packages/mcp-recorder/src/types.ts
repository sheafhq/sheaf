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
};

export type PendingCall = {
  id: number | string;
  method: string;
  params: unknown;
  startedAt: number;
};
