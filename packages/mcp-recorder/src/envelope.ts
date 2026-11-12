// Build an event envelope + submit to the Sheaf recorder. Submission is a
// background best-effort operation: it must never block the MCP proxy pipeline,
// and a recorder outage must not break the agent's tool calls.

import { canonicalize, hashCanonical, sha256Hex } from "./canonical.js";
import type { PendingCall, RecorderConfig } from "./types.js";

type EventResult = "ok" | "error" | "timeout" | "cancelled";

type SubmissionReceipt = {
  ok?: true;
  seq?: number;
  envelope_hash?: string;
  error?: string;
  expected_prev_hash?: string;
  current_head_seq?: number;
  current_head_hash?: string;
};

type ChainState = {
  seq: number;        // next seq to write (head_seq + 1)
  prev_hash: string | null;
};

export class RecorderClient {
  private state: Promise<ChainState>;
  private queue: Promise<void> = Promise.resolve();

  constructor(private cfg: RecorderConfig) {
    this.state = this.fetchInitialState();
  }

  private debug(...args: unknown[]) {
    if (this.cfg.logDebug) console.error("[sheaf]", ...args);
  }

  /** Try the configured recorder URLs in order. Returns the first response
   *  (including 4xx/5xx — those are real answers). Falls back only on fetch
   *  errors (network, DNS, TLS). Throws the last error if all fail. */
  private async fetchWithFallback(
    path: string,
    init?: RequestInit,
  ): Promise<Response> {
    let lastErr: unknown;
    for (const base of this.cfg.recorderUrls) {
      try {
        return await fetch(base + path, init);
      } catch (err) {
        lastErr = err;
        this.debug(
          `fetch to ${base}${path} failed (${(err as Error).message}); trying next`,
        );
      }
    }
    throw lastErr ?? new Error("no recorder URLs configured");
  }

  private async fetchInitialState(): Promise<ChainState> {
    try {
      const r = await this.fetchWithFallback(
        `/chains/${encodeURIComponent(this.cfg.chainId)}/head`,
      );
      if (r.status === 404) {
        this.debug(`chain ${this.cfg.chainId} is new; starting at seq=0`);
        return { seq: 0, prev_hash: null };
      }
      if (!r.ok) {
        this.debug(`recorder /head returned ${r.status}; assuming new chain`);
        return { seq: 0, prev_hash: null };
      }
      const body = (await r.json()) as { head_seq: number; head_hash: string };
      this.debug(
        `chain ${this.cfg.chainId} head is seq=${body.head_seq}; resuming at seq=${body.head_seq + 1}`,
      );
      return { seq: body.head_seq + 1, prev_hash: body.head_hash };
    } catch (err) {
      this.debug(
        `could not reach recorder for initial head (${(err as Error).message}); starting at seq=0`,
      );
      return { seq: 0, prev_hash: null };
    }
  }

  /** Queue an event submission. Returns immediately; does not block the caller. */
  submit(
    call: PendingCall,
    response: { result?: unknown; error?: { message: string } } | null,
  ): void {
    this.queue = this.queue.then(() => this.submitInternal(call, response));
  }

  /** Wait for all queued submissions to finish. Call before process exit. */
  async drain(): Promise<void> {
    await this.queue;
  }

  private async submitInternal(
    call: PendingCall,
    response: { result?: unknown; error?: { message: string } } | null,
  ): Promise<void> {
    try {
      const state = await this.state;

      let result: EventResult = "ok";
      let outputsHash: string | null = null;
      if (!response) result = "timeout";
      else if (response.error) result = "error";
      else if (response.result !== undefined)
        outputsHash = "sha256:" + sha256Hex(canonicalize(response.result));

      const inputsHash = "sha256:" + sha256Hex(canonicalize(call.params));

      const envelope = {
        v: "arca/1" as const,
        event: {
          intent: deriveIntent(call),
          actor: this.cfg.actor,
          authority: null,
          tool: deriveToolName(call),
          inputs_hash: inputsHash,
          outputs_hash: outputsHash,
          result,
          ts: new Date().toISOString(),
        },
        chain: {
          chain_id: this.cfg.chainId,
          seq: state.seq,
          prev_hash: state.prev_hash,
        },
        signatures: { actor: null },
      };

      const body = canonicalize(envelope);
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (this.cfg.apiKey) {
        headers.Authorization = `Bearer ${this.cfg.apiKey}`;
      }
      const r = await this.fetchWithFallback(`/events`, {
        method: "POST",
        headers,
        body,
      });
      const receipt = (await r.json()) as SubmissionReceipt;

      if (r.status === 201 && receipt.ok && typeof receipt.seq === "number") {
        this.state = Promise.resolve({
          seq: receipt.seq + 1,
          prev_hash: receipt.envelope_hash ?? state.prev_hash,
        });
        this.debug(
          `recorded seq=${receipt.seq} for ${envelope.event.tool} → ${envelope.event.result}`,
        );
        return;
      }

      // 409 with head info means our local state drifted. Re-sync and give up
      // this one submission (the proxy will keep working; recorder stays
      // consistent).
      if (
        r.status === 409 &&
        typeof receipt.current_head_seq === "number" &&
        typeof receipt.current_head_hash === "string"
      ) {
        this.state = Promise.resolve({
          seq: receipt.current_head_seq + 1,
          prev_hash: receipt.current_head_hash,
        });
        this.debug(
          `resynced after 409: new seq=${receipt.current_head_seq + 1} (missed this submission)`,
        );
        return;
      }

      this.debug(
        `submission failed (${r.status}): ${receipt.error ?? "unknown"}; event dropped`,
      );
    } catch (err) {
      this.debug(`submit threw: ${(err as Error).message}; event dropped`);
    }
  }
}

function deriveToolName(call: PendingCall): string {
  const p = call.params as { name?: string; uri?: string } | undefined;
  switch (call.method) {
    case "tools/call":
      return `mcp://tool/${p?.name ?? "unknown"}`;
    case "resources/read":
      return `mcp://resource/${p?.uri ?? "unknown"}`;
    case "sampling/createMessage":
      return `mcp://sampling/createMessage`;
    default:
      return `mcp://method/${call.method}`;
  }
}

function deriveIntent(call: PendingCall): string {
  const p = call.params as { name?: string; uri?: string } | undefined;
  switch (call.method) {
    case "tools/call":
      return `invoke tool ${p?.name ?? "unknown"}`;
    case "resources/read":
      return `read resource ${p?.uri ?? "unknown"}`;
    case "sampling/createMessage":
      return `sample LLM completion`;
    default:
      return call.method;
  }
}
