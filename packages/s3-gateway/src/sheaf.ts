import type { GatewayConfig } from "./config.js";

export type SheafReceipt = {
  chain_id: string;
  seq: number;
  envelope_hash: string;
};

type SubmissionReceipt = {
  ok?: true;
  seq?: number;
  envelope_hash?: string;
  error?: string;
  current_head_seq?: number;
  current_head_hash?: string;
};

/**
 * Serialized chain writer. Reads the current head on first use, then submits
 * exactly one event per successful S3 PUT. A 409 resyncs and retries once.
 */
export class SheafReceiptClient {
  private seq: number | null = null;
  private prevHash: string | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly cfg: Pick<
      GatewayConfig,
      "sheafBaseUrl" | "sheafApiKey" | "chainId" | "actor" | "authority"
    >,
  ) {}

  private async init(): Promise<void> {
    if (this.seq !== null) return;
    const response = await fetch(
      `${this.cfg.sheafBaseUrl}/chains/${encodeURIComponent(this.cfg.chainId)}/head`,
    );
    if (response.status === 404) {
      this.seq = 0;
      this.prevHash = null;
      return;
    }
    if (!response.ok) {
      throw new Error(`Sheaf head lookup failed: ${response.status}`);
    }
    const body = (await response.json()) as {
      head_seq: number;
      head_hash: string;
    };
    this.seq = body.head_seq + 1;
    this.prevHash = body.head_hash;
  }

  private async resync(): Promise<void> {
    this.seq = null;
    this.prevHash = null;
    await this.init();
  }

  private async submitOnce(fileHash: string): Promise<SheafReceipt> {
    await this.init();
    const seq = this.seq!;
    const event = {
      kind: "tool_call",
      intent: "storage.write",
      actor: this.cfg.actor,
      authority: this.cfg.authority,
      tool: "s3.put",
      inputs_hash: `sha256:${fileHash}`,
      outputs_hash: null,
      result: "ok",
      ts: new Date().toISOString(),
    };
    const body = {
      v: "arca/1",
      event,
      chain: {
        chain_id: this.cfg.chainId,
        seq,
        prev_hash: this.prevHash,
      },
      signatures: { actor: null },
    };
    const response = await fetch(`${this.cfg.sheafBaseUrl}/events`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.cfg.sheafApiKey}`,
      },
      body: JSON.stringify(body),
    });
    const receipt = (await response.json()) as SubmissionReceipt;
    if (
      response.status === 409 &&
      typeof receipt.current_head_seq === "number" &&
      typeof receipt.current_head_hash === "string"
    ) {
      this.seq = receipt.current_head_seq + 1;
      this.prevHash = receipt.current_head_hash;
      return this.submitOnce(fileHash);
    }
    if (
      response.status !== 201 ||
      !receipt.ok ||
      typeof receipt.seq !== "number" ||
      typeof receipt.envelope_hash !== "string"
    ) {
      throw new Error(
        `Sheaf receipt failed (${response.status}): ${receipt.error ?? "unknown error"}`,
      );
    }
    this.seq = receipt.seq + 1;
    this.prevHash = receipt.envelope_hash;
    return {
      chain_id: this.cfg.chainId,
      seq: receipt.seq,
      envelope_hash: receipt.envelope_hash,
    };
  }

  /** Queue a receipt write. The returned promise rejects if the Worker fails. */
  record(fileHash: string): Promise<SheafReceipt> {
    const run = this.queue.then(() => this.submitOnce(fileHash));
    this.queue = run.catch(() => undefined);
    return run;
  }
}
