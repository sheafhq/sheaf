// Buyer agent: an MCP client that talks to the merchant THROUGH Sheaf Local.
//
// Two brains:
//   - "ollama": a local LLM via Ollama's /api/chat tool-calling API
//     (OLLAMA_HOST, default http://127.0.0.1:11434). Still zero cloud.
//   - "mock":   a deterministic stand-in that follows the instruction
//     literally. Used when no local LLM is reachable, and by default in CI.
//
// Either way, the agent has no idea a firewall exists. It just sees MCP tools;
// a blocked call comes back as an ordinary tool error.

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";

export const BUYER_PROMPT =
  "Try to buy the enterprise data. If that fails, buy the premium data.";

type Tool = { name: string; description?: string; inputSchema?: unknown };
type ToolResult = { content?: Array<{ type: string; text?: string }>; isError?: boolean };

export type TranscriptStep = {
  tool: string;
  arguments: Record<string, unknown>;
  isError: boolean;
  text: string;
};

// ---- minimal MCP stdio client ----------------------------------------------

class McpClient {
  private nextId = 1;
  private pending = new Map<number, (m: { result?: unknown; error?: { message: string } }) => void>();
  readonly exited: Promise<number>;

  constructor(private proc: ChildProcess) {
    createInterface({ input: proc.stdout! }).on("line", (line) => {
      try {
        const msg = JSON.parse(line) as { id?: number; result?: unknown; error?: { message: string } };
        if (typeof msg.id === "number" && this.pending.has(msg.id)) {
          this.pending.get(msg.id)!(msg);
          this.pending.delete(msg.id);
        }
      } catch {
        /* ignore non-JSON */
      }
    });
    this.exited = new Promise((res) => proc.on("exit", (code) => res(code ?? 0)));
  }

  request<T>(method: string, params?: unknown): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, (m) => (m.error ? reject(new Error(m.error.message)) : resolve(m.result as T)));
      this.proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  notify(method: string, params?: unknown) {
    this.proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }

  /** Close stdin: Sheaf Local writes the session-close event, then exits. */
  close(): Promise<number> {
    this.proc.stdin!.end();
    return this.exited;
  }
}

function textOf(r: ToolResult): string {
  return (r.content ?? []).map((c) => c.text ?? "").join("\n");
}

// ---- brains -----------------------------------------------------------------

type CallTool = (name: string, args: Record<string, unknown>) => Promise<ToolResult>;

function priceFromDescription(t: Tool): number | null {
  const m = /€\s?(\d+(?:\.\d+)?)/.exec(t.description ?? "");
  return m ? Number(m[1]) : null;
}

/** Deterministic agent: follows BUYER_PROMPT literally. */
async function mockBrain(tools: Tool[], call: CallTool, log: (s: string) => void) {
  const plan = ["buy_enterprise_data", "buy_premium_data"];
  log(`[mock-agent] instruction: "${BUYER_PROMPT}"`);
  for (const name of plan) {
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`merchant does not offer ${name}`);
    const price = priceFromDescription(tool);
    if (price === null) throw new Error(`could not read a price for ${name}`);
    log(`[mock-agent] -> ${name}(amount=${price}, currency=EUR)`);
    const res = await call(name, { amount: price, currency: "EUR" });
    log(`[mock-agent] <- ${res.isError ? "FAILED" : "OK"}: ${textOf(res).split("\n")[0]}`);
    if (!res.isError) {
      log(`[mock-agent] done: purchased via ${name}`);
      return;
    }
  }
  log("[mock-agent] done: every option failed");
}

type OllamaMsg = {
  role: string;
  content: string;
  tool_calls?: Array<{ function: { name: string; arguments: Record<string, unknown> } }>;
};

async function ollamaBrain(
  host: string,
  model: string,
  tools: Tool[],
  call: CallTool,
  log: (s: string) => void,
) {
  const messages: OllamaMsg[] = [
    {
      role: "system",
      content:
        "You are a purchasing agent. Use the provided tools to make purchases. Always pass the exact list price as `amount` and \"EUR\" as `currency`. Make one tool call at a time. When finished, reply with a one-sentence summary and no tool calls.",
    },
    { role: "user", content: BUYER_PROMPT },
  ];
  const ollamaTools = tools.map((t) => ({
    type: "function",
    function: { name: t.name, description: t.description ?? "", parameters: t.inputSchema ?? {} },
  }));
  log(`[llm-agent] model=${model} instruction: "${BUYER_PROMPT}"`);
  for (let turn = 0; turn < 6; turn++) {
    const r = await fetch(`${host}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model, messages, tools: ollamaTools, stream: false, options: { temperature: 0 } }),
    });
    if (!r.ok) throw new Error(`ollama /api/chat HTTP ${r.status}: ${await r.text()}`);
    const { message } = (await r.json()) as { message: OllamaMsg };
    messages.push(message);
    if (!message.tool_calls?.length) {
      log(`[llm-agent] done: ${message.content.trim()}`);
      return;
    }
    for (const tc of message.tool_calls) {
      const args = tc.function.arguments ?? {};
      log(`[llm-agent] -> ${tc.function.name}(${JSON.stringify(args)})`);
      const res = await call(tc.function.name, args);
      log(`[llm-agent] <- ${res.isError ? "FAILED" : "OK"}: ${textOf(res).split("\n")[0]}`);
      messages.push({ role: "tool", content: textOf(res) });
    }
  }
  log("[llm-agent] stopped after 6 turns");
}

/** Pick a brain: an explicit mode, or "auto" = local Ollama if it is up and
 *  has a model, else the deterministic mock. */
export async function resolveBrain(
  mode: "auto" | "mock" | "ollama",
): Promise<{ kind: "mock" } | { kind: "ollama"; host: string; model: string }> {
  if (mode === "mock") return { kind: "mock" };
  const host = process.env.OLLAMA_HOST?.replace(/\/$/, "") ?? "http://127.0.0.1:11434";
  try {
    const r = await fetch(`${host}/api/tags`, { signal: AbortSignal.timeout(1500) });
    const { models } = (await r.json()) as { models: Array<{ name: string }> };
    const wanted = process.env.SIM_OLLAMA_MODEL;
    const model = wanted
      ? models.find((m) => m.name === wanted || m.name.startsWith(wanted + ":"))?.name
      : models[0]?.name;
    if (model) return { kind: "ollama", host, model };
    if (mode === "ollama") throw new Error(`no model ${wanted ?? ""} available in ollama at ${host}`);
  } catch (err) {
    if (mode === "ollama") throw new Error(`ollama not reachable at ${host}: ${(err as Error).message}`);
  }
  return { kind: "mock" };
}

// ---- entry ------------------------------------------------------------------

/** Spawn `command args` (Sheaf Local wrapping the merchant) and run the agent
 *  against it. Resolves once Sheaf Local has written the session-close event
 *  and exited. */
export async function runAgent(opts: {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
  brain: Awaited<ReturnType<typeof resolveBrain>>;
  log: (s: string) => void;
}): Promise<{ transcript: TranscriptStep[]; wrapperExitCode: number }> {
  const proc = spawn(opts.command, opts.args, { stdio: ["pipe", "pipe", "inherit"], env: opts.env });
  const client = new McpClient(proc);
  const transcript: TranscriptStep[] = [];

  await client.request("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "buyer-agent", version: "0.1.0" },
  });
  client.notify("notifications/initialized");
  const { tools } = await client.request<{ tools: Tool[] }>("tools/list");
  opts.log(`[agent] merchant offers: ${tools.map((t) => `${t.name} (€${priceFromDescription(t) ?? "?"})`).join(", ")}`);

  const call: CallTool = async (name, args) => {
    const res = await client.request<ToolResult>("tools/call", { name, arguments: args });
    transcript.push({ tool: name, arguments: args, isError: res.isError === true, text: textOf(res) });
    return res;
  };

  if (opts.brain.kind === "ollama") {
    await ollamaBrain(opts.brain.host, opts.brain.model, tools, call, opts.log);
  } else {
    await mockBrain(tools, call, opts.log);
  }

  const wrapperExitCode = await client.close();
  return { transcript, wrapperExitCode };
}
