// Stdio-mode MCP proxy. Spawn the wrapped server, relay JSON-RPC traffic
// bidirectionally. Tap tools/call, resources/read, sampling/createMessage.
// Fail open — any error in the recorder path must NOT disrupt the agent's
// tool calls.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { RecorderClient } from "./envelope.js";
import type {
  JsonRpcRequest,
  JsonRpcResponse,
  PendingCall,
  RecorderConfig,
} from "./types.js";

export function runProxy(
  cfg: RecorderConfig,
  childCmd: string,
  childArgs: string[],
): void {
  const recorder = new RecorderClient(cfg);
  const pending = new Map<number | string, PendingCall>();

  const child = spawn(childCmd, childArgs, {
    stdio: ["pipe", "pipe", "inherit"],
    env: process.env,
  });

  child.on("exit", (code, signal) => {
    if (cfg.logDebug)
      console.error(`[arca] wrapped child exited code=${code} signal=${signal}; draining recorder queue`);
    recorder
      .drain()
      .catch((err) => {
        if (cfg.logDebug)
          console.error(`[arca] drain error: ${(err as Error).message}`);
      })
      .finally(() => {
        process.exit(code ?? 0);
      });
  });
  child.on("error", (err) => {
    console.error(`[arca] failed to spawn wrapped child: ${err.message}`);
    process.exit(127);
  });

  // Parent stdin → child stdin. Also tap each line as an outgoing request.
  const parentIn = createInterface({ input: process.stdin });
  parentIn.on("line", (line) => {
    if (!line.trim()) return;
    try {
      const msg = JSON.parse(line) as JsonRpcRequest;
      if (
        msg &&
        typeof msg === "object" &&
        "method" in msg &&
        "id" in msg &&
        cfg.captureMethods.has(msg.method)
      ) {
        pending.set(msg.id, {
          id: msg.id,
          method: msg.method,
          params: msg.params ?? {},
          startedAt: Date.now(),
        });
      }
    } catch {
      // Not valid JSON — just pass through.
    }
    child.stdin.write(line + "\n");
  });
  parentIn.on("close", () => {
    try {
      child.stdin.end();
    } catch {}
  });

  // Child stdout → parent stdout. Tap responses that match a pending request.
  const childOut = createInterface({ input: child.stdout });
  childOut.on("line", (line) => {
    if (!line.trim()) {
      process.stdout.write(line + "\n");
      return;
    }
    try {
      const msg = JSON.parse(line) as JsonRpcResponse;
      if (
        msg &&
        typeof msg === "object" &&
        "id" in msg &&
        (msg.id || msg.id === 0) &&
        pending.has(msg.id as number | string)
      ) {
        const call = pending.get(msg.id as number | string)!;
        pending.delete(msg.id as number | string);
        recorder.submit(call, { result: msg.result, error: msg.error });
      }
    } catch {
      // Not valid JSON — pass through.
    }
    process.stdout.write(line + "\n");
  });

  // Forward signals so Ctrl-C etc. kills the child cleanly.
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.on(sig, () => {
      try {
        child.kill(sig);
      } catch {}
    });
  }
}
