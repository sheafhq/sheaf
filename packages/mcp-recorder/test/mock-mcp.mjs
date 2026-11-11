// Minimal mock MCP server for smoke-testing sheaf-mcp-recorder. Reads
// JSON-RPC lines on stdin and echoes back a deterministic response for any
// tools/call.
import { createInterface } from "node:readline";

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    return;
  }
  if (req.method === "tools/call") {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          content: [
            { type: "text", text: `echo: called ${req.params?.name ?? "?"}` },
          ],
          isError: false,
        },
      }) + "\n",
    );
  } else if (req.method === "initialize") {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: req.id,
        result: { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "mock", version: "0" } },
      }) + "\n",
    );
  }
});
