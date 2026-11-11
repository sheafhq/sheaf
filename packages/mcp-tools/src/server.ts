// Stdio MCP server. Reads JSON-RPC lines from stdin, writes responses to
// stdout. No SSE / HTTP transport — this is designed to be launched by an
// MCP-compatible client (Claude Desktop, Cline, etc.) and speak JSON-RPC
// directly over stdio.

import { createInterface } from "node:readline";
import {
  chainHead,
  getProofFor,
  verifyBundle,
  type ToolContext,
} from "./tools.js";

type JsonRpcRequest = {
  jsonrpc: "2.0";
  id: number | string | null;
  method: string;
  params?: Record<string, unknown>;
};

type JsonRpcResponse =
  | {
      jsonrpc: "2.0";
      id: number | string | null;
      result: unknown;
    }
  | {
      jsonrpc: "2.0";
      id: number | string | null;
      error: { code: number; message: string };
    };

// Tool definitions sent in reply to tools/list. The decider model chooses
// among these entirely from the description + inputSchema — so the
// descriptions below are the product, not a doc. Every field documented;
// an example call + example response in each description.
const TOOL_DEFS = [
  {
    name: "sheaf_chain_head",
    description: [
      "Return the current head (latest sequence number + hash) of a Sheaf chain.",
      "",
      "WHEN TO USE: You have a chain_id (an agent-run identifier recorded on Sheaf) and want to check what the latest event is, how many events exist, or whether the chain exists at all. Common uses: verify that your own agent's events reached the recorder; synchronize local state after a crash; prove to an auditor that no events were recorded on a given chain.",
      "",
      "WHEN NOT TO USE: You want to verify a specific receipt — use sheaf_verify_bundle instead. You want to prove an event is anchored on-chain — use sheaf_get_proof_for. You want to CREATE a new event — this tool is read-only; events are created transparently by the @sheafhq/mcp-recorder proxy.",
      "",
      "EXAMPLE CALL:",
      '  { "chain_id": "agent-run-2026-11-11-smoke" }',
      "",
      "EXAMPLE RESPONSE:",
      '  { "chain_id": "agent-run-2026-11-11-smoke", "head_seq": 42, "head_hash": "26795706...4951f12", "event_count": 43, "created_at_unix": 1794367540, "updated_at_unix": 1794367611, "source_url": "https://sheaf-recorder.goldencalf.workers.dev/chains/agent-run-2026-11-11-smoke/head" }',
      "",
      "If the chain does not exist (no events recorded), returns { head: null, note: ... } with HTTP 200. Free; no payment required.",
    ].join("\n"),
    inputSchema: {
      type: "object",
      properties: {
        chain_id: {
          type: "string",
          description:
            "Stable identifier the recorder uses to group related events in order. Typically matches what the operator set in SHEAF_CHAIN_ID when running the recorder. Required.",
        },
      },
      required: ["chain_id"],
      additionalProperties: false,
    },
  },
  {
    name: "sheaf_get_proof_for",
    description: [
      "Return a Merkle inclusion proof for one specific event (chain_id + seq) along with its on-chain anchor reference.",
      "",
      "WHEN TO USE: You want to prove to a third party that a specific recorded event is included in the Sheaf chain and committed on Base mainnet. Common uses: attach compliance evidence to an agent output; selectively disclose one action from a longer chain; let an external auditor independently check the proof against the on-chain anchor.",
      "",
      "WHEN NOT TO USE: You want to verify a receipt the other party already sent you — use sheaf_verify_bundle. You want to query chain state generally — use sheaf_chain_head. You want to buy the bundled + self-contained artifact — call GET /bundle/:chain_id/:seq on the recorder with an x402 payment ($0.001 USDC on Base); this tool returns the proof components for free but does not include the full signed envelope.",
      "",
      "EXAMPLE CALL:",
      '  { "chain_id": "agent-run-2026-11-11-smoke", "seq": 7 }',
      "",
      "EXAMPLE RESPONSE (anchored):",
      '  { "status": "anchored", "chain_id": "agent-run-...", "seq": 7, "epoch_id": 42, "leaf": "sha256:...", "leaf_index": 3, "merkle_root": "...", "siblings": [{"hash": "...", "side": "right"}, ...], "anchor": { "tx_hash": "0xc65349...", "block": 55369354, "explorer": "https://basescan.org/tx/0xc65349..." }, "verification_note": "..." }',
      "",
      "If the event exists but is not yet in a sealed epoch, returns { status: \"not_yet_anchored\", envelope_hash: ..., note: ... }; retry after the next epoch anchor. Free; no payment required.",
    ].join("\n"),
    inputSchema: {
      type: "object",
      properties: {
        chain_id: {
          type: "string",
          description: "Chain identifier. Required.",
        },
        seq: {
          type: "integer",
          minimum: 0,
          description:
            "Sequence number of the event within the chain (0-indexed). Required.",
        },
      },
      required: ["chain_id", "seq"],
      additionalProperties: false,
    },
  },
  {
    name: "sheaf_verify_bundle",
    description: [
      "Verify a Sheaf receipt bundle end-to-end: signature, Merkle inclusion, and on-chain anchor. Pure read; makes one RPC call to Base to confirm the anchor transaction, no payment required.",
      "",
      "WHEN TO USE: A counterparty, auditor, or upstream agent gave you a Sheaf bundle (version sheaf-bundle/1 from the paid /bundle endpoint, or the legacy {envelope, inclusion_proof, anchor_tx_hash} shape) and you need to confirm it is authentic and intact BEFORE acting on its contents. Common uses: gate agent workflows on independently verified evidence; log a receipt into your own audit trail only after validation; reject counterfeit or tampered bundles before they influence downstream decisions.",
      "",
      "WHEN NOT TO USE: You just want to look up what events exist — use sheaf_chain_head. You want a proof but don't have a bundle — use sheaf_get_proof_for. You want to CREATE a bundle for one of your own events — call GET /bundle/:chain_id/:seq on the recorder with an x402 payment.",
      "",
      "EXAMPLE CALL:",
      '  { "bundle": { "version": "sheaf-bundle/1", "envelope": {...}, "envelope_hash": "...", "anchor": {...}, "issuer": {...}, ... } }',
      "",
      "EXAMPLE RESPONSE:",
      '  { "valid": true, "checks": { "anchor_on_chain": true, "anchor_from_authorized_wallet": true, "merkle_root_matches_on_chain": true, "inclusion_proof_reproduces_root": true, "envelope_hash_matches_leaf": true, "recorder_signature_verifies": true, "chain_prev_hash_matches": null }, "anchor_block": 55369354, "recorder": "https://sheaf-recorder.goldencalf.workers.dev", "anchorer_checked": "0x08A22c..." }',
      "",
      "If any check fails, returns { valid: false, checks: {...}, reason: \"...\" } with the specific invariant that failed. Treat valid=false as evidence of tampering, forgery, or wrong-issuer verification — do not use the bundle's contents.",
    ].join("\n"),
    inputSchema: {
      type: "object",
      properties: {
        bundle: {
          type: "object",
          description:
            "The Sheaf bundle to verify. Accepts the sheaf-bundle/1 shape (preferred) or the legacy { envelope, inclusion_proof, anchor_tx_hash } shape. Required.",
        },
        anchorer_address: {
          type: "string",
          description:
            "Optional. 0x-prefixed Ethereum address expected to have sent the anchor tx. Defaults to the canonical sheaf-recorder anchorer. Only override this if verifying against a non-default Sheaf deployment.",
        },
      },
      required: ["bundle"],
      additionalProperties: false,
    },
  },
] as const;

function ok(id: JsonRpcRequest["id"], result: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

function err(
  id: JsonRpcRequest["id"],
  code: number,
  message: string,
): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function handle(
  req: JsonRpcRequest,
  ctx: ToolContext,
): Promise<JsonRpcResponse | null> {
  const id = req.id ?? null;
  switch (req.method) {
    case "initialize":
      return ok(id, {
        protocolVersion: "2025-03-26",
        capabilities: { tools: {} },
        serverInfo: { name: "sheaf-mcp-tools", version: "0.1.0" },
      });
    case "tools/list":
      return ok(id, { tools: TOOL_DEFS });
    case "tools/call": {
      const params = (req.params ?? {}) as {
        name?: string;
        arguments?: Record<string, unknown>;
      };
      const args = params.arguments ?? {};
      try {
        let data: unknown;
        switch (params.name) {
          case "sheaf_chain_head":
            data = await chainHead(ctx, args as { chain_id: string });
            break;
          case "sheaf_get_proof_for":
            data = await getProofFor(
              ctx,
              args as { chain_id: string; seq: number },
            );
            break;
          case "sheaf_verify_bundle":
            data = await verifyBundle(
              ctx,
              args as { bundle: unknown; anchorer_address?: string },
            );
            break;
          default:
            return ok(id, {
              content: [
                {
                  type: "text",
                  text: `unknown tool: ${params.name}`,
                },
              ],
              isError: true,
            });
        }
        return ok(id, {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
          isError: false,
        });
      } catch (e) {
        return ok(id, {
          content: [
            {
              type: "text",
              text: `error: ${(e as Error).message}`,
            },
          ],
          isError: true,
        });
      }
    }
    case "notifications/initialized":
    case "notifications/cancelled":
      // Notifications have no response.
      return null;
    default:
      return err(id, -32601, `method not found: ${req.method}`);
  }
}

export function runServer(ctx: ToolContext): void {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let req: JsonRpcRequest;
    try {
      req = JSON.parse(line) as JsonRpcRequest;
    } catch {
      return;
    }
    // Do not await inline — concurrent in-flight requests are allowed.
    handle(req, ctx)
      .then((res) => {
        if (res) process.stdout.write(JSON.stringify(res) + "\n");
      })
      .catch((e) => {
        process.stdout.write(
          JSON.stringify(err(req.id ?? null, -32603, (e as Error).message)) +
            "\n",
        );
      });
  });
}
