// Policy enforcement at the MCP boundary.
//
// This module is the decision layer used by the stdio proxy. It is kept
// separate so the exact JSON-RPC rejection shape is testable without spawning
// a child MCP server.

import { evaluatePolicy, type PolicyDecision } from "./policy.js";
import type {
  JsonRpcRequest,
  JsonRpcResponse,
  PendingCall,
  PolicyMetadata,
  RecorderConfig,
} from "./types.js";

export type BlockedRecorder = {
  submitBlocked(
    call: PendingCall,
    decision: PolicyDecision,
    policyHash: string,
  ): void;
};

export type EnforceResult =
  | { action: "forward"; call: PendingCall }
  | {
      action: "blocked";
      call: PendingCall;
      response: JsonRpcResponse;
    };

export function policyMetadata(
  policyHash: string,
  decision: PolicyDecision,
): PolicyMetadata {
  return {
    schema: "sheaf.policy/1",
    hash: policyHash,
    verdict: decision.verdict,
    reason_code: decision.reason_code,
  };
}

export function buildBlockedResponse(
  id: number | string,
  decision: PolicyDecision,
  policyHash: string,
): JsonRpcResponse {
  const approval = decision.verdict === "REQUIRE_APPROVAL";
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: approval ? -32002 : -32001,
      message: approval
        ? "Approval required by Sheaf policy"
        : "Blocked by Sheaf policy",
      data: {
        sheaf: true,
        verdict: decision.verdict,
        code: decision.code,
        reason_code: decision.reason_code,
        policy_hash: policyHash,
      },
    },
  };
}

/**
 * Evaluate a tools/call against cfg.policy.
 *
 * Returns null for non-tool calls or when no policy is configured. On BLOCK or
 * REQUIRE_APPROVAL, the blocked attempt is queued for recording and a
 * structured JSON-RPC error is returned; the caller must NOT forward it.
 */
export function enforceToolCall(
  msg: JsonRpcRequest,
  cfg: RecorderConfig,
  recorder: BlockedRecorder,
): EnforceResult | null {
  if (msg.method !== "tools/call" || !cfg.policy || !cfg.policyHash) {
    return null;
  }

  const params = msg.params as
    | { name?: string; arguments?: unknown }
    | undefined;
  const tool = params?.name;
  if (typeof tool !== "string" || tool.length === 0) {
    const decision: PolicyDecision = {
      verdict: "BLOCK",
      code: "POLICY_VIOLATION",
      reason_code: "missing_tool_name",
    };
    const call: PendingCall = {
      id: msg.id,
      method: msg.method,
      params: msg.params ?? {},
      startedAt: Date.now(),
      policy: policyMetadata(cfg.policyHash, decision),
    };
    recorder.submitBlocked(call, decision, cfg.policyHash);
    return {
      action: "blocked",
      call,
      response: buildBlockedResponse(msg.id, decision, cfg.policyHash),
    };
  }

  const args = params?.arguments ?? {};
  const decision = evaluatePolicy(tool, args, cfg.policy);
  const call: PendingCall = {
    id: msg.id,
    method: msg.method,
    params: msg.params ?? {},
    startedAt: Date.now(),
    policy: policyMetadata(cfg.policyHash, decision),
  };

  if (decision.verdict !== "ALLOW") {
    recorder.submitBlocked(call, decision, cfg.policyHash);
    return {
      action: "blocked",
      call,
      response: buildBlockedResponse(msg.id, decision, cfg.policyHash),
    };
  }

  return { action: "forward", call };
}
