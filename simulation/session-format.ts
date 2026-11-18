// sheaf-session/1: the exported `.sheaf` file for a whole policy-governed
// agent session.
//
// It is deliberately a thin wrapper around N standard `sheaf-bundle/1`
// receipts (the same shape GET /bundle/:chain/:seq returns), so every receipt
// in it can also be checked on its own with `npx @sheafhq/verify`.
//
// What is signed + anchored (cannot be altered without detection):
//   receipts[i].envelope   -- intent (incl. policy decision), authority
//                             (policy hash), tool, inputs_hash, outputs_hash,
//                             result, ts, chain seq + prev_hash
//
// What is disclosed in the clear and checked AGAINST the signed data:
//   policy.document        -- must hash to every envelope's authority
//   disclosures[i].inputs  -- must hash to receipts[i].envelope.event.inputs_hash
//   disclosures[i].outputs -- must hash to receipts[i].envelope.event.outputs_hash
//
// `policy_enforced: true` is a CLAIM made by the exporter. The notary only
// accepts it after re-deriving it from the signed data.

import type { Decision, Policy } from "@sheafhq/mcp-recorder";

export const SESSION_VERSION = "sheaf-session/1";

export type Sibling = { hash: string; side: "left" | "right" };

export type ReceiptBundle = {
  version: "sheaf-bundle/1";
  envelope: {
    v: "arca/1";
    event: {
      intent: string;
      actor: string;
      authority: string | null;
      tool: string;
      inputs_hash: string;
      outputs_hash: string | null;
      result: "ok" | "error" | "timeout" | "cancelled";
      ts: string;
    };
    chain: { chain_id: string; seq: number; prev_hash: string | null };
    signatures: { actor: string | null; recorder: string };
  };
  envelope_hash: string;
  chain: { chain_id: string; seq: number };
  anchor: {
    epoch_id: number;
    leaf_index: number;
    merkle_root: string;
    siblings: Sibling[];
    tx_hash: string;
    block: number | null;
    network: string;
  };
  issuer: { name: string; key_id: string; public_key_base64: string };
};

export type Disclosure = {
  seq: number;
  kind: "session_open" | "tool_call" | "passthrough" | "session_close";
  inputs: unknown;
  outputs: unknown | null;
  decision?: Decision;
};

export type SessionExport = {
  version: typeof SESSION_VERSION;
  policy_enforced: boolean;
  exported_at: string;
  chain_id: string;
  actor: string;
  enforcement: { engine: "sheaf-local"; policy_id: string; policy_authority: string };
  policy: { authority: string; document: Policy };
  anchor_network: { chain_id: number; rpc_hint: string; anchorer_address: string };
  receipts: ReceiptBundle[];
  disclosures: Disclosure[];
};
