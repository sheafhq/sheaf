// Export a Sheaf Local session as a single `.sheaf` file (sheaf-session/1).
//
// Pulls each event's signed envelope and Merkle inclusion proof from the
// recorder's FREE read endpoints (/events and /epoch/:id/proof), so the
// simulation never touches the x402-paywalled /bundle route, and joins them
// with the local disclosure journal written by
// `sheaf-mcp-recorder --local` (@sheafhq/mcp-recorder).
//
// Exports ONE session: the most recent session/open .. session/close bracket
// for the chain in the journal. A chain can hold many sessions.

import { readFileSync, writeFileSync } from "node:fs";
import {
  JOURNAL_VERSION,
  SESSION_CLOSE_TOOL,
  SESSION_OPEN_TOOL,
  type JournalEntry,
  type Policy,
} from "@sheafhq/mcp-recorder";
import {
  SESSION_VERSION,
  type Disclosure,
  type ReceiptBundle,
  type SessionExport,
} from "./session-format.ts";

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`GET ${url} -> HTTP ${r.status}: ${await r.text()}`);
  return (await r.json()) as T;
}

export async function exportSession(opts: {
  recorderUrl: string;
  chainId: string;
  actor: string;
  issuer: { name: string; key_id: string; public_key_base64: string };
  policy: Policy;
  policyAuthority: string;
  journalPath: string;
  anchorChainId: number;
  rpcHint: string;
  anchorerAddress: string;
  outPath: string;
}): Promise<SessionExport> {
  const all = readFileSync(opts.journalPath, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as JournalEntry)
    .filter((e) => e.v === JOURNAL_VERSION && e.chain_id === opts.chainId);

  // Last session bracket in the journal.
  const openIdx = all.map((e) => e.tool).lastIndexOf(SESSION_OPEN_TOOL);
  if (openIdx === -1) throw new Error(`no ${SESSION_OPEN_TOOL} for ${opts.chainId} in ${opts.journalPath}`);
  const journal = all.slice(openIdx);
  const last = journal[journal.length - 1]!;
  if (last.tool !== SESSION_CLOSE_TOOL) throw new Error("latest session has no close event (still running?)");

  const receipts: ReceiptBundle[] = [];
  for (const entry of journal) {
    const seq = entry.seq;
    const ev = await getJson<{
      envelope: ReceiptBundle["envelope"];
      envelope_hash: string;
      epoch_id: number | null;
    }>(`${opts.recorderUrl}/events/${encodeURIComponent(opts.chainId)}/${seq}`);
    if (ev.epoch_id === null) throw new Error(`event ${seq} is not anchored yet`);
    if (ev.envelope_hash !== entry.envelope_hash)
      throw new Error(`journal seq ${seq} does not match the recorder (${entry.envelope_hash} vs ${ev.envelope_hash})`);
    const pf = await getJson<{
      leaf: string;
      leaf_index: number;
      merkle_root: string;
      siblings: ReceiptBundle["anchor"]["siblings"];
      anchor: { tx_hash: string; block: number | null };
    }>(`${opts.recorderUrl}/epoch/${ev.epoch_id}/proof/${encodeURIComponent(opts.chainId)}/${seq}`);
    receipts.push({
      version: "sheaf-bundle/1",
      envelope: ev.envelope,
      envelope_hash: ev.envelope_hash,
      chain: { chain_id: opts.chainId, seq },
      anchor: {
        epoch_id: ev.epoch_id,
        leaf_index: pf.leaf_index,
        merkle_root: pf.merkle_root,
        siblings: pf.siblings,
        tx_hash: pf.anchor.tx_hash,
        block: pf.anchor.block,
        network: `eip155:${opts.anchorChainId}`,
      },
      issuer: opts.issuer,
    });
  }

  const disclosures: Disclosure[] = journal.map((j) => ({
    seq: j.seq,
    kind: j.kind,
    inputs: j.inputs,
    outputs: j.outputs,
    ...(j.decision ? { decision: j.decision } : {}),
  }));

  const session: SessionExport = {
    version: SESSION_VERSION,
    policy_enforced: true,
    exported_at: new Date().toISOString(),
    chain_id: opts.chainId,
    actor: opts.actor,
    enforcement: {
      engine: "sheaf-local",
      policy_id: opts.policy.id,
      policy_authority: opts.policyAuthority,
    },
    policy: { authority: opts.policyAuthority, document: opts.policy },
    anchor_network: {
      chain_id: opts.anchorChainId,
      rpc_hint: opts.rpcHint,
      anchorer_address: opts.anchorerAddress,
    },
    receipts,
    disclosures,
  };
  writeFileSync(opts.outPath, JSON.stringify(session, null, 2) + "\n");
  return session;
}
