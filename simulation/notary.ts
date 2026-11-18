// Sheaf Notary: independent, offline audit of an exported agent session.
//
//   node --import tsx notary.ts <session.sheaf> [--trust <trust.json>] \
//        [--rpc http://127.0.0.1:18545] [--anchorer 0x...] [--recorder-key <base64>]
//
// "Offline" means no contact with Sheaf, the merchant or the agent. The only
// network read is the anchor transaction, from whatever chain RPC the notary
// chooses (here: the local anvil node).
//
// The notary trusts exactly two things, ideally passed out-of-band
// (individually, or together via --trust <file>):
//   --recorder-key  the recorder's published Ed25519 public key
//   --anchorer      the recorder's published anchoring address
// If omitted, it falls back to the values embedded in the bundle and says so
// (trust-on-first-use).
//
// Asserts (exit 0 only if all hold):
//   a) verdict is `VALID (complete)`
//   b) `policy_enforced: true` is present AND independently re-derived
// then prints a human-readable Notary Certificate with the event timeline.

import { readFileSync } from "node:fs";
import { hashCanonical, verify, type VerifyResult } from "@sheafhq/verify";
// Policy semantics come from the product itself, so the notary re-evaluates
// with exactly the engine that enforced.
import {
  SESSION_CLOSE_TOOL,
  SESSION_OPEN_TOOL,
  decodeIntent,
  evaluate,
  policyAuthority,
  validatePolicy,
} from "@sheafhq/mcp-recorder";
import type { SessionExport } from "./session-format.ts";

// ---- args --------------------------------------------------------------------

function usage(code: number): never {
  console.error(
    "usage: notary <session.sheaf> [--trust <trust.json>] [--rpc <url>] [--anchorer <0x...>] [--recorder-key <base64>]",
  );
  process.exit(code);
}
const argv = process.argv.slice(2);
const positional: string[] = [];
const flags: Record<string, string> = {};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i]!;
  if (a === "-h" || a === "--help") usage(0);
  if (a.startsWith("--")) flags[a.slice(2)] = argv[++i] ?? usage(2);
  else positional.push(a);
}
if (positional.length !== 1) usage(2);
const bundlePath = positional[0]!;

// ---- output helpers -----------------------------------------------------------

const useColor = process.stdout.isTTY || process.env.FORCE_COLOR === "1";
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = paint("32");
const red = paint("31");
const yellow = paint("33");
const bold = paint("1");
const dim = paint("2");

const failures: string[] = [];
function check(ok: boolean, label: string, detail?: string): boolean {
  console.log(`  ${ok ? green("✓") : red("✗")} ${label}${detail ? dim(`  ${detail}`) : ""}`);
  if (!ok) failures.push(label + (detail ? ` (${detail})` : ""));
  return ok;
}
const short = (h: string, n = 12) => (h.length > n + 2 ? `${h.slice(0, n)}…` : h);

// ---- load ------------------------------------------------------------------------

let session: SessionExport;
try {
  session = JSON.parse(readFileSync(bundlePath, "utf8")) as SessionExport;
} catch (err) {
  console.error(`notary: cannot read ${bundlePath}: ${(err as Error).message}`);
  process.exit(2);
}
if (session.version !== "sheaf-session/1" || !Array.isArray(session.receipts)) {
  console.error(`notary: ${bundlePath} is not a sheaf-session/1 export`);
  process.exit(2);
}

const receipts = session.receipts;
const n = receipts.length;
// --trust <file>: pinned trust roots as published by the recorder
// ({ recorder_public_key_base64, anchorer_address, rpc }). Flags override it.
let trust: { recorder_public_key_base64?: string; anchorer_address?: string; rpc?: string } = {};
if (flags.trust) {
  try {
    trust = JSON.parse(readFileSync(flags.trust, "utf8"));
  } catch (err) {
    console.error(`notary: cannot read trust file ${flags.trust}: ${(err as Error).message}`);
    process.exit(2);
  }
}
const rpc = flags.rpc ?? trust.rpc ?? session.anchor_network?.rpc_hint ?? "http://127.0.0.1:8545";
const pinnedAnchorer = flags.anchorer ?? trust.anchorer_address;
const pinnedKey = flags["recorder-key"] ?? trust.recorder_public_key_base64;
const anchorer = pinnedAnchorer ?? session.anchor_network?.anchorer_address;
const recorderKey = pinnedKey ?? receipts[0]?.issuer.public_key_base64;
const tofu: string[] = [];
if (!pinnedAnchorer) tofu.push("anchorer address");
if (!pinnedKey) tofu.push("recorder public key");
if (!anchorer || !recorderKey) {
  console.error("notary: no anchorer address / recorder key available");
  process.exit(2);
}

console.log(bold(`\nSheaf Notary: auditing ${bundlePath}`));
console.log(dim(`  chain ${session.chain_id} · ${n} events · anchor RPC ${rpc}`));
if (tofu.length)
  console.log(yellow(`  ! trusting ${tofu.join(" + ")} embedded in the bundle (pass --anchorer / --recorder-key to pin)`));

// ---- 1. per-receipt cryptography ---------------------------------------------------

console.log(bold("\n[1/5] Cryptographic receipts (via @sheafhq/verify)"));
const results: VerifyResult[] = [];
for (let i = 0; i < n; i++) {
  const r = receipts[i]!;
  const res = await verify(
    {
      envelope: r.envelope,
      inclusion_proof: {
        leaf: r.envelope_hash,
        leaf_index: r.anchor.leaf_index,
        merkle_root: r.anchor.merkle_root,
        siblings: r.anchor.siblings,
      },
      anchor_tx_hash: r.anchor.tx_hash,
      ...(i > 0 ? { prev_envelope: receipts[i - 1]!.envelope } : {}),
    },
    { base_rpc: rpc, recorder_public_key_base64: recorderKey, expected_anchorer_address: anchorer },
  );
  results.push(res);
  const passed = Object.values(res.checks).filter((v) => v === true).length;
  const total = Object.values(res.checks).filter((v) => v !== null).length;
  check(
    res.valid,
    `seq ${r.envelope.chain.seq} ${r.envelope.event.tool}`,
    res.valid ? `${passed}/${total} checks · block ${res.anchor_block}` : res.reason,
  );
}
const cryptoOk = n > 0 && results.every((r) => r.valid);

// ---- 2. completeness ---------------------------------------------------------------

console.log(bold("\n[2/5] Completeness (no gaps, no truncation)"));
// A session may start mid-chain (the firewall resumes existing chains). It
// must still be one unbroken run from a session/open to a session/close.
const s0 = receipts[0]?.envelope.chain.seq ?? 0;
let completeOk = check(n >= 2, "session has open + close events", `${n} events`);
completeOk =
  check(
    receipts.every((r, i) => r.envelope.chain.seq === s0 + i && r.envelope.chain.chain_id === session.chain_id),
    `contiguous seq ${s0}..${s0 + n - 1} on a single chain`,
  ) && completeOk;
completeOk =
  check(
    receipts[0]?.envelope.event.tool === SESSION_OPEN_TOOL &&
      (s0 > 0 || receipts[0]?.envelope.chain.prev_hash === null),
    s0 === 0 ? "chain starts at genesis with session/open" : `session starts with session/open at seq ${s0}`,
  ) && completeOk;

const disclosures = session.disclosures ?? [];
const bySeq = new Map(disclosures.map((d) => [d.seq, d]));
const last = receipts[n - 1];
const closeD = last ? bySeq.get(last.envelope.chain.seq) : undefined;
const closeInputs = (closeD?.inputs ?? {}) as {
  events_before_close?: number;
  last_seq_before_close?: number;
  head_hash_before_close?: string | null;
  recording_failures?: number;
};
let closeHashOk = false;
if (last && closeD) {
  closeHashOk = "sha256:" + (await hashCanonical(closeD.inputs)) === last.envelope.event.inputs_hash;
}
completeOk =
  check(
    last?.envelope.event.tool === SESSION_CLOSE_TOOL && closeHashOk,
    "session ends with a signed session/close commitment",
  ) && completeOk;
completeOk =
  check(
    closeInputs.events_before_close === n - 1 &&
      closeInputs.last_seq_before_close === s0 + n - 2 &&
      closeInputs.head_hash_before_close === receipts[n - 2]?.envelope_hash,
    "close commitment matches the exported chain",
    `commits to ${closeInputs.events_before_close} prior events, export has ${n - 1}`,
  ) && completeOk;
completeOk =
  check(closeInputs.recording_failures === 0, "firewall reported zero recording failures") && completeOk;

// ---- 3. policy binding -------------------------------------------------------------

console.log(bold("\n[3/5] Policy binding"));
let policyOk = check(session.policy_enforced === true, "`policy_enforced: true` is present");
let policy;
try {
  policy = validatePolicy(session.policy?.document);
} catch (err) {
  policyOk = check(false, "policy document is well-formed", (err as Error).message) && false;
}
let authority = "";
if (policy) {
  authority = await policyAuthority(policy);
  policyOk =
    check(authority === session.policy.authority, "policy document hashes to the declared authority", short(authority, 32)) &&
    policyOk;
  policyOk =
    check(
      receipts.every((r) => r.envelope.event.authority === authority),
      "every signed event names this exact policy as its authority",
    ) && policyOk;
}

// ---- 4. disclosure integrity ---------------------------------------------------------

console.log(bold("\n[4/5] Disclosure integrity (raw inputs/outputs vs signed hashes)"));
let disclosureOk = check(
  disclosures.length === n && receipts.every((r) => bySeq.has(r.envelope.chain.seq)),
  "one disclosure per receipt",
);
for (const r of receipts) {
  const d = bySeq.get(r.envelope.chain.seq);
  if (!d) continue;
  const inOk = "sha256:" + (await hashCanonical(d.inputs)) === r.envelope.event.inputs_hash;
  const outOk =
    d.outputs === null
      ? r.envelope.event.outputs_hash === null
      : "sha256:" + (await hashCanonical(d.outputs)) === r.envelope.event.outputs_hash;
  disclosureOk = check(inOk && outOk, `seq ${r.envelope.chain.seq} inputs + outputs match`) && disclosureOk;
}

// ---- 5. policy re-evaluation ------------------------------------------------------------

console.log(bold("\n[5/5] Independent policy re-evaluation"));
let reevalOk = true;
const toolReceipts = receipts.filter((r) => r.envelope.event.tool.startsWith("mcp://tool/"));
if (policy) {
  for (const r of toolReceipts) {
    const d = bySeq.get(r.envelope.chain.seq);
    const signed = decodeIntent(r.envelope.event.intent);
    const params = d?.inputs as { name?: string } | undefined;
    const recomputed = params ? evaluate(policy, params) : null;
    const ok =
      !!signed &&
      !!recomputed &&
      signed.effect === recomputed.effect &&
      signed.rule_id === recomputed.rule_id &&
      r.envelope.event.tool === `mcp://tool/${params?.name}` &&
      (signed.effect === "allow" || r.envelope.event.result === "error");
    reevalOk =
      check(
        ok,
        `seq ${r.envelope.chain.seq} ${params?.name ?? "?"}: signed=${signed?.effect}:${signed?.rule_id} recomputed=${recomputed?.effect}:${recomputed?.rule_id}`,
      ) && reevalOk;
  }
} else reevalOk = false;

// ---- verdict ---------------------------------------------------------------------------

const verdict = !cryptoOk ? "NOT VALID" : completeOk ? "VALID (complete)" : "VALID (incomplete)";
const policyEnforcedVerified = policyOk && disclosureOk && reevalOk && completeOk && cryptoOk;

console.log(bold("\nAssertions"));
check(verdict === "VALID (complete)", `bundle is VALID (complete)`, `got ${verdict}`);
check(policyEnforcedVerified, "policy_enforced: true is present and independently verified");

// ---- certificate -------------------------------------------------------------------------

type Args = { amount?: number; currency?: string };
const money = (a?: Args) =>
  typeof a?.amount === "number" ? `${a.currency === "EUR" || !a.currency ? "€" : a.currency + " "}${a.amount}` : "an unpriced";

const timeline: string[] = [];
let spent = 0;
for (const r of receipts) {
  const e = r.envelope.event;
  const d = bySeq.get(r.envelope.chain.seq);
  const t = e.ts.replace("T", " ").replace(/\.\d+Z$/, "Z");
  if (e.tool === SESSION_OPEN_TOOL) {
    timeline.push(`${t}  Session opened under policy "${session.policy?.document?.id}"`);
  } else if (e.tool === SESSION_CLOSE_TOOL) {
    timeline.push(`${t}  Session closed (${closeInputs.events_before_close} events committed)`);
  } else if (!e.tool.startsWith("mcp://tool/")) {
    timeline.push(`${t}  ${e.tool} (${e.result}; not governed by policy)`);
  } else {
    const params = d?.inputs as { name?: string; arguments?: Args } | undefined;
    const sig = decodeIntent(e.intent);
    const what = `${money(params?.arguments)} purchase (${params?.name})`;
    if (sig?.effect === "deny") {
      timeline.push(`${t}  Agent attempted ${what} -> BLOCKED  [${sig.rule_id}: ${d?.decision?.reason ?? ""}]`);
    } else if (e.result === "ok") {
      const order = (d?.outputs as { structuredContent?: { order_id?: string } } | null)?.structuredContent?.order_id;
      if (typeof params?.arguments?.amount === "number") spent += params.arguments.amount;
      timeline.push(
        `${t}  Agent purchased ${money(params?.arguments)} (${params?.name}) -> ALLOWED  [${sig?.rule_id}${order ? `; order ${order}` : ""}]`,
      );
    } else {
      timeline.push(`${t}  Agent attempted ${what} -> ALLOWED by policy, merchant refused`);
    }
  }
}

const anchors = [...new Map(receipts.map((r) => [r.anchor.tx_hash, r])).values()];
const certDigest = await hashCanonical({
  chain_id: session.chain_id,
  envelope_hashes: receipts.map((r) => r.envelope_hash),
  policy_authority: authority,
  verdict,
  policy_enforced: policyEnforcedVerified,
});

const W = 78;
const visibleLen = (s: string) => [...s.replace(/\x1b\[[0-9;]*m/g, "")].length;
const line = (s = "") => console.log(`│ ${s}${" ".repeat(Math.max(0, W - 4 - visibleLen(s)))} │`);
const rule = (l: string, r: string) => console.log(l + "─".repeat(W - 2) + r);

console.log("");
rule("┌", "┐");
line(bold("NOTARY CERTIFICATE · Sheaf agent-session audit"));
rule("├", "┤");
line(`Verdict           ${verdict === "VALID (complete)" ? green(verdict) : red(verdict)}`);
line(`policy_enforced   ${policyEnforcedVerified ? green("true (independently re-derived)") : red("NOT VERIFIED")}`);
line(`Agent (actor)     ${receipts[0]?.envelope.event.actor ?? "?"}`);
line(`Chain             ${session.chain_id}  (${n} events)`);
line(`Policy            ${session.policy?.document?.id}`);
line(`Policy hash       ${short(authority.replace("sheaf-policy:sha256:", ""), 40)}`);
line(`Recorder key      ${receipts[0]?.issuer.key_id}  ${short(recorderKey, 20)}`);
for (const a of anchors) {
  line(`Anchor            epoch ${a.anchor.epoch_id} · chain ${session.anchor_network?.chain_id} · block ${results[receipts.indexOf(a)]?.anchor_block ?? "?"}`);
  line(`                  tx ${short(a.anchor.tx_hash, 40)}`);
  line(`                  merkle root ${short(a.anchor.merkle_root, 32)}`);
}
line(`Total spent       €${spent}`);
rule("├", "┤");
line(bold("Timeline (from signed, anchored events)"));
for (const t of timeline) {
  // wrap long lines
  const words = t.split(/ +/);
  let cur = "";
  for (const w of words) {
    if ([...(cur + " " + w)].length > W - 6 && cur) {
      line(cur);
      cur = "                      " + w;
    } else cur = cur ? `${cur} ${w}` : w;
  }
  line(cur);
}
rule("├", "┤");
line(`Certificate digest  sha256:${short(certDigest, 40)}`);
line(dim(`Issued ${new Date().toISOString()} by sheaf-notary (offline)`));
rule("└", "┘");

if (failures.length) {
  console.log(red(`\n✗ NOTARY REJECTS: ${failures.length} check(s) failed`));
  for (const f of failures) console.log(red(`   - ${f}`));
  process.exit(1);
}
console.log(green("\n✓ NOTARY ACCEPTS: all assertions hold"));
process.exit(0);
