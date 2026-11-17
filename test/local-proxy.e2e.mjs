// Real end-to-end local proxy test: dummy MCP server, --local wrap, blocked
// call, allowed call, local export, offline verify. Run with:
//   node test/local-proxy.e2e.mjs
// This test spawns child processes; run it outside the restricted sandbox.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import {
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";

import { runCli } from "../dist-cli/cli.js";

const dir = "test/tmp-local-proxy";
const chainDir = join(dir, ".sheaf");
rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });
mkdirSync(chainDir, { recursive: true });

const policyPath = "test/fixtures/dispute-walking/policy.json";
const policy = JSON.parse(readFileSync(policyPath, "utf8"));

for (const file of ["mandate", "delegation", "consent"]) {
  const doc = JSON.parse(readFileSync(`test/fixtures/evidence/${file}.json`, "utf8"));
  if (doc.scope) {
    doc.scope.valid_until = "2027-11-11T16:30:00Z";
    doc.expires_at = "2027-11-11T16:30:00Z";
  }
  writeFileSync(join(dir, `${file}.json`), JSON.stringify(doc, null, 2));
}

const args = {
  merchant: "northwind-outfitters.example",
  amount_minor: 12900,
  currency: "USD",
  order_id: "order_demo_001",
  mandate_id: "mnd_demo_001",
  consent_id: "consent_demo_001",
};
const blockedArgs = { ...args, amount_minor: 20000, order_id: "order_demo_blocked_001" };
const casePath = join(dir, "case.json");
const manifest = {
  case: {
    case_id: "CB-LOCAL-E2E-001",
    card_network: "visa",
    reason_code: {
      schema: "2026 Visa Claims Resolution guide",
      value: "10.4",
      label: "Other fraud",
    },
    transaction: {
      reference: "txn_local_e2e_001",
      amount_minor: 12900,
      currency: "USD",
      occurred_at: new Date().toISOString(),
    },
    merchant: {
      id: "merchant_local",
      name: "Northwind Outfitters",
      url: "https://northwind-outfitters.example",
    },
    response_due_at: "2026-11-24T23:59:59Z",
    dispute_basis: {
      category: "friendly_fraud",
      asserted_by: "merchant",
      merchant_position: "Policy blocked the over-limit transfer.",
    },
    created_at: new Date(Date.now() + 60_000).toISOString(),
  },
  subject: {
    from_seq: 4,
    to_seq: 5,
    disputed_event_seqs: [4],
    claims: {
      agent_id: { value: "agent://shopper-7", derived_from: "event.actor", ref: "seq:4" },
      tool: { value: "mcp://shop/payment", derived_from: "event.tool", ref: "seq:4" },
      merchant: { value: args.merchant, derived_from: "payload", ref: "pl_4_args", path: "$.merchant" },
      amount_minor: { value: 12900, derived_from: "payload", ref: "pl_4_args", path: "$.amount_minor" },
      currency: { value: "USD", derived_from: "payload", ref: "pl_4_args", path: "$.currency" },
    },
  },
  evidence: {
    mandate: { seq: 1, document: "mandate.json" },
    delegation: { chain: [{ seq: 2, parent_seq: 1, document: "delegation.json" }] },
    consent: { seq: 3, document: "consent.json" },
  },
  payloads: [
    { seq: 4, kind: "tool_arguments", path: ".sheaf/payloads/000004-arguments.json" },
    { seq: 4, kind: "tool_result", path: ".sheaf/payloads/000004-result.json" },
    { seq: 5, kind: "tool_arguments", path: ".sheaf/payloads/000005-arguments.json" },
  ],
};
writeFileSync(casePath, JSON.stringify(manifest, null, 2));

const dummy = join(dir, "dummy-mcp.mjs");
writeFileSync(
  dummy,
  [
    'import { createInterface } from "node:readline";',
    'const rl = createInterface({ input: process.stdin });',
    'rl.on("line", (line) => {',
    '  let msg; try { msg = JSON.parse(line); } catch { return; }',
    '  if (msg.method === "tools/call") {',
    '    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { status: "authorized", order_id: msg.params?.arguments?.order_id } }) + "\\n");',
    '  }',
    '});',
    "",
  ].join("\n"),
);

const proxy = spawn(
  process.execPath,
  [
    "packages/mcp-recorder/dist/cli.js",
    "wrap",
    "--local",
    "--policy",
    policyPath,
    "--chain-dir",
    chainDir,
    "--case",
    casePath,
    process.execPath,
    dummy,
  ],
  { stdio: ["pipe", "pipe", "inherit"] },
);

const responses = new Map();
const rl = createInterface({ input: proxy.stdout });
rl.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.id !== undefined) responses.set(msg.id, msg);
  } catch {}
});

function send(id, arguments_) {
  proxy.stdin.write(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: "mcp://shop/payment", arguments: arguments_ },
    }) + "\n",
  );
}

async function waitFor(id, timeoutMs = 10_000) {
  const started = Date.now();
  while (!responses.has(id)) {
    if (Date.now() - started > timeoutMs) throw new Error(`timeout waiting for id ${id}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  return responses.get(id);
}

await new Promise((r) => setTimeout(r, 300));
send(1, args);
const allowed = await waitFor(1);
assert.equal(allowed.result?.status, "authorized");

send(2, blockedArgs);
const blocked = await waitFor(2);
assert.equal(blocked.error?.code, -32001);
assert.equal(blocked.error?.data?.reason_code, "amount_exceeds_limit");
console.log("BLOCKED_RESPONSE " + JSON.stringify(blocked));

send(3, args);
const allowedAgain = await waitFor(3);
assert.equal(allowedAgain.result?.status, "authorized");

proxy.kill("SIGTERM");
await new Promise((resolve) => proxy.once("exit", resolve));

const ledger = readFileSync(join(chainDir, "ledger.jsonl"), "utf8")
  .trim()
  .split("\n")
  .map((line) => JSON.parse(line));
console.log(
  "LEDGER " +
    ledger
      .map((row) => `${row.seq}:${row.envelope.event.kind}:${row.envelope.event.result}:${row.envelope.event.policy?.verdict ?? "-"}`)
      .join(","),
);
assert.equal(ledger.length, 7);
assert.equal(ledger[0].envelope.event.kind, "policy");
assert.equal(ledger[4].envelope.event.result, "ok");
assert.equal(ledger[5].envelope.event.result, "blocked");
assert.equal(ledger[5].envelope.event.policy.verdict, "BLOCK");
assert.equal(ledger[6].envelope.event.result, "ok");

const out = join(dir, "bundle.sheaf");
const exportCode = await runCli([
  "local",
  "export",
  "--chain-dir",
  chainDir,
  "--case",
  casePath,
  "--out",
  out,
]);
assert.equal(exportCode, 0);

const verifyCode = await runCli([
  "dispute",
  "verify",
  out,
  "--offline",
  "--trust",
  join(chainDir, "trust.json"),
]);
assert.equal(verifyCode, 0);

console.log(`LOCAL_BUNDLE ${out}`);
