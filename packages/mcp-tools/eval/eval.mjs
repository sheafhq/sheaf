// 10-task eval for @sheafhq/mcp-tools tool descriptions.
//
// Premise (from the Sheaf priority plan point #2): the decider model picks
// tools from metadata, not READMEs. If a small model with the current
// tool descriptions can't reliably pick the right Sheaf tool, the bug is
// in the description — not in the agent.
//
// Setup: feed Claude Haiku each task + a 7-tool list (3 Sheaf + 4
// distractors). Score whether it picks the expected tool with sensible
// args. Report per-tool accuracy, false positives (picked Sheaf when it
// shouldn't have), and per-task outcomes.
//
// Usage from WSL:
//   cd ~/sheaf/packages/mcp-tools
//   export PATH=$HOME/.local/node/bin:$PATH
//   export ANTHROPIC_API_KEY=sk-...
//   node eval/eval.mjs
//
// Requires: @anthropic-ai/sdk installed as a devDependency.

import Anthropic from "@anthropic-ai/sdk";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

const MODEL = process.env.EVAL_MODEL ?? "claude-haiku-4-5-20251001";

// Load the canary bundle so verify tasks get a real artifact.
async function loadCanaryBundle() {
  try {
    const files = await readdir("/tmp");
    const candidates = files
      .filter((f) => f.startsWith("sheaf-canary-bundle-") && f.endsWith(".json"))
      .sort()
      .reverse();
    if (candidates.length === 0) throw new Error("no canary bundle in /tmp");
    const path = join("/tmp", candidates[0]);
    return JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    console.error(
      `WARNING: could not load canary bundle (${err.message}); verify tasks will use a synthetic stub`,
    );
    return {
      version: "sheaf-bundle/1",
      envelope: { v: "arca/1", event: { tool: "stub" }, chain: {} },
      envelope_hash: "stub",
      anchor: { tx_hash: "0xstub", merkle_root: "stub", siblings: [], leaf_index: 0 },
      issuer: { public_key_base64: "stub" },
    };
  }
}

// --- Tool definitions (mirror of what @sheafhq/mcp-tools advertises
//     via tools/list). The eval uses these verbatim so we're measuring
//     the live descriptions, not a trimmed copy. ------------------------

const SHEAF_TOOLS = [
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
      "If the chain does not exist (no events recorded), returns { head: null, note: ... } with HTTP 200. Free; no payment required.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        chain_id: { type: "string" },
      },
      required: ["chain_id"],
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
      "If the event exists but is not yet in a sealed epoch, returns { status: \"not_yet_anchored\", envelope_hash: ..., note: ... }; retry after the next epoch anchor. Free; no payment required.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        chain_id: { type: "string" },
        seq: { type: "integer", minimum: 0 },
      },
      required: ["chain_id", "seq"],
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
      "If any check fails, returns { valid: false, checks: {...}, reason: \"...\" } with the specific invariant that failed. Treat valid=false as evidence of tampering, forgery, or wrong-issuer verification — do not use the bundle's contents.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        bundle: { type: "object" },
        anchorer_address: { type: "string" },
      },
      required: ["bundle"],
    },
  },
];

const DISTRACTORS = [
  {
    name: "read_file",
    description:
      "Read the contents of a local file on the host filesystem. WHEN TO USE: the user asks you to look at a specific file by path. WHEN NOT TO USE: the user wants you to fetch data from a URL (use fetch_url) or run a command (use run_shell).",
    input_schema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
  },
  {
    name: "fetch_url",
    description:
      "HTTP GET a public URL and return the body. WHEN TO USE: user asks for live data from a website or public API (weather, stock quotes, generic REST endpoints). WHEN NOT TO USE: the user wants to cryptographically verify a document — that is sheaf_verify_bundle's job.",
    input_schema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
    },
  },
  {
    name: "search_github",
    description:
      "Search public GitHub repositories matching a query. WHEN TO USE: find packages, source, or examples related to a keyword. WHEN NOT TO USE: look up transactions, anchors, or receipts — those are not on GitHub.",
    input_schema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    },
  },
  {
    name: "run_shell",
    description:
      "Execute a shell command on the host and return stdout/stderr. WHEN TO USE: run `uname`, `df`, `ls`, or similar inspection commands. WHEN NOT TO USE: verify signed documents or check blockchain state — those are domain-specific tools.",
    input_schema: {
      type: "object",
      properties: { cmd: { type: "string" } },
      required: ["cmd"],
    },
  },
];

const ALL_TOOLS = [...SHEAF_TOOLS, ...DISTRACTORS];

// Shuffle tools so the order doesn't bias Haiku.
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// --- Task corpus ---------------------------------------------------------
// Each task has: id, prompt, expected_tool (or null if no tool should fire).
// For the verify tasks the bundle gets injected at runtime.

function buildTasks(canaryBundle) {
  return [
    // --- Sheaf-wins -----------------------------------------------------
    {
      id: "t1-verify-vendor-receipt",
      expected_tool: "sheaf_verify_bundle",
      prompt: `A vendor LLM agent just submitted this receipt to prove it completed a job. Before we accept the invoice and pay out, confirm the receipt is authentic.

Bundle:
${JSON.stringify(canaryBundle)}`,
    },
    {
      id: "t2-check-own-chain-head",
      expected_tool: "sheaf_chain_head",
      prompt:
        "My agent has been running under chain id 'contract-review-run-42'. I want to confirm all its events reached the Sheaf recorder and tell me the latest sequence number.",
    },
    {
      id: "t3-prove-event-anchored",
      expected_tool: "sheaf_get_proof_for",
      prompt:
        "The quarterly auditor wants cryptographic proof that event sequence 17 on the chain 'q3-compliance-batch' is anchored on Base mainnet. Produce the inclusion proof they can verify independently.",
    },
    {
      id: "t4-verify-untrusted-blob",
      expected_tool: "sheaf_verify_bundle",
      prompt: `This JSON came from an agent I do not trust. Determine whether it is a genuine Sheaf receipt and all internal invariants hold.

${JSON.stringify(canaryBundle)}`,
    },
    {
      id: "t5-selective-disclosure",
      expected_tool: "sheaf_get_proof_for",
      prompt:
        "For regulatory disclosure, I need to reveal exactly one specific action my agent took — event 3 of chain 'kyc-decision-2026-11-11' — without exposing the other events on the same chain. Fetch what I need to disclose.",
    },
    {
      id: "t6-event-count-audit",
      expected_tool: "sheaf_chain_head",
      prompt:
        "Our internal log claims the agent recorded 847 events on chain 'ops-daily-run-2026-11-10'. Confirm the recorder agrees — give me the event count it currently has.",
    },

    // --- Sheaf-loses (should NOT pick a Sheaf tool) ----------------------
    {
      id: "t7-read-local-file",
      expected_tool: "read_file",
      prompt: "What does /etc/hostname contain on this machine?",
    },
    {
      id: "t8-weather-fetch",
      expected_tool: "fetch_url",
      prompt:
        "Fetch today's weather forecast for San Francisco from a public weather API.",
    },
    {
      id: "t9-github-search",
      expected_tool: "search_github",
      prompt:
        "Find public GitHub repositories matching the query 'awesome-mcp-servers' so I can see which lists we should submit to.",
    },
    {
      id: "t10-run-shell",
      expected_tool: "run_shell",
      prompt:
        "Run `uname -a` on this host and tell me the OS and kernel version.",
    },
  ];
}

// --- Harness -----------------------------------------------------------

async function runOne(client, tools, task) {
  const resp = await client.messages.create({
    model: MODEL,
    max_tokens: 1024,
    tools,
    tool_choice: { type: "auto" },
    messages: [{ role: "user", content: task.prompt }],
  });
  const toolUses = resp.content.filter((b) => b.type === "tool_use");
  const picked = toolUses[0]; // first tool call
  return {
    id: task.id,
    expected: task.expected_tool,
    picked: picked ? picked.name : null,
    args_keys: picked ? Object.keys(picked.input ?? {}) : [],
    correct: picked && picked.name === task.expected_tool,
    stop_reason: resp.stop_reason,
    content_text:
      resp.content.find((b) => b.type === "text")?.text?.slice(0, 200) ?? "",
  };
}

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error("ANTHROPIC_API_KEY env var required");
    process.exit(1);
  }
  const client = new Anthropic();
  const canaryBundle = await loadCanaryBundle();
  const tasks = buildTasks(canaryBundle);
  const tools = shuffle(ALL_TOOLS);

  console.log(`model: ${MODEL}`);
  console.log(`tasks: ${tasks.length}  tools: ${tools.length}`);
  console.log("");

  const results = [];
  for (const t of tasks) {
    try {
      const r = await runOne(client, tools, t);
      results.push(r);
      const mark = r.correct ? "✓" : "✗";
      console.log(
        `${mark}  ${r.id.padEnd(30)} expected=${(r.expected ?? "none").padEnd(22)} picked=${r.picked ?? "none"}`,
      );
    } catch (err) {
      console.log(`!  ${t.id.padEnd(30)} ERROR: ${err.message}`);
      results.push({
        id: t.id,
        expected: t.expected_tool,
        picked: null,
        correct: false,
        error: err.message,
      });
    }
  }

  // --- Summary ----------------------------------------------------------
  const total = results.length;
  const correct = results.filter((r) => r.correct).length;
  const sheafNames = SHEAF_TOOLS.map((t) => t.name);
  const sheafWinsExpected = results.filter((r) =>
    sheafNames.includes(r.expected),
  );
  const sheafWinsHit = sheafWinsExpected.filter((r) => r.correct).length;
  const sheafLosesExpected = results.filter(
    (r) => !sheafNames.includes(r.expected),
  );
  const falsePositives = sheafLosesExpected.filter(
    (r) => r.picked && sheafNames.includes(r.picked),
  ).length;

  console.log("");
  console.log("summary:");
  console.log(`  overall correct:          ${correct}/${total}`);
  console.log(
    `  sheaf-wins recall:        ${sheafWinsHit}/${sheafWinsExpected.length}  (sheaf tool picked when expected)`,
  );
  console.log(
    `  sheaf-loses false-pos:    ${falsePositives}/${sheafLosesExpected.length}  (sheaf picked when it shouldn't be)`,
  );

  const perTool = {};
  for (const name of sheafNames) {
    const expectedForTool = results.filter((r) => r.expected === name);
    const hits = expectedForTool.filter((r) => r.correct).length;
    perTool[name] = `${hits}/${expectedForTool.length}`;
  }
  console.log("  per-sheaf-tool recall:");
  for (const [name, score] of Object.entries(perTool)) {
    console.log(`    ${name.padEnd(24)} ${score}`);
  }

  console.log("");
  console.log("misses:");
  for (const r of results.filter((r) => !r.correct)) {
    console.log(
      `  ${r.id}: expected ${r.expected}, got ${r.picked ?? "none"}${r.error ? " (" + r.error + ")" : ""}`,
    );
    if (r.content_text) {
      console.log(`    model said: ${r.content_text.replace(/\n/g, " ")}`);
    }
  }

  process.exit(correct === total ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
