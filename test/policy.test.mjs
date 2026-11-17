// Layer 4: policy evaluator, MCP enforcement, and recorder event binding.

import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webcrypto } from "node:crypto";

import {
  buildBlockedResponse,
  enforceToolCall,
} from "../packages/mcp-recorder/dist/enforce.js";
import {
  evaluatePolicy,
  validatePolicy,
} from "../packages/mcp-recorder/dist/policy.js";
import { RecorderClient } from "../packages/mcp-recorder/dist/envelope.js";
import {
  canonicalize,
  hashCanonical,
} from "../packages/mcp-recorder/dist/canonical.js";
import {
  evaluatePolicy as verifyEvaluate,
  validatePolicy as verifyValidate,
  verifyDisputeBundle,
} from "../packages/verify/dist/index.js";
import { buildMerkleTree } from "../.test-dist/merkle.js";
import { runCli } from "../dist-cli/cli.js";

const { subtle } = webcrypto;

const policy = JSON.parse(
  readFileSync("test/fixtures/policy/payments.json", "utf8"),
);
const policyHash = "sha256:" + hashCanonical(policy);

const allowedArgs = {
  amount: 12900,
  currency: "USD",
  order_id: "order_demo_001",
  merchant: "https://northwind-outfitters.example",
};
const blockedArgs = { ...allowedArgs, amount: 20000 };

function req(id, args) {
  return {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: "payments.transfer", arguments: args },
  };
}

test("policy schema and evaluator: allow, block, deny, required, domain", () => {
  assert.deepEqual(validatePolicy(policy), []);
  assert.deepEqual(verifyValidate(policy), []);
  assert.ok(
    validatePolicy({ ...policy, default_verdict: "MAYBE" }).some((e) =>
      e.includes("default_verdict"),
    ),
  );
  assert.ok(
    validatePolicy({ ...policy, unexpected: true }).some((e) =>
      e.includes("unexpected field"),
    ),
  );

  const allowed = evaluatePolicy("payments.transfer", allowedArgs, policy);
  assert.equal(allowed.verdict, "ALLOW");
  assert.equal(allowed.code, "POLICY_ALLOW");
  assert.equal(verifyEvaluate("payments.transfer", allowedArgs, policy).verdict, "ALLOW");

  const amount = evaluatePolicy("payments.transfer", blockedArgs, policy);
  assert.equal(amount.verdict, "BLOCK");
  assert.equal(amount.reason_code, "amount_exceeds_limit");

  const currency = evaluatePolicy(
    "payments.transfer",
    { ...allowedArgs, currency: "EUR" },
    policy,
  );
  assert.equal(currency.verdict, "BLOCK");
  assert.equal(currency.reason_code, "currency_not_usd");

  const missing = evaluatePolicy(
    "payments.transfer",
    { ...allowedArgs, order_id: undefined },
    policy,
  );
  assert.equal(missing.verdict, "BLOCK");
  assert.equal(missing.reason_code, "order_id_required");

  const domain = evaluatePolicy(
    "payments.transfer",
    { ...allowedArgs, merchant: "https://evil.example" },
    policy,
  );
  assert.equal(domain.verdict, "BLOCK");
  assert.equal(domain.reason_code, "merchant_domain_not_allowed");

  const denied = evaluatePolicy("admin.delete", {}, policy);
  assert.equal(denied.verdict, "BLOCK");
  assert.equal(denied.reason_code, "tool_denied");

  const approvalPolicy = {
    ...policy,
    rules: [
      {
        tool: "payments.transfer",
        verdict: "REQUIRE_APPROVAL",
        constraints: [],
      },
    ],
  };
  const approval = evaluatePolicy(
    "payments.transfer",
    allowedArgs,
    approvalPolicy,
  );
  assert.equal(approval.verdict, "REQUIRE_APPROVAL");
  assert.equal(approval.code, "POLICY_APPROVAL_REQUIRED");
});

test("MCP enforcement: allowed forwards, blocked returns exact JSON-RPC error", () => {
  const blocked = [];
  const recorder = {
    submitBlocked(call, decision, hash) {
      blocked.push({ call, decision, hash });
    },
  };
  const cfg = {
    recorderUrls: ["https://rec.test"],
    chainId: "policy-test",
    actor: "agent:test",
    captureMethods: new Set(["tools/call"]),
    logDebug: false,
    policy,
    policyHash,
  };

  const allowed = enforceToolCall(req(1, allowedArgs), cfg, recorder);
  assert.equal(allowed.action, "forward");
  assert.equal(allowed.call.policy.verdict, "ALLOW");
  assert.equal(allowed.call.policy.hash, policyHash);

  const blockedResult = enforceToolCall(req(2, blockedArgs), cfg, recorder);
  assert.equal(blockedResult.action, "blocked");
  assert.equal(blocked.length, 1);
  assert.equal(blocked[0].decision.verdict, "BLOCK");
  assert.equal(blocked[0].decision.reason_code, "amount_exceeds_limit");

  assert.deepEqual(blockedResult.response, {
    jsonrpc: "2.0",
    id: 2,
    error: {
      code: -32001,
      message: "Blocked by Sheaf policy",
      data: {
        sheaf: true,
        verdict: "BLOCK",
        code: "POLICY_VIOLATION",
        reason_code: "amount_exceeds_limit",
        policy_hash: policyHash,
      },
    },
  });
});

test("recorder writes policy first, then blocked and allowed tool events", async () => {
  const originalFetch = globalThis.fetch;
  const posts = [];
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith("/chains/policy-chain/head")) {
      return new Response("not found", { status: 404 });
    }
    if (String(url).endsWith("/events")) {
      const envelope = JSON.parse(String(init?.body ?? "{}"));
      posts.push(envelope);
      return new Response(
        JSON.stringify({
          ok: true,
          seq: posts.length - 1,
          envelope_hash: hashCanonical({
            v: envelope.v,
            event: envelope.event,
            chain: envelope.chain,
          }),
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected fetch ${url}`);
  };

  try {
    const recorder = new RecorderClient({
      recorderUrls: ["https://rec.test"],
      chainId: "policy-chain",
      actor: "agent:test",
      captureMethods: new Set(["tools/call"]),
      logDebug: false,
      policy,
      policyHash,
    });

    const decision = evaluatePolicy("payments.transfer", blockedArgs, policy);
    recorder.submitBlocked(
      {
        id: 9,
        method: "tools/call",
        params: { name: "payments.transfer", arguments: blockedArgs },
        startedAt: Date.now(),
        policy: {
          schema: "sheaf.policy/1",
          hash: policyHash,
          verdict: "BLOCK",
          reason_code: "amount_exceeds_limit",
        },
      },
      decision,
      policyHash,
    );
    await recorder.drain();

    assert.equal(posts.length, 2);
    assert.equal(posts[0].event.kind, "policy");
    assert.equal(posts[0].event.tool, "sheaf.policy");
    assert.equal(posts[0].event.inputs_hash, policyHash);

    assert.equal(posts[1].event.kind, "tool_call");
    assert.equal(posts[1].event.result, "blocked");
    assert.equal(posts[1].event.outputs_hash, null);
    assert.equal(posts[1].event.policy.verdict, "BLOCK");
    assert.equal(posts[1].event.policy.reason_code, "amount_exceeds_limit");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

async function makeKey() {
  const pair = await subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  return {
    privateKey: pair.privateKey,
    publicKeyBase64: Buffer.from(raw).toString("base64"),
  };
}

async function signCore(key, core) {
  const signature = new Uint8Array(
    await subtle.sign(
      "Ed25519",
      key.privateKey,
      new TextEncoder().encode(canonicalize(core)),
    ),
  );
  return Buffer.from(signature).toString("base64");
}

async function capture(fn) {
  const original = process.stdout.write;
  let text = "";
  process.stdout.write = (chunk) => {
    text += String(chunk);
    return true;
  };
  try {
    const code = await fn();
    return { code, text };
  } finally {
    process.stdout.write = original;
  }
}

test("bundle with policy verifies policy_enforced: true", async () => {
  const key = await makeKey();
  const dir = mkdtempSync(join(tmpdir(), "sheaf-policy-bundle-"));
  const posts = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith("/chains/policy-chain/head")) {
      return new Response("not found", { status: 404 });
    }
    if (String(url).endsWith("/events")) {
      const envelope = JSON.parse(String(init?.body ?? "{}"));
      posts.push(envelope);
      return new Response(
        JSON.stringify({
          ok: true,
          seq: posts.length - 1,
          envelope_hash: hashCanonical({
            v: envelope.v,
            event: envelope.event,
            chain: envelope.chain,
          }),
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected fetch ${url}`);
  };

  try {
    const recorder = new RecorderClient({
      recorderUrls: ["https://rec.test"],
      chainId: "policy-chain",
      actor: "agent:test",
      captureMethods: new Set(["tools/call"]),
      logDebug: false,
      policy,
      policyHash,
    });
    const allowedDecision = evaluatePolicy(
      "payments.transfer",
      allowedArgs,
      policy,
    );
    recorder.submit(
      {
        id: 1,
        method: "tools/call",
        params: { name: "payments.transfer", arguments: allowedArgs },
        startedAt: Date.now(),
        policy: {
          schema: "sheaf.policy/1",
          hash: policyHash,
          verdict: "ALLOW",
          reason_code: "allowed",
        },
      },
      { result: { ok: true } },
    );
    const blockedDecision = evaluatePolicy(
      "payments.transfer",
      blockedArgs,
      policy,
    );
    recorder.submitBlocked(
      {
        id: 2,
        method: "tools/call",
        params: { name: "payments.transfer", arguments: blockedArgs },
        startedAt: Date.now(),
        policy: {
          schema: "sheaf.policy/1",
          hash: policyHash,
          verdict: "BLOCK",
          reason_code: "amount_exceeds_limit",
        },
      },
      blockedDecision,
      policyHash,
    );
    await recorder.drain();

    assert.equal(posts.length, 3);
    assert.equal(posts[0].event.kind, "policy");
    assert.equal(posts[1].event.result, "ok");
    assert.equal(posts[1].event.policy.verdict, "ALLOW");
    assert.equal(posts[2].event.result, "blocked");
    assert.equal(posts[2].event.policy.verdict, "BLOCK");

    const signed = [];
    for (const envelope of posts) {
      const core = {
        v: envelope.v,
        event: envelope.event,
        chain: envelope.chain,
      };
      signed.push({
        envelope: {
          ...core,
          signatures: {
            actor: null,
            recorder: await signCore(key, core),
          },
        },
        envelope_hash: hashCanonical(core),
      });
    }

    const leaves = signed.map((row) => row.envelope_hash);
    const { root } = await buildMerkleTree(leaves);
    const epoch = {
      epoch_id: 0,
      merkle_root: root,
      anchor_tx_hash: "0x" + "b".repeat(64),
      anchor_block: 123456,
    };

    const archiveLines = [
      JSON.stringify({
        type: "meta",
        chain_id: "policy-chain",
        recorder: {
          name: "Policy Test Recorder",
          key_id: "policy-test-key",
          public_key_base64: key.publicKeyBase64,
          public_key_url: "",
        },
        anchorer: "0x1111111111111111111111111111111111111111",
        network: "eip155:8453",
      }),
      JSON.stringify({ type: "epoch", ...epoch }),
      ...signed.map((row, seq) =>
        JSON.stringify({
          type: "event",
          seq,
          envelope: row.envelope,
          envelope_hash: row.envelope_hash,
          epoch_id: 0,
          epoch_leaf_idx: seq,
        }),
      ),
    ];
    writeFileSync(join(dir, "archive.jsonl"), archiveLines.join("\n") + "\n");
    writeFileSync(join(dir, "1-args.json"), JSON.stringify(allowedArgs));
    writeFileSync(join(dir, "1-result.json"), JSON.stringify({ ok: true }));
    writeFileSync(join(dir, "2-args.json"), JSON.stringify(blockedArgs));

    const manifest = {
      schema: "sheaf.dispute-bundle/1",
      manifest_version: "sheaf.dispute-case/1",
      case: {
        case_id: "CB-POLICY-001",
        card_network: "visa",
        reason_code: {
          schema: "2026 Visa Claims Resolution guide",
          value: "10.4",
          label: "policy test",
        },
        transaction: {
          reference: "txn_policy_001",
          amount_minor: 12900,
          currency: "USD",
          occurred_at: "2026-11-10T16:42:11Z",
        },
        merchant: {
          id: "merchant_policy",
          name: "Northwind Outfitters",
          url: "https://northwind-outfitters.example",
        },
        response_due_at: "2026-11-24T23:59:59Z",
        dispute_basis: {
          category: "friendly_fraud",
          asserted_by: "merchant",
          merchant_position: "The transfer was within the recorded policy.",
        },
        created_at: new Date(Date.now() + 60_000).toISOString(),
      },
      subject: {
        from_seq: 1,
        to_seq: 2,
        disputed_event_seqs: [1],
        claims: {
          agent_id: {
            value: "agent:test",
            derived_from: "event.actor",
            ref: "seq:1",
          },
          tool: {
            value: "mcp://tool/payments.transfer",
            derived_from: "event.tool",
            ref: "seq:1",
          },
          merchant: {
            value: allowedArgs.merchant,
            derived_from: "payload",
            ref: "pl_1_args",
            path: "$.merchant",
          },
          amount_minor: {
            value: 12900,
            derived_from: "payload",
            ref: "pl_1_args",
            path: "$.amount",
          },
          currency: {
            value: "USD",
            derived_from: "payload",
            ref: "pl_1_args",
            path: "$.currency",
          },
        },
      },
      evidence: {
        mandate: { status: "absent" },
        delegation: { status: "absent" },
        consent: { status: "absent" },
      },
      payloads: [
        { seq: 1, kind: "tool_arguments", path: "1-args.json" },
        { seq: 1, kind: "tool_result", path: "1-result.json" },
        { seq: 2, kind: "tool_arguments", path: "2-args.json" },
      ],
    };
    writeFileSync(join(dir, "case.json"), JSON.stringify(manifest, null, 2));
    const trust = {
      recorder_keys: [
        {
          key_id: "policy-test-key",
          public_key_base64: key.publicKeyBase64,
          active_from: "2020-01-01T00:00:00Z",
          active_until: null,
        },
      ],
      anchorers: [
        {
          network: "eip155:8453",
          address: "0x1111111111111111111111111111111111111111",
        },
      ],
    };
    writeFileSync(join(dir, "trust.json"), JSON.stringify(trust));

    const out = join(dir, "bundle.sheaf");
    const exported = await capture(() =>
      runCli([
        "dispute",
        "export",
        "--archive",
        join(dir, "archive.jsonl"),
        "--case",
        join(dir, "case.json"),
        "--out",
        out,
        "--policy",
        "test/fixtures/policy/payments.json",
        "--self-check",
        "--offline",
        "--trust",
        join(dir, "trust.json"),
      ]),
    );
    assert.equal(exported.code, 0, exported.text);
    assert.match(exported.text, /WROTE /);

    const bundle = JSON.parse(readFileSync(out, "utf8"));
    assert.equal(bundle.policy.schema, "sheaf.policy/1");
    assert.equal(bundle.policy.hash, policyHash);

    const verified = await verifyDisputeBundle(bundle, { trust });
    const policyCheck = verified.checks.find(
      (check) => check.name === "policy_enforced",
    );
    assert.equal(policyCheck.ok, true, JSON.stringify(policyCheck));
    assert.equal(verified.valid, true);
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(dir, { recursive: true, force: true });
  }
});
