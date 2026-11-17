// Local mode: policy enforcement, append-only ledger, local export, sync staging.
// This test does not spawn a child process; the full stdio proxy test is
// test/local-proxy.e2e.mjs.

import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { createServer } from "node:http";

import { LocalLedger } from "../packages/mcp-recorder/dist/local.js";
import { evaluatePolicy } from "../packages/mcp-recorder/dist/policy.js";
import { hashCanonical } from "../packages/mcp-recorder/dist/canonical.js";
import { runCli } from "../dist-cli/cli.js";

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

test("local mode: blocked call, allowed call, ledger, export, offline verify", async () => {
  const dir = "test/tmp-local";
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  try {
    for (const name of ["mandate", "delegation", "consent"]) {
      const doc = JSON.parse(
        readFileSync(`test/fixtures/evidence/${name}.json`, "utf8"),
      );
      if (doc.scope) {
        doc.scope.valid_until = "2027-11-11T16:30:00Z";
        doc.expires_at = "2027-11-11T16:30:00Z";
      }
      writeFileSync(join(dir, `${name}.json`), JSON.stringify(doc, null, 2));
    }

    const policy = JSON.parse(
      readFileSync("test/fixtures/dispute-walking/policy.json", "utf8"),
    );
    const policyHash = "sha256:" + hashCanonical(policy);
    const args = {
      merchant: "northwind-outfitters.example",
      amount_minor: 12900,
      currency: "USD",
      order_id: "order_demo_001",
      mandate_id: "mnd_demo_001",
      consent_id: "consent_demo_001",
    };
    const blockedArgs = {
      ...args,
      amount_minor: 20000,
      order_id: "order_demo_blocked_001",
    };
    const casePath = join(dir, "case.json");
    writeFileSync(
      casePath,
      JSON.stringify(
        {
          case: {
            case_id: "CB-LOCAL-001",
            card_network: "visa",
            reason_code: {
              schema: "2026 Visa Claims Resolution guide",
              value: "10.4",
              label: "Other fraud",
            },
            transaction: {
              reference: "txn_local_001",
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
              agent_id: {
                value: "agent://shopper-7",
                derived_from: "event.actor",
                ref: "seq:4",
              },
              tool: {
                value: "mcp://shop/payment",
                derived_from: "event.tool",
                ref: "seq:4",
              },
              merchant: {
                value: args.merchant,
                derived_from: "payload",
                ref: "pl_4_args",
                path: "$.merchant",
              },
              amount_minor: {
                value: 12900,
                derived_from: "payload",
                ref: "pl_4_args",
                path: "$.amount_minor",
              },
              currency: {
                value: "USD",
                derived_from: "payload",
                ref: "pl_4_args",
                path: "$.currency",
              },
            },
          },
          evidence: {
            mandate: { seq: 1, document: "mandate.json" },
            delegation: {
              chain: [{ seq: 2, parent_seq: 1, document: "delegation.json" }],
            },
            consent: { seq: 3, document: "consent.json" },
          },
          payloads: [
            {
              seq: 4,
              kind: "tool_arguments",
              path: ".sheaf/payloads/000004-arguments.json",
            },
            {
              seq: 4,
              kind: "tool_result",
              path: ".sheaf/payloads/000004-result.json",
            },
            {
              seq: 5,
              kind: "tool_arguments",
              path: ".sheaf/payloads/000005-arguments.json",
            },
          ],
        },
        null,
        2,
      ),
    );

    const chainDir = join(dir, ".sheaf");
    const ledger = new LocalLedger({
      recorderUrls: [],
      chainId: "local-test",
      actor: "local-user",
      captureMethods: new Set(),
      logDebug: false,
      policy,
      policyHash,
      local: { chainDir, casePath, actor: "local-user" },
    });

    ledger.submit(
      {
        id: 1,
        method: "tools/call",
        params: { name: "mcp://shop/payment", arguments: args },
        startedAt: Date.now(),
        policy: {
          schema: "sheaf.policy/1",
          hash: policyHash,
          verdict: "ALLOW",
          reason_code: "allowed",
        },
      },
      { result: { status: "authorized" } },
    );
    const decision = evaluatePolicy("mcp://shop/payment", blockedArgs, policy);
    ledger.submitBlocked(
      {
        id: 2,
        method: "tools/call",
        params: { name: "mcp://shop/payment", arguments: blockedArgs },
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
    await ledger.drain();

    const rows = readFileSync(join(chainDir, "ledger.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(rows.length, 6);
    assert.deepEqual(
      rows.map((row) => row.envelope.event.kind),
      ["policy", "mandate", "delegation", "consent", "tool_call", "tool_call"],
    );
    assert.equal(rows[4].envelope.event.result, "ok");
    assert.equal(rows[4].envelope.event.policy.verdict, "ALLOW");
    assert.equal(rows[5].envelope.event.result, "blocked");
    assert.equal(rows[5].envelope.event.policy.verdict, "BLOCK");
    assert.equal(rows[5].envelope.event.policy.reason_code, "amount_exceeds_limit");
    assert.ok(existsSync(join(chainDir, "local-keys.json")));
    if (process.platform !== "win32") {
      assert.equal(statSync(join(chainDir, "local-keys.json")).mode & 0o777, 0o600);
    }

    const out = join(dir, "bundle.sheaf");
    const exported = await capture(() =>
      runCli([
        "local",
        "export",
        "--chain-dir",
        chainDir,
        "--case",
        casePath,
        "--out",
        out,
      ]),
    );
    assert.equal(exported.code, 0, exported.text);
    assert.match(exported.text, /WROTE /);
    assert.match(exported.text, /LOCAL_ANCHOR local:/);

    const verified = await capture(() =>
      runCli([
        "dispute",
        "verify",
        out,
        "--offline",
        "--trust",
        join(chainDir, "trust.json"),
      ]),
    );
    assert.equal(verified.code, 0, verified.text);
    assert.match(verified.text, /^VALID \(complete\)/m);
    assert.match(verified.text, /\[14\] policy_enforced ✓/);
    assert.match(verified.text, /anchor_mode: local/);
    assert.doesNotMatch(verified.text, /anchor_on_base ✓/);

    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const request = JSON.parse(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            chain_id: request.chain_id,
            merkle_root: request.merkle_root,
            event_count: request.event_count,
            epoch_id: 999,
            tx_hash: "0x" + "a".repeat(64),
            block_number: 123456,
            anchorer: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
            calldata: "0x" + "0".repeat(88),
          }),
        );
      });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    try {
      const synced = await capture(() =>
        runCli([
          "local",
          "sync",
          "--chain-dir",
          chainDir,
          "--endpoint",
          `http://127.0.0.1:${port}/v1/anchor/local`,
        ]),
      );
      assert.equal(synced.code, 0, synced.text);
      assert.match(synced.text, /ANCHORED 0x[a]{64}/);
      assert.match(synced.text, /merkle_root: [0-9a-f]{64}/);
      assert.ok(existsSync(join(chainDir, "anchor.json")));
    } finally {
      server.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
