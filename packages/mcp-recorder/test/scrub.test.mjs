// Node built-in test runner (no deps). Run with:
//   node --test test/scrub.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { scrubSecrets, installGlobalScrubber, _resetInstalledForTest } from "../dist/scrub.js";

test("scrubSecrets replaces shf_live_ keys", () => {
  const k = "shf_live_" + "a".repeat(64);
  assert.equal(scrubSecrets(`key is ${k} ok`), "key is [REDACTED_SHEAF_KEY] ok");
});

test("scrubSecrets replaces legacy sk_live_ keys", () => {
  const k = "sk_live_" + "0123456789abcdef".repeat(4);
  assert.equal(scrubSecrets(`before ${k} after`), "before [REDACTED_SHEAF_KEY] after");
});

test("scrubSecrets replaces sk_test_ and shf_test_", () => {
  const k1 = "sk_test_" + "f".repeat(32);
  const k2 = "shf_test_" + "0".repeat(48);
  assert.equal(scrubSecrets(`${k1} ${k2}`), "[REDACTED_SHEAF_KEY] [REDACTED_SHEAF_KEY]");
});

test("scrubSecrets leaves non-key strings alone", () => {
  assert.equal(scrubSecrets("just a sentence"), "just a sentence");
  // Non-hex chars → not a key
  assert.equal(scrubSecrets("sk_live_xyz"), "sk_live_xyz");
  // Too short → not a key
  assert.equal(scrubSecrets("sk_live_abc"), "sk_live_abc");
});

test("scrubSecrets handles objects and arrays", () => {
  const k = "shf_live_" + "b".repeat(64);
  const obj = { nested: { key: k }, list: [k, "safe"] };
  const out = scrubSecrets(obj);
  assert.ok(!out.includes(k), "key should be redacted from JSON");
  assert.ok(out.includes("[REDACTED_SHEAF_KEY]"));
});

test("scrubSecrets handles null, undefined, numbers", () => {
  assert.equal(scrubSecrets(null), "null");
  assert.equal(scrubSecrets(undefined), "undefined");
  assert.equal(scrubSecrets(42), "42");
});

test("installGlobalScrubber redacts via console.log", () => {
  _resetInstalledForTest();
  const captured = [];
  const origStdoutWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, ...rest) => {
    captured.push(typeof chunk === "string" ? chunk : chunk.toString());
    return origStdoutWrite(chunk, ...rest);
  };
  installGlobalScrubber();
  const k = "shf_live_" + "c".repeat(64);
  console.log(`my key is ${k} here`);
  process.stdout.write = origStdoutWrite;
  const joined = captured.join("");
  assert.ok(joined.includes("[REDACTED_SHEAF_KEY]"), `should redact; got: ${joined}`);
  assert.ok(!joined.includes(k), "raw key must not appear");
});

test("installGlobalScrubber redacts via console.error", () => {
  _resetInstalledForTest();
  const captured = [];
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    captured.push(typeof chunk === "string" ? chunk : chunk.toString());
    return origStderrWrite(chunk, ...rest);
  };
  installGlobalScrubber();
  const k = "sk_live_" + "d".repeat(64);
  console.error(`debug: api key = ${k}`);
  process.stderr.write = origStderrWrite;
  const joined = captured.join("");
  assert.ok(joined.includes("[REDACTED_SHEAF_KEY]"));
  assert.ok(!joined.includes(k));
});

test("installGlobalScrubber redacts errors with stack traces", () => {
  _resetInstalledForTest();
  const captured = [];
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    captured.push(typeof chunk === "string" ? chunk : chunk.toString());
    return origStderrWrite(chunk, ...rest);
  };
  installGlobalScrubber();
  const k = "shf_live_" + "e".repeat(64);
  const err = new Error(`auth failed with ${k}`);
  console.error(err);
  process.stderr.write = origStderrWrite;
  const joined = captured.join("");
  assert.ok(joined.includes("[REDACTED_SHEAF_KEY]"));
  assert.ok(!joined.includes(k));
});
