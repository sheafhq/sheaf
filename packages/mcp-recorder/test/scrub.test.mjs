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

// Coverage test: assert every historical Sheaf key format is caught by the
// scrubber regex. If a new format is added in accounts.ts, this test fails
// until the scrubber regex is widened. Added 2026-11-12 after the sk_live_
// leak incident.
test("scrubber catches every historical key format emitted by accounts.ts", () => {
  // Pull current + legacy prefixes from server-side accounts.ts. Kept in
  // sync manually; if a new prefix is added there, add it here too and
  // widen the scrub.ts KEY_PATTERNS array to match.
  const ALL_PREFIXES_EVER_EMITTED = [
    "sk_live_",   // legacy (pre-2026-11-12)
    "shf_live_",  // current (post-2026-11-12)
  ];
  // Historical suffix formats: 64 lowercase hex. If this ever changes
  // (e.g. base32, longer, uppercase), add variants to this list.
  const SUFFIX_VARIANTS = [
    "a".repeat(64),                        // all-a
    "0123456789abcdef".repeat(4),          // every hex digit
    "f".repeat(64),                        // all-f
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", // mixed
  ];
  for (const pfx of ALL_PREFIXES_EVER_EMITTED) {
    for (const suf of SUFFIX_VARIANTS) {
      const key = pfx + suf;
      const scrubbed = scrubSecrets(`before ${key} after`);
      assert.ok(
        scrubbed.includes("[REDACTED_SHEAF_KEY]"),
        `scrubber failed to catch format ${pfx}<64hex>; got: ${scrubbed}`,
      );
      assert.ok(
        !scrubbed.includes(key),
        `raw key leaked through scrubber for format ${pfx}<64hex>`,
      );
    }
  }
});

// Tighter adversarial variants — surround/embed keys in patterns that
// might confuse a naive regex.
test("scrubber catches keys in adversarial contexts", () => {
  const key = "shf_live_" + "a".repeat(64);
  const cases = [
    { ctx: `url: https://api.sheafhq.io/?token=${key}&foo=bar`, where: "URL query string" },
    { ctx: `json: {"api_key":"${key}"}`, where: "JSON value" },
    { ctx: `header: Authorization: Bearer ${key}`, where: "Bearer header" },
    { ctx: `yaml:\n  key: ${key}\n`, where: "YAML value" },
    { ctx: `multiline\nkey=${key}\nnext line`, where: "multiline env" },
    { ctx: `${key}`, where: "bare key" },
  ];
  for (const { ctx, where } of cases) {
    const scrubbed = scrubSecrets(ctx);
    assert.ok(
      !scrubbed.includes(key),
      `raw key leaked in ${where}: ${scrubbed}`,
    );
  }
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
