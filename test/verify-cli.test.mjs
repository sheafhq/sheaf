// The published `sheaf-verify` CLI must verify the dispute bundles the site
// publishes (sample-bundle.sheaf, sample-bundle-policy.sheaf) without the
// unpublished root `sheaf` CLI, and print the same report as
// `sheaf dispute verify`. Offline, so the suite needs no network.

import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const VERIFY = "packages/verify/dist/cli.js";
const ROOT = "dist-cli/cli.js";
const FIXTURES = [
  "test/fixtures/dispute-walking/bundle.sheaf",
  "test/fixtures/dispute-walking/bundle-policy.sheaf",
];

function run(cli, args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

for (const fixture of FIXTURES) {
  test(`sheaf-verify detects a dispute bundle: ${fixture}`, () => {
    const r = run(VERIFY, ["--offline", fixture]);
    assert.equal(r.status, 3, r.stdout + r.stderr); // valid, anchor unconfirmed
    assert.match(r.stdout, /^VALID/);
    assert.match(r.stdout, /anchor_confirmed: false/);
    const ok = run(VERIFY, ["--offline", "--allow-unconfirmed-anchor", fixture]);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  });

  test(`sheaf-verify output == sheaf dispute verify: ${fixture}`, () => {
    const npm = run(VERIFY, ["--offline", "--allow-unconfirmed-anchor", fixture]);
    const root = run(ROOT, ["dispute", "verify", fixture, "--offline", "--allow-unconfirmed-anchor"]);
    assert.equal(root.status, 0, root.stdout + root.stderr);
    assert.equal(npm.stdout, root.stdout);
  });
}

test("sheaf-verify rejects a tampered dispute bundle with exit 1", () => {
  const bundle = JSON.parse(readFileSync(FIXTURES[0], "utf8"));
  bundle.case.case_id = "TAMPERED";
  const path = join(mkdtempSync(join(tmpdir(), "sheaf-verify-")), "tampered.sheaf");
  writeFileSync(path, JSON.stringify(bundle));
  const r = run(VERIFY, ["--offline", path]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /^NOT VALID/);
});

// URL input: served from a loopback HTTP server so the suite needs no network.
// spawnSync would block the server's event loop, so these use async spawn.
function runAsync(cli, args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...args]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function withServer(fn) {
  const server = createServer((req, res) => {
    if (req.url === "/bundle.sheaf") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(readFileSync(FIXTURES[0]));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

test("sheaf-verify accepts a URL and prints the same report as the file", async () => {
  await withServer(async (base) => {
    const byUrl = await runAsync(VERIFY, ["--offline", "--allow-unconfirmed-anchor", `${base}/bundle.sheaf`]);
    const byFile = run(VERIFY, ["--offline", "--allow-unconfirmed-anchor", FIXTURES[0]]);
    assert.equal(byUrl.status, 0, byUrl.stdout + byUrl.stderr);
    assert.equal(byUrl.stdout, byFile.stdout);
  });
});

test("sheaf-verify reports a failed download with exit 2", async () => {
  await withServer(async (base) => {
    const r = await runAsync(VERIFY, [`${base}/missing.sheaf`]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /HTTP 404/);
  });
});

test("sheaf-verify refuses plain http to a non-local host", () => {
  const r = run(VERIFY, ["http://example.com/bundle.sheaf"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /refusing plain http/);
});

test("sheaf-verify says 'file not found' for a missing path", () => {
  const r = run(VERIFY, ["does-not-exist.sheaf"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /file not found: does-not-exist\.sheaf/);
});

test("--signers is refused for non-dispute input", () => {
  const r = run(VERIFY, ["--signers", "x.json", "test/fixtures/sheaf-bundle-1.smoke-test-1-0.json"]);
  assert.equal(r.status, 2);
});
