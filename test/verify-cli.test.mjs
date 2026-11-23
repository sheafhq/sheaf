// The published `sheaf-verify` CLI must verify the dispute bundles the site
// publishes (sample-bundle.sheaf, sample-bundle-policy.sheaf) without the
// unpublished root `sheaf` CLI, and print the same report as
// `sheaf dispute verify`. Offline, so the suite needs no network.

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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

test("--signers is refused for non-dispute input", () => {
  const r = run(VERIFY, ["--signers", "x.json", "test/fixtures/sheaf-bundle-1.smoke-test-1-0.json"]);
  assert.equal(r.status, 2);
});
