// Bundle versioning (owner decision 2026-11-18):
//  - sheaf.dispute-bundle/1 rejects unknown top-level keys, so a v2 bundle
//    relabelled as v1 fails closed instead of having its authority section
//    silently ignored.
//  - sheaf.dispute-bundle/2 is recognised and refused until this verifier can
//    verify its authority section (SAP phases 3-9).

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  DISPUTE_BUNDLE_SCHEMA_V2,
  DISPUTE_BUNDLE_V1_KEYS,
  DISPUTE_BUNDLE_V2_KEYS,
  computeDisputeBundleId,
  verifyDisputeBundle,
} from "../packages/verify/dist/index.js";

const FIXTURES = [
  "test/fixtures/dispute-walking/bundle.sheaf",
  "test/fixtures/dispute-walking/bundle-policy.sheaf",
  "test/fixtures/s1/legacy-recorder-signed.sheaf",
];

async function verifyMutated(path, mutate, opts = {}) {
  const bundle = JSON.parse(readFileSync(path, "utf8"));
  mutate(bundle);
  bundle.bundle_id = await computeDisputeBundleId(bundle);
  return verifyDisputeBundle(bundle, opts);
}

test("v1 key set covers every shipped fixture (no false rejections)", () => {
  for (const path of FIXTURES) {
    const bundle = JSON.parse(readFileSync(path, "utf8"));
    const extra = Object.keys(bundle).filter((k) => !DISPUTE_BUNDLE_V1_KEYS.includes(k));
    assert.deepEqual(extra, [], path);
  }
  assert.deepEqual(DISPUTE_BUNDLE_V2_KEYS, [...DISPUTE_BUNDLE_V1_KEYS, "authority"]);
});

test("v1 with a top-level authority section (v2 relabelled as v1) fails closed", async () => {
  const result = await verifyMutated(FIXTURES[0], (b) => {
    b.authority = { decision: "BLOCK", reasons: ["EXCEEDED_AUTHORITY"], issuer_signature: "garbage" };
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "SCHEMA_UNSUPPORTED");
  assert.equal(result.reason, "unknown top-level key(s) for sheaf.dispute-bundle/1: authority");
  assert.equal(result.checks[0].ok, false);
});

test("v1 rejects any unknown top-level key, and names all of them", async () => {
  const result = await verifyMutated(FIXTURES[0], (b) => {
    b.zeta = 1;
    b.extensions = {};
  });
  assert.equal(result.code, "SCHEMA_UNSUPPORTED");
  assert.equal(result.reason, "unknown top-level key(s) for sheaf.dispute-bundle/1: extensions, zeta");
});

test("v1 bundles with only known keys verify unchanged", async () => {
  for (const path of FIXTURES.slice(0, 2)) {
    const result = await verifyDisputeBundle(JSON.parse(readFileSync(path, "utf8")));
    assert.equal(result.valid, true, `${path}: ${result.code} ${result.reason}`);
  }
});

test("sheaf.dispute-bundle/2 is recognised and refused (authority not yet verifiable)", async () => {
  const result = await verifyMutated(FIXTURES[0], (b) => {
    b.schema = DISPUTE_BUNDLE_SCHEMA_V2;
    b.authority = {};
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "SCHEMA_UNSUPPORTED");
  assert.match(result.reason, /^sheaf\.dispute-bundle\/2 is recognised, but this verifier cannot verify its authority section yet/);
});
