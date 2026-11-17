// Pinned-trust smoke tests for @sheafhq/verify dispute mode.
// The full disclosure matrix lives in ../../test/disclose.test.mjs because it
// needs the recorder-side builder fixture as well as the verifier.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  PINNED_ANCHORERS,
  PINNED_RECORDER_KEYS,
  verifyDisclosures,
} from "../dist/index.js";

test("shipped recorder-key JSON matches runtime constants", () => {
  const doc = JSON.parse(
    readFileSync(new URL("../trust/recorder-keys.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(
    doc.keys.map(({ key_id, public_key_base64, active_from, active_until }) => ({
      key_id,
      public_key_base64,
      active_from,
      active_until,
    })),
    PINNED_RECORDER_KEYS,
  );
});

test("shipped anchorer JSON matches runtime constants", () => {
  const doc = JSON.parse(
    readFileSync(
      new URL("../trust/base-anchorers.json", import.meta.url),
      "utf8",
    ),
  );
  const flattened = Object.entries(doc.networks).flatMap(([network, entries]) =>
    entries.map((entry) => ({
      network,
      address: entry.address,
      active_from: entry.active_from,
      active_until: entry.active_until,
    })),
  );
  assert.deepEqual(flattened, PINNED_ANCHORERS);
});

test("dispute mode is required before any disclosure is trusted", async () => {
  const result = await verifyDisclosures(
    {
      version: "sheaf-disclosure/1",
      chain_id: "x",
      from_seq: 0,
      to_seq: 0,
      recorder: {
        name: "x",
        key_id: "x",
        public_key_base64: "x",
        public_key_url: "https://example.invalid",
      },
      disclosures: [],
      anchor: { network: "eip155:8453", anchorer: "0x0", epochs: [] },
      before_ref: null,
      after_ref: null,
    },
    {},
  );
  assert.equal(result.valid, false);
  assert.equal(result.code, "DISPUTE_MODE_REQUIRED");
});
