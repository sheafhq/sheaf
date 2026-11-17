# Pinned trust for dispute mode

These files are release artifacts, not bundle data.

- `recorder-keys.json` — Ed25519 public keys authorized to sign Sheaf events,
  with the active window for each key id.
- `base-anchorers.json` — Base mainnet anchorer addresses, keyed by CAIP-2
  network id.

Dispute-mode verification (`verifyDisclosures(..., { mode: "dispute" })`) uses
these values to fail closed on:

- `UNKNOWN_RECORDER_KEY`
- `RECORDER_KEY_MISMATCH`
- `UNKNOWN_ANCHORER`

It never fetches `recorder.public_key_url` from a bundle. The only network call
dispute mode can make is a Base JSON-RPC `eth_getTransactionByHash`, and only
when `base_rpc` is supplied.

Updating a key or anchorer requires a new `@sheafhq/verify` release. Do not add
keys or addresses dynamically from an untrusted bundle.

`src/trust.ts` is the runtime copy of these files (for browser/Workers
compatibility). `test/trust.test.mjs` asserts that the JSON and runtime
constants do not drift.
