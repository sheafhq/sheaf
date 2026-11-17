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

## The same set classifies recorder signatures (S1)

The pinned recorder keys also decide which evidence-document signatures count
as **recorder** signatures (never principal authorisation). This includes the
bundle's own `recorder.public_key_base64`, and the `--trust` keys when given.
Classification compares raw key bytes, never strings or `key_id`.

## Signer pins (relying party) are separate

`trusted_signers` (library) / `--signers` (CLI) pin **principal** keys to
parties. Unlike this directory, they are **not** shipped: they are the relying
party's own assertions, supplied per verification. The browser page has no
signer input, so in the browser unrecognised keys always report
`authorisation: unauthenticated`. Pins are validated with strict Ed25519 (weak
keys are ignored), and a recorder key can never be a signer pin.

## How the browser verifier gets its trusted keys

`dispute-verify.html` (served at `/verify`) has **no trust input**: no URL
parameter, no fetch of key material, no storage. Its only fetch is the
"Load Sample" button. The trusted recorder keys and anchorers are the values
in `src/trust.ts`, **compiled into the page** by
`node scripts/build-dispute-verifier.mjs` (esbuild inlines `@sheafhq/verify`).
`--trust` exists only in the CLI and the library API, for tests and local
ledgers.

To update the trusted set:

1. Edit `trust/recorder-keys.json` / `trust/base-anchorers.json` **and**
   `src/trust.ts`. The drift test fails if they differ.
2. Release `@sheafhq/verify`.
3. Rebuild `dispute-verify.html` with the script above.
4. Deploy the Worker, which serves the page.

Old keys stay in the list with `active_until` set, so historical bundles still
verify.

**Limitation:** the page is only as trustworthy as its delivery (HTTPS from
sheafhq.io, Cloudflare). A party that needs independence from that delivery
should build `dispute-verify.html` from a reviewed source tree, or keep a copy
it has audited, and open it locally. Per-release SHA-256 hashes of the page are
not published yet; doing so is an open item. Bundles signed by a recorder
key that isn't compiled in (e.g. a local ledger) fail closed in the browser
with `UNKNOWN_RECORDER_KEY`; verify those with the CLI and `--trust`.
