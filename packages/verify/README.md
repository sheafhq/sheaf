# @sheafhq/verify

Standalone offline verifier for [Sheaf](https://github.com/sheafhq/sheaf) receipts. Checks hash chain + Merkle inclusion + Ed25519 signature + Base L2 anchor. **Zero runtime dependencies.**

The verifier reads only the anchor transaction from a Base RPC — no contact with Sheaf's servers needed to verify a receipt. Receipts survive us.

## Install

```bash
npm install @sheafhq/verify
```

## Usage

```ts
import { verify } from "@sheafhq/verify";

// A ReceiptBundle (what an agent stored alongside a tool call result)
const bundle = {
  envelope: /* the full signed Sheaf envelope */,
  inclusion_proof: /* { leaf, leaf_index, merkle_root, siblings } */,
  anchor_tx_hash: "0x…",            // Base tx hash where the Merkle root was anchored
  prev_envelope: /* optional */,    // if present, chain link is also verified
};

const result = await verify(bundle, {
  base_rpc: "https://mainnet.base.org",       // or any public/private Base RPC
  recorder_public_key_base64:
    "3HAltFwtHSZp83CLKYF/KKG2Ac4Se/YiD+AkfqCb+e8=",
  expected_anchorer_address: "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100",
});

if (result.valid) {
  console.log(`✓ valid; anchored in Base block ${result.anchor_block}`);
} else {
  console.log("✗ invalid:", result.reason);
  console.log("per-check breakdown:", result.checks);
}
```

## What it checks

Every call runs these seven invariants and reports them individually:

1. Anchor transaction exists on Base
2. Transaction was sent from (and to) the authorized anchorer address
3. Merkle root in the inclusion proof matches the one encoded in the anchor tx calldata
4. The (leaf, siblings) sequence actually reproduces the Merkle root
5. The hash of the envelope (excluding signatures) equals the leaf in the proof
6. The recorder Ed25519 signature verifies over the canonical (RFC 8785) serialization of {v, event, chain}
7. (Optional) `envelope.chain.prev_hash` equals the hash of `prev_envelope`

If any fails, `verify()` returns `{ valid: false, checks, reason }` with the exact field that broke.

## Primitives

The building blocks are also exported if you want to use them directly:

- `canonicalize(value)` — RFC 8785 JCS
- `sha256Hex(bytes | string)` — SHA-256 → hex
- `computeRootFromProof(leaf, siblings)` — Merkle recompute
- `verifyEd25519(publicKeyB64, sigB64, message)` — Ed25519 verify via WebCrypto
- `fetchAnchorTx(rpcUrl, txHash)` — read + decode Sheaf anchor tx from Base

## Runtime support

- Node 18+
- Cloudflare Workers
- Modern browsers (Chrome 113+, Firefox 130+, Safari 17+ — anywhere WebCrypto's Ed25519 is available)
- Deno
- Bun

## License

MIT
