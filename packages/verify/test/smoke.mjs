// Smoke test: fetch a real receipt from the live Sheaf recorder, verify it
// end-to-end using only the public key and a Base RPC.
import { verify } from "../dist/index.js";

const RECORDER = "https://sheaf-recorder.goldencalf.workers.dev";
const CHAIN_ID = "smoke-test-1";
const SEQ = 0;
const EPOCH_ID = 0;
const ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";

const ev = await (await fetch(`${RECORDER}/events/${CHAIN_ID}/${SEQ}`)).json();
const pf = await (
  await fetch(`${RECORDER}/epoch/${EPOCH_ID}/proof/${CHAIN_ID}/${SEQ}`)
).json();
const pk = await (await fetch(`${RECORDER}/.well-known/sheaf-public-key`)).json();

const bundle = {
  envelope: ev.envelope,
  inclusion_proof: {
    leaf: pf.leaf,
    leaf_index: pf.leaf_index,
    merkle_root: pf.merkle_root,
    siblings: pf.siblings,
  },
  anchor_tx_hash: pf.anchor.tx_hash,
};

const active = pk.keys.find((k) => k.key_id === pk.active_key_id);
const result = await verify(bundle, {
  base_rpc: "https://mainnet.base.org",
  recorder_public_key_base64: active.public_key_base64,
  expected_anchorer_address: ANCHORER,
});

console.log(JSON.stringify(result, null, 2));
process.exit(result.valid ? 0 : 1);
