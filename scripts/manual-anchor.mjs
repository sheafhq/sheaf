// One-shot: send an anchor tx from local WSL (not the Worker) to bypass
// Cloudflare egress-IP rate limits on public Base RPCs.
//
// Reads the pending anchor payload from the Worker's failed response, then
// submits it directly from a residential IP.
import { createWalletClient, http, fallback } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

const PK = process.env.ANCHORER_PRIVATE_KEY;
const EPOCH_ID = Number(process.env.EPOCH_ID ?? 0);
const ROOT = process.env.ROOT;
if (!PK || !ROOT) {
  console.error("ANCHORER_PRIVATE_KEY and ROOT env vars required");
  process.exit(1);
}

function encodeCalldata(epochId, rootHex) {
  const epochBytes = new Uint8Array(8);
  new DataView(epochBytes.buffer).setBigUint64(0, BigInt(epochId), false);
  const clean = rootHex.startsWith("0x") ? rootHex.slice(2) : rootHex;
  if (clean.length !== 64) throw new Error("root must be 32 bytes");
  const hex =
    "41524341" +
    Array.from(epochBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("") +
    clean;
  return "0x" + hex;
}

const account = privateKeyToAccount(PK);
const wallet = createWalletClient({
  account,
  chain: base,
  transport: fallback([
    http("https://base.llamarpc.com"),
    http("https://base.publicnode.com"),
    http("https://mainnet.base.org"),
  ]),
});

const data = encodeCalldata(EPOCH_ID, ROOT);
console.log("sending anchor tx...");
console.log(`  from:  ${account.address}`);
console.log(`  to:    ${account.address}`);
console.log(`  data:  ${data}`);
console.log(`  epoch: ${EPOCH_ID}, root: ${ROOT}`);

const hash = await wallet.sendTransaction({
  to: account.address,
  value: 0n,
  data,
});

console.log(`\ntx hash: ${hash}`);
console.log(`explorer: https://basescan.org/tx/${hash}`);
