// Base L2 anchor: send a 0-value self-transfer whose calldata carries
// (magic prefix || epoch_id || merkle_root). Verifiers read the tx, confirm
// `from` and `to` equal the published anchorer address, and extract the root.
//
// Calldata layout (44 bytes total):
//   bytes 0..3   : 0x41524341 ("ARCA" ASCII) magic
//   bytes 4..11  : uint64 BE epoch_id
//   bytes 12..43 : 32-byte Merkle root

import { createWalletClient, createPublicClient, http, fallback, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

// Multiple public RPCs with failover. mainnet.base.org rate-limits Cloudflare
// Worker egress IPs; llamarpc + publicnode are less aggressive. Order matters:
// viem tries them in order and falls back on error.
const BASE_RPCS = [
  "https://base.llamarpc.com",
  "https://base.publicnode.com",
  "https://base-rpc.publicnode.com",
  "https://mainnet.base.org",
];

export const ANCHOR_MAGIC = "0x41524341"; // "ARCA"

function encodeCalldata(epochId: number | bigint, rootHex: string): Hex {
  const epoch = BigInt(epochId);
  const epochBytes = new Uint8Array(8);
  const view = new DataView(epochBytes.buffer);
  view.setBigUint64(0, epoch, false); // big-endian
  const rootClean = rootHex.startsWith("0x") ? rootHex.slice(2) : rootHex;
  if (rootClean.length !== 64)
    throw new Error("root must be 32 bytes (64 hex chars)");
  const hex =
    ANCHOR_MAGIC.slice(2) +
    Array.from(epochBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("") +
    rootClean;
  return ("0x" + hex) as Hex;
}

export type AnchorResult = {
  tx_hash: string;
  calldata: string;
  from: string;
  to: string;
  epoch_id: number;
  root: string;
};

export async function anchorRoot(
  privateKeyHex: string,
  epochId: number,
  rootHex: string,
): Promise<AnchorResult> {
  const account = privateKeyToAccount(privateKeyHex as Hex);
  const data = encodeCalldata(epochId, rootHex);

  const transport = fallback(BASE_RPCS.map((url) => http(url)));
  const wallet = createWalletClient({
    account,
    chain: base,
    transport,
  });
  const pub = createPublicClient({ chain: base, transport });

  // Self-send with ARCA-tagged calldata. Zero value. Let viem fill gas + nonce.
  const hash = await wallet.sendTransaction({
    to: account.address,
    value: 0n,
    data,
  });

  return {
    tx_hash: hash,
    calldata: data,
    from: account.address,
    to: account.address,
    epoch_id: epochId,
    root: rootHex,
  };

  // Not waiting for confirmation here — caller can poll /epoch/:id later.
  // publicClient.waitForTransactionReceipt({ hash }) is available if needed.
}
