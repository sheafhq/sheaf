// Fetch an Sheaf anchor tx from a Base RPC and decode (epoch_id, root).
// Uses only raw JSON-RPC fetch; no viem dependency.

const ANCHOR_MAGIC_HEX = "41524341"; // "ARCA"

export type AnchorRecord = {
  tx_hash: string;
  from: string;
  to: string;
  block_number: number;
  epoch_id: number;
  merkle_root: string; // hex, no 0x prefix
};

export async function fetchAnchorTx(
  rpcUrl: string,
  txHash: string,
): Promise<AnchorRecord> {
  const resp = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_getTransactionByHash",
      params: [txHash],
    }),
  });
  if (!resp.ok) {
    throw new Error(`Base RPC error ${resp.status}: ${await resp.text()}`);
  }
  const body = (await resp.json()) as {
    result: {
      from: string;
      to: string;
      input: string;
      blockNumber: string;
      hash: string;
    } | null;
    error?: { message: string };
  };
  if (body.error) throw new Error(`Base RPC: ${body.error.message}`);
  if (!body.result) throw new Error(`anchor tx ${txHash} not found on Base`);

  const tx = body.result;
  const input = tx.input.startsWith("0x") ? tx.input.slice(2) : tx.input;
  if (input.length !== 44 * 2)
    throw new Error(
      `anchor tx input is ${input.length / 2} bytes; expected 44`,
    );
  const magic = input.slice(0, 8);
  if (magic.toLowerCase() !== ANCHOR_MAGIC_HEX.toLowerCase())
    throw new Error(
      `anchor tx magic prefix is ${magic}; expected ${ANCHOR_MAGIC_HEX}`,
    );
  const epochHex = input.slice(8, 24);
  const rootHex = input.slice(24);
  const epochId = Number(BigInt("0x" + epochHex));
  return {
    tx_hash: tx.hash,
    from: tx.from.toLowerCase(),
    to: tx.to.toLowerCase(),
    block_number: Number(BigInt(tx.blockNumber)),
    epoch_id: epochId,
    merkle_root: rootHex.toLowerCase(),
  };
}
