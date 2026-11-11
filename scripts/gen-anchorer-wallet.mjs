// Generate a fresh EOA for Sheaf's on-chain anchorer. This wallet sends tiny
// self-transfer txs on Base whose calldata carries epoch IDs + Merkle roots.
// User funds it with ~$1 of Base ETH. Private key goes to a Worker secret.
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const pk = generatePrivateKey();
const account = privateKeyToAccount(pk);

console.log("=== Sheaf anchorer EOA ===");
console.log("address:", account.address);
console.log("");
console.log("Private key (wrangler secret put ANCHORER_PRIVATE_KEY):");
console.log(pk);
console.log("");
console.log(
  "Fund this address with ~$1 of ETH on Base mainnet. Gas per anchor ≈ $0.0005.",
);
