// Generate Sheaf's Ed25519 recorder signing keypair. Private goes to a Worker
// secret; public hardcoded in src/keys.ts + served at /.well-known/sheaf-public-key.
import { generateKeyPairSync } from "node:crypto";
import { Buffer } from "node:buffer";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pubRaw = publicKey.export({ format: "jwk" }).x; // base64url 32 bytes
const privPkcs8 = Buffer.from(
  privateKey.export({ format: "der", type: "pkcs8" }),
).toString("base64");

const pubB64 = Buffer.from(
  pubRaw.replace(/-/g, "+").replace(/_/g, "/"),
  "base64",
).toString("base64");

console.log("=== Sheaf recorder keypair (Ed25519) ===");
console.log("public_key_base64  (hardcode in src/keys.ts):", pubB64);
console.log("");
console.log("private_key_pkcs8  (wrangler secret put RECORDER_PRIVATE_KEY):");
console.log(privPkcs8);
