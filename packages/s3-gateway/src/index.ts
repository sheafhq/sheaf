import "dotenv/config";

import { loadConfig } from "./config.js";
import { startGateway } from "./gateway.js";

async function main(): Promise<void> {
  const cfg = loadConfig();
  const server = await startGateway(cfg);
  const address = server.address();
  const port =
    typeof address === "object" && address ? address.port : cfg.port;
  console.log(
    `[sheaf-s3-gateway] listening on :${port} upstream=${cfg.upstreamEndpoint} chain=${cfg.chainId} authority=${cfg.authority}`,
  );
}

main().catch((err) => {
  console.error(`[sheaf-s3-gateway] ${(err as Error).message}`);
  process.exitCode = 1;
});
