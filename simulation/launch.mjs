#!/usr/bin/env node
// `npm run sim` entry point (repo root). Routes to the platform launcher:
//   Windows        -> simulation/run-sim.ps1  (which itself picks WSL or native)
//   Linux / macOS  -> simulation/run-sim.sh
//
// Options use one syntax everywhere and are translated for PowerShell:
//   npm run sim -- --agent mock --keep-state --anvil-port 18545 --wrangler-port 18787
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

let result;
if (process.platform === "win32") {
  const map = { "--agent": "-Agent", "--anvil-port": "-AnvilPort", "--wrangler-port": "-WranglerPort", "--keep-state": "-KeepState", "--wsl": "-Wsl", "--native": "-Native" };
  const psArgs = args.map((a) => map[a] ?? a);
  result = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", join(here, "run-sim.ps1"), ...psArgs],
    { stdio: "inherit" },
  );
} else {
  result = spawnSync("bash", [join(here, "run-sim.sh"), ...args], { stdio: "inherit" });
}
if (result.error) {
  console.error(`npm run sim: could not start launcher: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
