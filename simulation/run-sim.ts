// Agent Economy in a Box: master orchestrator.
//
//   npm install && npm run sim          (repo root, any OS; see launch.mjs)
//   npm run sim -- --agent mock         (options after --)
//
// The firewall under test is the published @sheafhq/mcp-recorder@0.3.0
// (pinned in simulation/package.json), launched through its `bin`
// (sheaf-mcp-recorder --local), exactly as a user would run it.
//
// Options:
//   --agent auto|mock|ollama   brain for the buyer agent (default: auto =
//                              local Ollama if reachable, else deterministic mock)
//   --anvil-port <n>           default 18545
//   --wrangler-port <n>        default 18787
//   --keep-state               keep simulation/.state after the run
//
// Steps:
//   a) start anvil (chain id 8453 so the recorder's Base anchor code runs unmodified)
//   b) start the REAL Sheaf recorder Worker under `wrangler dev` (local D1,
//      ephemeral Ed25519 key, anvil as its Base RPC)
//   c+d) run the buyer agent -> Sheaf Local (policy firewall + recorder) -> merchant MCP server
//   e) the agent's instruction: "Try to buy the enterprise data. If that fails, buy the premium data."
//   f) seal + anchor the epoch on anvil, export the session as a .sheaf bundle
//   g) run the notary on the exported bundle
//   h) shut down wrangler + anvil (always, also on error / Ctrl-C)
//
// Zero cloud: every process binds to 127.0.0.1; the Worker's x402 facilitator
// URL points at a dead local port and is never called by this flow.

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { homedir, platform } from "node:os";
import { delimiter, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { BUYER_PROMPT, resolveBrain, runAgent } from "./agent.ts";
// NOTE: anything that imports @sheafhq/* is loaded with a dynamic import()
// AFTER preflight has checked that simulation/node_modules is installed.
import type { exportSession as ExportSessionFn } from "./export-session.ts";

const SIM = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SIM, "..");
const STATE = join(SIM, ".state");
const OUT = join(SIM, "out");
const IS_WIN = platform() === "win32";
const TSX = import.meta.resolve("tsx"); // file:// URL usable with node --import

// anvil's well-known dev account #0 (public test key; never use on a real chain)
const ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const BASE_CHAIN_ID = 8453;

// ---- args ------------------------------------------------------------------------

const argv = process.argv.slice(2);
const argVal = (name: string, dflt: string) => {
  const i = argv.indexOf(name);
  return i === -1 ? dflt : (argv[i + 1] ?? dflt);
};
const agentMode = argVal("--agent", "auto") as "auto" | "mock" | "ollama";
const ANVIL_PORT = Number(argVal("--anvil-port", "18545"));
const WRANGLER_PORT = Number(argVal("--wrangler-port", "18787"));
const KEEP_STATE = argv.includes("--keep-state");
if (!["auto", "mock", "ollama"].includes(agentMode)) {
  console.error(`--agent must be auto|mock|ollama (got ${agentMode})`);
  process.exit(2);
}

const RPC = `http://127.0.0.1:${ANVIL_PORT}`;
const RECORDER = `http://127.0.0.1:${WRANGLER_PORT}`;

// ---- small helpers ---------------------------------------------------------------

const COLOR = process.stdout.isTTY === true;
const sgr = (code: string) => (s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = sgr("1");
const green = sgr("32");
const red = sgr("31");
const banner = (step: string, title: string) => console.log(`\n${bold(`━━ ${step}) ${title}`)}`);
const info = (s: string) => console.log(`   ${s}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const posixRel = (p: string) => relative(ROOT, p).split("\\").join("/");

function findOnPath(names: string[], extra: string[] = []): string | null {
  const dirs = [...(process.env.PATH ?? "").split(delimiter), ...extra];
  for (const d of dirs) for (const n of names) {
    const p = join(d, n);
    if (d && existsSync(p)) return p;
  }
  return null;
}

async function portFree(port: number): Promise<boolean> {
  return new Promise((res) => {
    const s = createServer();
    s.once("error", () => res(false));
    s.listen(port, "127.0.0.1", () => s.close(() => res(true)));
  });
}

async function waitFor(label: string, fn: () => Promise<boolean>, timeoutMs: number, proc?: ChildProcess) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (proc && proc.exitCode !== null) throw new Error(`${label} exited early (code ${proc.exitCode})`);
    try {
      if (await fn()) return;
    } catch {
      /* not up yet */
    }
    await sleep(300);
  }
  throw new Error(`${label} not ready after ${timeoutMs / 1000}s`);
}

async function rpc<T>(method: string, params: unknown[] = []): Promise<T> {
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const b = (await r.json()) as { result: T; error?: { message: string } };
  if (b.error) throw new Error(b.error.message);
  return b.result;
}

// ---- background process management -----------------------------------------------

const background: Array<{ name: string; proc: ChildProcess }> = [];

function startBackground(name: string, cmd: string, args: string[], logFile: string, env?: NodeJS.ProcessEnv) {
  const log = createWriteStream(logFile);
  const proc = spawn(cmd, args, {
    cwd: ROOT,
    env: env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: !IS_WIN, // own process group on POSIX so we can kill the whole tree
    windowsHide: true,
  });
  proc.stdout!.pipe(log);
  proc.stderr!.pipe(log);
  background.push({ name, proc });
  info(`${name} started (pid ${proc.pid}); log: ${relative(ROOT, logFile)}`);
  return proc;
}

function killTree(proc: ChildProcess) {
  if (proc.exitCode !== null || proc.pid === undefined) return;
  try {
    if (IS_WIN) spawnSync("taskkill", ["/pid", String(proc.pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-proc.pid, "SIGTERM");
  } catch {
    /* already gone */
  }
}

let shutDown = false;
/** h) Stop every background process tree. State (keys, D1, logs) is deleted
 *  unless --keep-state was given or the run failed. */
async function shutdown(deleteState: boolean) {
  if (shutDown) return;
  shutDown = true;
  banner("h", "Shutting down Wrangler and Anvil");
  for (const { name, proc } of [...background].reverse()) {
    if (proc.exitCode !== null || proc.signalCode !== null) {
      info(`${name} already exited`);
      continue;
    }
    const exited = new Promise((r) => proc.once("exit", r));
    killTree(proc);
    await Promise.race([exited, sleep(5000)]);
    if (proc.exitCode === null && proc.signalCode === null && !IS_WIN) {
      try {
        process.kill(-proc.pid!, "SIGKILL");
      } catch {}
    }
    info(`${name} stopped`);
  }
  if (deleteState) rmSync(STATE, { recursive: true, force: true });
  else if (existsSync(STATE)) info(`state + logs kept in ${relative(ROOT, STATE)}`);
}

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    console.error(`\nreceived ${sig}; cleaning up`);
    shutdown(false).finally(() => process.exit(130));
  });
}

// ---- main ----------------------------------------------------------------------------

async function main(): Promise<number> {
  console.log(`${bold("Agent Economy in a Box")}: Sheaf local simulation (zero cloud)`);

  // -- preflight
  const anvil =
    process.env.ANVIL_BIN ??
    findOnPath(IS_WIN ? ["anvil.exe"] : ["anvil"], [join(homedir(), ".foundry", "bin")]);
  if (!anvil) throw new Error("anvil not found. Install Foundry: https://book.getfoundry.sh/getting-started/installation (or set ANVIL_BIN)");
  const wranglerJs = join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js");
  if (!existsSync(wranglerJs)) throw new Error(`wrangler not installed; run \`npm install\` in ${ROOT}`);

  // The firewall is the PUBLISHED @sheafhq/mcp-recorder@0.3.0 (pinned in
  // simulation/package.json), resolved by package name and launched through
  // its `bin`, exactly as a user would run it. It is pinned because the
  // repo's packages/mcp-recorder (0.4.0) has a different `--local` mode.
  const require = createRequire(import.meta.url);
  let recorderPkgJson: string;
  try {
    recorderPkgJson = require.resolve("@sheafhq/mcp-recorder/package.json");
  } catch {
    throw new Error(`@sheafhq/mcp-recorder is not installed; run \`npm install\` in ${SIM}`);
  }
  const recorderPkg = JSON.parse(readFileSync(recorderPkgJson, "utf8")) as { version: string; bin: Record<string, string> };
  const recorderCli = join(dirname(realpathSync(recorderPkgJson)), recorderPkg.bin["sheaf-mcp-recorder"]!);
  info(`firewall: @sheafhq/mcp-recorder@${recorderPkg.version} (${posixRel(realpathSync(dirname(recorderPkgJson)))}) bin sheaf-mcp-recorder --local`);
  for (const [p, label] of [[ANVIL_PORT, "--anvil-port"], [WRANGLER_PORT, "--wrangler-port"], [WRANGLER_PORT + 1, "inspector (wrangler-port+1)"]] as const) {
    if (!(await portFree(p))) throw new Error(`port ${p} (${label}) is in use; pick another`);
  }

  // -- ephemeral identities + sim-only wrangler config
  rmSync(STATE, { recursive: true, force: true });
  mkdirSync(STATE, { recursive: true });
  mkdirSync(OUT, { recursive: true });

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const recorderPkcs8 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const recorderPub = publicKey.export({ type: "spki", format: "der" }).subarray(12).toString("base64");
  const adminToken = randomBytes(24).toString("hex");
  const keyId = "sim-ed25519-ephemeral";

  const posix = (p: string) => p.split("\\").join("/");
  const wranglerCfg = join(STATE, "wrangler.sim.json");
  writeFileSync(
    wranglerCfg,
    JSON.stringify(
      {
        name: "sheaf-recorder-sim",
        main: posix(relative(STATE, join(ROOT, "src", "index.ts"))),
        compatibility_date: "2026-11-01",
        compatibility_flags: ["nodejs_compat"],
        // Same module rules as the repo's wrangler.jsonc (the Worker imports
        // its pages, sample bundles and favicon as text).
        rules: [
          { type: "Text", globs: ["**/*.html"], fallthrough: true },
          { type: "Text", globs: ["**/*.sheaf"], fallthrough: true },
          { type: "Text", globs: ["**/*.txt"], fallthrough: true },
          { type: "Text", globs: ["**/*.svg"], fallthrough: true },
        ],
        vars: {
          ISSUER: "sheaf-local-sim",
          KEY_ID: keyId,
          ANCHOR_CONTRACT: "",
          ANCHOR_NETWORK: `eip155:${BASE_CHAIN_ID}`,
          ANCHORER_ADDRESS: ANVIL_ADDR,
          PAYOUT_ADDRESS: ANVIL_ADDR,
          NETWORK: `eip155:${BASE_CHAIN_ID}`,
          FACILITATOR_URL: "http://127.0.0.1:9/x402-disabled-in-simulation",
        },
        d1_databases: [
          {
            binding: "DB",
            database_name: "sheaf-sim",
            database_id: "00000000-0000-0000-0000-000000000000",
            migrations_dir: posix(relative(STATE, join(ROOT, "migrations"))),
          },
        ],
      },
      null,
      2,
    ),
  );
  // Secrets: .dev.vars is read from the config file's directory, so the
  // developer's own ROOT/.dev.vars is never touched.
  writeFileSync(
    join(STATE, ".dev.vars"),
    [
      `RECORDER_PRIVATE_KEY=${recorderPkcs8}`,
      `ANCHORER_PRIVATE_KEY=${ANVIL_KEY}`,
      `ADMIN_TOKEN=${adminToken}`,
      `BASE_RPC_URL=${RPC}`,
    ].join("\n") + "\n",
  );
  const wranglerEnv = {
    ...process.env,
    CI: "true",
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_LOG: "info",
    NO_UPDATE_NOTIFIER: "1",
  };
  const persist = join(STATE, "wrangler-state");

  const chainId = `sim-buyer-${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14)}-${randomBytes(2).toString("hex")}`;
  const outBase = join(OUT, chainId);

  // -- a) anvil
  banner("a", `Starting Anvil (chain id ${BASE_CHAIN_ID}, ${RPC})`);
  const anvilProc = startBackground(
    "anvil",
    anvil,
    [
      "--host", "127.0.0.1", "--port", String(ANVIL_PORT), "--chain-id", String(BASE_CHAIN_ID),
      // Persist the chain next to the bundle so the notary can re-verify the
      // anchor after this run ends (dumped every second; survives a hard kill).
      "--dump-state", `${outBase}.anvil-state.json`, "--state-interval", "1",
    ],
    join(STATE, "anvil.log"),
  );
  await waitFor("anvil", async () => (await rpc<string>("eth_chainId")) === "0x" + BASE_CHAIN_ID.toString(16), 30_000, anvilProc);
  info(`anvil ready; anchorer = dev account #0 ${ANVIL_ADDR}`);

  // -- b) wrangler dev (real recorder Worker)
  banner("b", `Starting the Sheaf recorder under wrangler dev (${RECORDER})`);
  const mig = spawnSync(
    process.execPath,
    [wranglerJs, "d1", "migrations", "apply", "DB", "--local", "--persist-to", persist, "-c", wranglerCfg],
    { cwd: ROOT, env: wranglerEnv, encoding: "utf8", windowsHide: true },
  );
  writeFileSync(join(STATE, "migrations.log"), (mig.stdout ?? "") + (mig.stderr ?? ""));
  if (mig.status !== 0) throw new Error(`D1 migrations failed; see ${relative(ROOT, join(STATE, "migrations.log"))}`);
  info("local D1 migrated (0001 events, 0002 anchor epochs, 0003 accounts)");

  const wranglerProc = startBackground(
    "wrangler",
    process.execPath,
    [
      wranglerJs, "dev", "-c", wranglerCfg,
      "--ip", "127.0.0.1", "--port", String(WRANGLER_PORT),
      "--inspector-port", String(WRANGLER_PORT + 1),
      "--persist-to", persist,
      "--show-interactive-dev-session=false",
    ],
    join(STATE, "wrangler.log"),
    wranglerEnv,
  );
  await waitFor("wrangler dev", async () => (await fetch(`${RECORDER}/`)).ok, 120_000, wranglerProc);
  info("recorder ready");

  const acct = (await (await fetch(`${RECORDER}/accounts`, { method: "POST", body: "{}" })).json()) as {
    account_id?: string;
    api_key?: string;
    error?: string;
  };
  if (!acct.api_key) throw new Error(`POST /accounts failed: ${acct.error ?? JSON.stringify(acct)}`);
  info(`buyer account ${acct.account_id} created (API key kept in memory only)`);

  // -- c/d/e) agent -> Sheaf Local -> merchant
  const { loadPolicy, policyAuthority } = await import("@sheafhq/mcp-recorder");
  const policyPath = join(SIM, "buyer-policy.json");
  const policy = loadPolicy(policyPath);
  const authority = policyAuthority(policy);
  const actor = "buyer-agent";
  const journalPath = join(STATE, "journal.jsonl");

  banner("c", "Starting merchant-server.ts (MCP stdio) behind `sheaf-mcp-recorder --local`");
  info(`policy ${policy.id} (${authority.slice(0, 32)}…)`);
  info(`chain ${chainId}`);
  const brain = await resolveBrain(agentMode);
  banner("d", `Running buyer agent: ${brain.kind === "ollama" ? `local LLM (ollama ${brain.model})` : "deterministic mock agent"}`);
  banner("e", `Prompt: "${BUYER_PROMPT}"`);
  const { transcript, wrapperExitCode } = await runAgent({
    command: process.execPath,
    // The real product CLI, exactly as a user would wire it into an MCP client.
    args: [
      recorderCli,
      "--local",
      "--policy", policyPath,
      "--journal", journalPath,
      "--wrap",
      process.execPath, "--import", TSX, join(SIM, "merchant-server.ts"),
    ],
    env: {
      ...process.env,
      SHEAF_RECORDER_URL: RECORDER,
      SHEAF_CHAIN_ID: chainId,
      SHEAF_API_KEY: acct.api_key,
      SHEAF_ACTOR: actor,
    },
    brain,
    log: info,
  });
  if (wrapperExitCode !== 0) throw new Error(`sheaf-mcp-recorder --local exited with code ${wrapperExitCode}`);
  info(`agent finished after ${transcript.length} tool call(s)`);

  // -- f) anchor + export
  banner("f", "Sealing epoch, anchoring on Anvil, exporting the .sheaf bundle");
  const anchorRes = (await (
    await fetch(`${RECORDER}/admin/anchor`, { method: "POST", headers: { authorization: `Bearer ${adminToken}` } })
  ).json()) as { ok: boolean; epoch_id?: number; anchor_tx_hash?: string; event_count?: number; merkle_root?: string; reason?: string };
  if (!anchorRes.ok || !anchorRes.anchor_tx_hash) throw new Error(`anchor failed: ${anchorRes.reason ?? JSON.stringify(anchorRes)}`);
  await waitFor(
    "anchor tx receipt",
    async () => (await rpc<{ status: string } | null>("eth_getTransactionReceipt", [anchorRes.anchor_tx_hash]))?.status === "0x1",
    30_000,
  );
  info(`epoch ${anchorRes.epoch_id}: ${anchorRes.event_count} events, root ${anchorRes.merkle_root?.slice(0, 16)}…`);
  info(`anchor tx ${anchorRes.anchor_tx_hash} mined on anvil`);

  const outPath = `${outBase}.sheaf`;
  const { exportSession } = await import("./export-session.ts");
  const exported = await exportSession({
    recorderUrl: RECORDER,
    chainId,
    actor,
    issuer: { name: "sheaf-local-sim", key_id: keyId, public_key_base64: recorderPub },
    policy,
    policyAuthority: authority,
    journalPath,
    anchorChainId: BASE_CHAIN_ID,
    rpcHint: RPC,
    anchorerAddress: ANVIL_ADDR,
    outPath,
  });
  info(`exported ${exported.receipts.length} receipts -> ${relative(ROOT, outPath)}`);

  // The notary's trust roots, as the recorder would publish them. Kept apart
  // from the bundle: a notary should never take these from the thing it audits.
  const trustPath = `${outBase}.trust.json`;
  writeFileSync(
    trustPath,
    JSON.stringify(
      {
        recorder_key_id: keyId,
        recorder_public_key_base64: recorderPub,
        anchorer_address: ANVIL_ADDR,
        anchor_chain_id: BASE_CHAIN_ID,
        rpc: RPC,
      },
      null,
      2,
    ) + "\n",
  );
  info(`trust roots -> ${relative(ROOT, trustPath)}; chain state -> ${relative(ROOT, outBase)}.anvil-state.json`);

  // -- g) notary
  banner("g", "Notary audit (offline: bundle + anvil RPC + pinned trust roots only)");
  const notaryArgs = (file: string) => [
    "--disable-warning=ExperimentalWarning", // Node 20 flags WebCrypto Ed25519 as experimental
    "--import", TSX, join(SIM, "notary.ts"), file,
    "--trust", trustPath,
  ];
  const notary = spawnSync(process.execPath, notaryArgs(outPath), {
    cwd: SIM,
    stdio: "inherit",
    env: { ...process.env, ...(process.stdout.isTTY ? { FORCE_COLOR: "1" } : {}) },
  });
  if (notary.status !== 0) return notary.status ?? 1;

  // The notary must not be a rubber stamp: forged variants of the same
  // bundle have to be REJECTED (while anvil is still up, so rejection is
  // about the forgery, not a missing anchor).
  console.log("\n   Adversarial check: forged bundles must be rejected");
  const tamperDir = join(STATE, "tampered");
  mkdirSync(tamperDir, { recursive: true });
  const forgeries = tamperedVariants(exported);
  let forgeriesCaught = 0;
  for (const [name, doc] of forgeries) {
    const file = join(tamperDir, `${name.replace(/\W+/g, "-")}.sheaf`);
    writeFileSync(file, JSON.stringify(doc, null, 2));
    const r = spawnSync(process.execPath, notaryArgs(file), { cwd: SIM, encoding: "utf8", env: process.env });
    const firstFailure = /^\s+- (.+)$/m.exec(r.stdout ?? "")?.[1] ?? "(no reason printed)";
    const rejected = r.status === 1;
    if (rejected) forgeriesCaught++;
    info(`${rejected ? green("✓ rejected") : red("✗ ACCEPTED")}  ${name}  ->  ${firstFailure}`);
  }
  if (forgeriesCaught !== forgeries.length) {
    console.error(`   notary accepted ${forgeries.length - forgeriesCaught} forged bundle(s)`);
    return 1;
  }
  return 0;
}

/** Forgeries an interested party might attempt after the fact. */
function tamperedVariants(honest: Awaited<ReturnType<typeof ExportSessionFn>>): Array<[string, unknown]> {
  const clone = () => JSON.parse(JSON.stringify(honest)) as typeof honest;
  const out: Array<[string, unknown]> = [];

  // 1. Hide the blocked €200 attempt (cherry-pick the chain).
  {
    const s = clone();
    const i = s.receipts.findIndex((r) => r.envelope.event.intent.startsWith("policy:deny"));
    s.receipts.splice(i, 1);
    s.disclosures.splice(i, 1);
    out.push(["hide the blocked purchase", s]);
  }
  // 2. Truncate: drop the session/close commitment.
  {
    const s = clone();
    s.receipts.pop();
    s.disclosures.pop();
    out.push(["drop the session-close event", s]);
  }
  // 3. Re-label the denial as an approval in the signed intent.
  {
    const s = clone();
    const r = s.receipts.find((r) => r.envelope.event.intent.startsWith("policy:deny"))!;
    r.envelope.event.intent = r.envelope.event.intent.replace("policy:deny:deny-over-budget", "policy:allow:allow-premium-data");
    out.push(["rewrite deny as allow", s]);
  }
  // 4. Lie about what was bought: claim the premium purchase cost €90.
  {
    const s = clone();
    const d = s.disclosures.find((d) => (d.inputs as { name?: string }).name === "buy_premium_data")!;
    (d.inputs as { arguments: { amount: number } }).arguments.amount = 90;
    out.push(["alter the disclosed amount", s]);
  }
  // 5. Swap in a looser policy (budget €250) and claim it was enforced.
  {
    const s = clone();
    const rule = s.policy.document.rules.find((r) => r.id === "deny-over-budget")!;
    rule.when!.value = 250;
    out.push(["substitute a looser policy", s]);
  }
  // 6. Strip the policy_enforced claim.
  {
    const s = clone();
    (s as { policy_enforced: boolean }).policy_enforced = false;
    out.push(["unset policy_enforced", s]);
  }
  return out;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.error(`\n${red("simulation failed:")} ${(err as Error).message}`);
  code = 1;
} finally {
  await shutdown(code === 0 && !KEEP_STATE);
}
console.log("\n" + (code === 0 ? green("SIMULATION PASSED") : red("SIMULATION FAILED")));
process.exit(code);
