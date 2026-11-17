// `sheaf-mcp-recorder init` — ephemeral-chain onboarding.
// No account signup from the operator's perspective: creates an account
// transparently, mints a chain ID, writes a first event, prints the
// verification + proof URLs. Credentials go into `.sheaf/credentials.json`
// (0600 + added to .gitignore). Chain manifest goes into
// `.sheaf/config.json` (safe to commit). First event is tagged
// tool="sheaf://init" so the funnel endpoint can count init_runs.

import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { hostname } from "node:os";
import { join, resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";

type InitConfig = {
  recorderUrls: string[];
  cwd: string;
  logDebug: boolean;
};

type AccountResponse = {
  ok?: true;
  account_id?: string;
  api_key?: string;
  plan?: string;
  error?: string;
};

type EventReceipt = {
  ok?: true;
  seq?: number;
  envelope_hash?: string;
  error?: string;
};

function debug(cfg: InitConfig, ...args: unknown[]) {
  if (cfg.logDebug) console.error("[sheaf init]", ...args);
}

function randomSlug(prefix: string): string {
  const b = randomBytes(6).toString("hex");
  return `${prefix}-${b}`;
}

async function fetchWithFallback(
  urls: string[],
  path: string,
  init?: RequestInit,
): Promise<{ response: Response; sourceUrl: string }> {
  let lastErr: unknown;
  for (const base of urls) {
    try {
      const response = await fetch(base + path, init);
      return { response, sourceUrl: base };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error("no recorder URLs reachable");
}

async function createAccount(cfg: InitConfig): Promise<{ accountId: string; apiKey: string; baseUrl: string }> {
  const { response, sourceUrl } = await fetchWithFallback(cfg.recorderUrls, "/accounts", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!response.ok) {
    throw new Error(`POST /accounts returned HTTP ${response.status}`);
  }
  const body = (await response.json()) as AccountResponse;
  if (!body.account_id || !body.api_key) {
    throw new Error(`account response missing fields: ${body.error ?? JSON.stringify(body)}`);
  }
  return { accountId: body.account_id, apiKey: body.api_key, baseUrl: sourceUrl };
}

async function submitInitEvent(
  cfg: InitConfig,
  chainId: string,
  apiKey: string,
): Promise<EventReceipt> {
  const now = new Date().toISOString();
  const inputs = { chain_id: chainId, host: hostname(), created_at: now };
  const inputsHash =
    "sha256:" + createHash("sha256").update(JSON.stringify(inputs)).digest("hex");
  const envelope = {
    v: "arca/1" as const,
    event: {
      intent: "chain initialized via sheaf-mcp-recorder init",
      actor: chainId,
      authority: null,
      tool: "sheaf://init",
      inputs_hash: inputsHash,
      outputs_hash: null,
      result: "ok" as const,
      ts: now,
    },
    chain: { chain_id: chainId, seq: 0, prev_hash: null },
    signatures: { actor: null },
  };
  const { response } = await fetchWithFallback(cfg.recorderUrls, "/events", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(envelope),
  });
  const body = (await response.json()) as EventReceipt;
  if (response.status !== 201 || !body.ok) {
    throw new Error(`first-event submission failed (HTTP ${response.status}): ${body.error ?? "unknown"}`);
  }
  return body;
}

function ensureGitignoreEntry(cwd: string): { changed: boolean; path: string } {
  const gi = join(cwd, ".gitignore");
  const marker = ".sheaf/credentials.json";
  let content = "";
  let existed = false;
  if (existsSync(gi)) {
    existed = true;
    content = readFileSync(gi, "utf8");
  }
  if (content.split(/\r?\n/).some((l) => l.trim() === marker)) {
    return { changed: false, path: gi };
  }
  const prefix = content.length && !content.endsWith("\n") ? "\n" : "";
  const block = `${prefix}${existed ? "\n" : ""}# sheaf credentials — never commit\n${marker}\n`;
  writeFileSync(gi, content + block);
  return { changed: true, path: gi };
}

/** Build the MCP config snippet containing the real API key, write it to
 *  .sheaf/mcp-config.json, return the path. Does NOT print the key to
 *  stdout — the scrubber would redact it anyway, and we don't want secrets
 *  in terminal scrollback or session transcripts. */
function writeMcpConfigSnippet(opts: {
  chainId: string;
  apiKey: string;
  sheafDir: string;
}): string {
  const snippet = {
    mcpServers: {
      "my-filesystem": {
        command: "npx",
        args: [
          "-y",
          "@sheafhq/mcp-recorder",
          "--wrap",
          "npx",
          "-y",
          "@modelcontextprotocol/server-filesystem",
          "/path/to/your/files",
        ],
        env: {
          SHEAF_CHAIN_ID: opts.chainId,
          SHEAF_API_KEY: opts.apiKey,
        },
      },
    },
  };
  const path = join(opts.sheafDir, "mcp-config.json");
  writeFileSync(path, JSON.stringify(snippet, null, 2));
  try {
    chmodSync(path, 0o600);
  } catch {}
  return path;
}

export async function runInit(cfg: InitConfig): Promise<void> {
  const cwd = resolve(cfg.cwd);
  const sheafDir = join(cwd, ".sheaf");
  const configPath = join(sheafDir, "config.json");
  const credsPath = join(sheafDir, "credentials.json");

  if (existsSync(configPath) && existsSync(credsPath)) {
    const existing = JSON.parse(readFileSync(configPath, "utf8"));
    console.error(
      `sheaf-mcp-recorder: .sheaf/ already exists in ${cwd} (chain_id=${existing.chain_id}).`,
    );
    console.error(
      "Delete .sheaf/ to re-init, or set SHEAF_CHAIN_ID + SHEAF_API_KEY env vars to use the existing one.",
    );
    process.exit(2);
  }

  const chainId = randomSlug("agent");
  debug(cfg, `minting chain_id=${chainId}`);

  // Transparent account creation. The operator doesn't see this; it's just
  // the Bearer API key that will sign future events. If they want to migrate
  // / share / attach an email later, that's a separate (optional) flow.
  const { accountId, apiKey, baseUrl } = await createAccount(cfg);
  debug(cfg, `account_id=${accountId} via ${baseUrl}`);

  // First event: the chain creation itself. Tagged sheaf://init so the
  // server-side funnel endpoint can count init_runs distinctly from real
  // tool-call events.
  const receipt = await submitInitEvent(cfg, chainId, apiKey);
  debug(cfg, `first event seq=${receipt.seq} hash=${receipt.envelope_hash}`);

  // Persist. Credentials file is 0600 so other users on the machine can't
  // read the API key.
  mkdirSync(sheafDir, { recursive: true });
  const now = new Date().toISOString();
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        chain_id: chainId,
        recorder_url: baseUrl,
        created_at: now,
        first_event_hash: receipt.envelope_hash,
        _note:
          "Safe to commit. The secret (API key) is in credentials.json which is auto-added to .gitignore.",
      },
      null,
      2,
    ),
  );
  writeFileSync(
    credsPath,
    JSON.stringify(
      {
        account_id: accountId,
        api_key: apiKey,
        _warning: "Keep private. Added to .gitignore automatically.",
      },
      null,
      2,
    ),
  );
  try {
    chmodSync(credsPath, 0o600);
  } catch {
    // Windows: chmod is best-effort; skip silently.
  }
  const gi = ensureGitignoreEntry(cwd);

  // Output. Deliberately minimal and copy-pasteable.
  const verifyUrl = `${baseUrl}/c/${encodeURIComponent(chainId)}`;
  const proofUrl = `${baseUrl}/r/${encodeURIComponent(chainId)}/0`;
  const badgeMd = `[![sheaf](${baseUrl}/badge/${encodeURIComponent(chainId)}.svg)](${verifyUrl})`;

  const mcpConfigPath = writeMcpConfigSnippet({
    chainId,
    apiKey,
    sheafDir,
  });

  console.log("");
  console.log("✓ Sheaf chain created");
  console.log("");
  console.log(`  chain_id      ${chainId}`);
  console.log(`  recorder      ${baseUrl}`);
  console.log(`  verify URL    ${verifyUrl}`);
  console.log(`  proof URL     ${proofUrl}`);
  console.log(`  badge         ${badgeMd}`);
  console.log("");
  console.log(`  config saved  ${configPath}`);
  console.log(`  credentials   ${credsPath} (0600${gi.changed ? "; added to .gitignore" : "; .gitignore already covered it"})`);
  console.log(`  MCP snippet   ${mcpConfigPath} (0600; contains your api_key)`);
  console.log("");
  console.log(`API key was NOT printed to this terminal (Sheaf keys are scrubbed`);
  console.log(`from stdout to prevent transcript leaks). To wire it into Claude`);
  console.log(`Desktop, open:   cat ${mcpConfigPath}`);
  console.log(`and paste the "mcpServers" block into claude_desktop_config.json.`);
  console.log("");
  console.log(`Next: run your agent against the wrapped server. Every tools/call,`);
  console.log(`resources/read, and sampling/createMessage gets signed, hash-chained,`);
  console.log(`and anchored on Base mainnet.`);
}
