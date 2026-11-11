#!/usr/bin/env node
// CLI entry for @sheafhq/verify. Verifies a bundle offline.
//
// Usage:
//   npx @sheafhq/verify <bundle.sheaf>
//   npx @sheafhq/verify --rpc https://base-mainnet.g.alchemy.com/v2/<key> bundle.sheaf
//   cat bundle.sheaf | npx @sheafhq/verify -
//
// Exits 0 if the bundle is valid, 1 if not, 2 for argument / fetch errors.

import { readFileSync } from "node:fs";
import { verify } from "./index.js";

const DEFAULT_RPC = "https://mainnet.base.org";
const DEFAULT_ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";

type Args = {
  bundlePath: string | "-";
  rpc: string;
  anchorer: string;
  recorderKey?: string;
  recorderUrl?: string;
};

function die(msg: string, code = 2): never {
  console.error(`sheaf-verify: ${msg}`);
  console.error(
    [
      "",
      "usage: sheaf-verify [options] <bundle.sheaf | - for stdin>",
      "",
      "options:",
      "  --rpc <url>                   Base mainnet RPC (default: " + DEFAULT_RPC + ")",
      "  --anchorer <0x...>            Expected anchorer address (default: canonical sheaf)",
      "  --recorder-key <base64>       Recorder Ed25519 public key (base64)",
      "  --recorder-url <url>          Recorder base URL to fetch /.well-known/sheaf-public-key",
      "                                (default: use key embedded in bundle; or https://sheaf-recorder.goldencalf.workers.dev)",
      "",
      "If neither --recorder-key nor the bundle's issuer.public_key_base64 is",
      "present, the CLI fetches /.well-known/sheaf-public-key from --recorder-url.",
    ].join("\n"),
  );
  process.exit(code);
}

function parseArgs(argv: string[]): Args {
  const rest: string[] = [];
  const a: Partial<Args> = { rpc: DEFAULT_RPC, anchorer: DEFAULT_ANCHORER };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i]!;
    if (v === "--rpc") a.rpc = argv[++i] ?? die("--rpc requires a URL");
    else if (v === "--anchorer") a.anchorer = argv[++i] ?? die("--anchorer requires an address");
    else if (v === "--recorder-key") a.recorderKey = argv[++i] ?? die("--recorder-key requires a value");
    else if (v === "--recorder-url") a.recorderUrl = argv[++i] ?? die("--recorder-url requires a URL");
    else if (v === "--help" || v === "-h") die("", 0);
    else rest.push(v);
  }
  if (rest.length !== 1) die("expected exactly one bundle path (or '-' for stdin)");
  return { ...(a as Args), bundlePath: rest[0] as string };
}

async function readBundle(path: string | "-"): Promise<unknown> {
  let text: string;
  if (path === "-") {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    text = Buffer.concat(chunks).toString("utf8");
  } else {
    text = readFileSync(path, "utf8");
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    die(`could not parse bundle JSON: ${(err as Error).message}`);
  }
}

type BundleShape = {
  version?: string;
  envelope?: unknown;
  envelope_hash?: string;
  anchor?: {
    tx_hash?: string;
    merkle_root?: string;
    leaf_index?: number;
    siblings?: Array<{ hash: string; side: "left" | "right" }>;
  };
  issuer?: { public_key_base64?: string };
  inclusion_proof?: {
    leaf: string;
    leaf_index: number;
    merkle_root: string;
    siblings: Array<{ hash: string; side: "left" | "right" }>;
  };
  anchor_tx_hash?: string;
};

function normalize(bundle: unknown): {
  envelope: unknown;
  inclusion_proof: {
    leaf: string;
    leaf_index: number;
    merkle_root: string;
    siblings: Array<{ hash: string; side: "left" | "right" }>;
  };
  anchor_tx_hash: string;
} {
  const b = bundle as BundleShape;
  if (b.version === "sheaf-bundle/1" && b.envelope && b.anchor && b.envelope_hash) {
    return {
      envelope: b.envelope,
      inclusion_proof: {
        leaf: b.envelope_hash,
        leaf_index: b.anchor.leaf_index ?? 0,
        merkle_root: b.anchor.merkle_root ?? "",
        siblings: b.anchor.siblings ?? [],
      },
      anchor_tx_hash: b.anchor.tx_hash ?? "",
    };
  }
  if (b.envelope && b.inclusion_proof && b.anchor_tx_hash) {
    return {
      envelope: b.envelope,
      inclusion_proof: b.inclusion_proof,
      anchor_tx_hash: b.anchor_tx_hash,
    };
  }
  die("bundle shape not recognized (expected sheaf-bundle/1 or legacy)");
}

async function resolveRecorderKey(
  bundle: BundleShape,
  args: Args,
): Promise<string> {
  if (args.recorderKey) return args.recorderKey;
  if (bundle.issuer?.public_key_base64) return bundle.issuer.public_key_base64;
  const url =
    (args.recorderUrl ??
      "https://sheaf-recorder.goldencalf.workers.dev") +
    "/.well-known/sheaf-public-key";
  const r = await fetch(url);
  if (!r.ok) die(`could not fetch recorder public key from ${url}: HTTP ${r.status}`);
  const pk = (await r.json()) as {
    active_key_id: string;
    keys: Array<{ key_id: string; public_key_base64: string }>;
  };
  const active = pk.keys.find((k) => k.key_id === pk.active_key_id);
  if (!active) die(`active recorder key not found in keyring at ${url}`);
  return active.public_key_base64;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bundle = (await readBundle(args.bundlePath)) as BundleShape;
  const recorderKey = await resolveRecorderKey(bundle, args);
  const verifyInput = normalize(bundle);
  const result = await verify(verifyInput as never, {
    base_rpc: args.rpc,
    recorder_public_key_base64: recorderKey,
    expected_anchorer_address: args.anchorer,
  });

  // Pretty-print check status
  const marks = { true: "✓", false: "✗", null: "–" } as const;
  console.log(result.valid ? "VALID" : "NOT VALID");
  if (result.reason) console.log(`reason: ${result.reason}`);
  if (result.anchor_block) console.log(`anchor block: ${result.anchor_block}`);
  console.log("checks:");
  for (const [k, v] of Object.entries(result.checks)) {
    const mark = marks[String(v) as "true" | "false" | "null"] ?? "?";
    console.log(`  ${mark} ${k}`);
  }
  process.exit(result.valid ? 0 : 1);
}

main().catch((err) => {
  console.error(`sheaf-verify: ${(err as Error).message}`);
  process.exit(2);
});
