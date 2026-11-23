#!/usr/bin/env node
// CLI entry for @sheafhq/verify. Verifies a bundle offline.
//
// Usage:
//   npx @sheafhq/verify <bundle.sheaf>
//   npx @sheafhq/verify --rpc https://base-mainnet.g.alchemy.com/v2/<key> bundle.sheaf
//   cat bundle.sheaf | npx @sheafhq/verify -
//
// sheaf.dispute-bundle/1 and /2 files are detected by their `schema` field
// and verified with verifyDisputeBundle against the pinned trust store.
//
// Exits 0 if the bundle is valid, 1 if not, 2 for argument / fetch errors,
// 3 for a dispute bundle verified --offline whose anchor is unconfirmed
// (unless --allow-unconfirmed-anchor).

import { readFileSync } from "node:fs";
import {
  verify,
  verifyDisclosures,
  verifyDisputeBundle,
  formatDisputeVerification,
  defaultTrustStore,
  DISPUTE_BUNDLE_SCHEMA,
  DISPUTE_BUNDLE_SCHEMA_V2,
  type DisclosureSet,
  type TrustStore,
  type TrustedSigner,
} from "./index.js";

const DEFAULT_RPC = "https://mainnet.base.org";
const DEFAULT_ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";

type Args = {
  bundlePath: string | "-";
  rpc: string;
  anchorer: string;
  recorderKey?: string;
  recorderUrl?: string;
  dispute: boolean;
  offline: boolean;
  trustPath?: string;
  signersPath?: string;
  allowUnconfirmedAnchor: boolean;
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
      "  --dispute                     Verify a sheaf-disclosure/1 set using the pinned trust store",
      "  --offline                     Dispute/disclosure only: skip the Base RPC anchor check",
      "  --trust <path>                Dispute/disclosure only: JSON {recorder_keys, anchorers}",
      "  --signers <path>              Dispute bundles only: sheaf.trusted-signers/1 pins",
      "  --allow-unconfirmed-anchor    Dispute bundles only: exit 0 (not 3) when --offline",
      "                                integrity is valid but the anchor is unconfirmed",
      "",
      "sheaf.dispute-bundle/1 and /2 files are detected automatically (no flag needed).",
      "Legacy sheaf-bundle/1 behavior is unchanged. In dispute mode the key and",
      "anchorer come from the pinned trust store; public_key_url is never fetched.",
    ].join("\n"),
  );
  process.exit(code);
}

function parseArgs(argv: string[]): Args {
  const rest: string[] = [];
  const a: Partial<Args> = {
    rpc: DEFAULT_RPC,
    anchorer: DEFAULT_ANCHORER,
    dispute: false,
    offline: false,
    allowUnconfirmedAnchor: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i]!;
    if (v === "--rpc") a.rpc = argv[++i] ?? die("--rpc requires a URL");
    else if (v === "--anchorer") a.anchorer = argv[++i] ?? die("--anchorer requires an address");
    else if (v === "--recorder-key") a.recorderKey = argv[++i] ?? die("--recorder-key requires a value");
    else if (v === "--recorder-url") a.recorderUrl = argv[++i] ?? die("--recorder-url requires a URL");
    else if (v === "--dispute") a.dispute = true;
    else if (v === "--offline") a.offline = true;
    else if (v === "--trust") a.trustPath = argv[++i] ?? die("--trust requires a path");
    else if (v === "--allow-unconfirmed-anchor") a.allowUnconfirmedAnchor = true;
    else if (v === "--signers") a.signersPath = argv[++i] ?? die("--signers requires a path");
    else if (v === "--help" || v === "-h") die("", 0);
    else rest.push(v);
  }
  if (rest.length !== 1) die("expected exactly one bundle path (or '-' for stdin)");
  if (a.dispute && (a.recorderKey || a.recorderUrl)) {
    die(
      "--recorder-key/--recorder-url are legacy-only; dispute mode uses the pinned --trust store",
    );
  }
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

const DEFAULT_RECORDER_URLS = [
  "https://api.sheafhq.io",
  "https://sheaf-recorder.goldencalf.workers.dev",
];

async function resolveRecorderKey(
  bundle: BundleShape,
  args: Args,
): Promise<string> {
  if (args.recorderKey) return args.recorderKey;
  if (bundle.issuer?.public_key_base64) return bundle.issuer.public_key_base64;
  const urls = args.recorderUrl ? [args.recorderUrl] : DEFAULT_RECORDER_URLS;
  let lastErr: unknown;
  for (const base of urls) {
    const url = base + "/.well-known/sheaf-public-key";
    try {
      const r = await fetch(url);
      if (!r.ok) {
        lastErr = new Error(`HTTP ${r.status} from ${url}`);
        continue;
      }
      const pk = (await r.json()) as {
        active_key_id: string;
        keys: Array<{ key_id: string; public_key_base64: string }>;
      };
      const active = pk.keys.find((k) => k.key_id === pk.active_key_id);
      if (!active) {
        lastErr = new Error(`active recorder key not found in keyring at ${url}`);
        continue;
      }
      return active.public_key_base64;
    } catch (err) {
      lastErr = err;
    }
  }
  die(`could not fetch recorder public key: ${(lastErr as Error)?.message ?? "unknown error"}`);
}

function loadTrust(path: string): TrustStore {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    die(`could not read trust file: ${(err as Error).message}`);
  }
  const t = parsed as Partial<TrustStore>;
  if (!Array.isArray(t.recorder_keys) || !Array.isArray(t.anchorers)) {
    die("trust file must contain recorder_keys[] and anchorers[]");
  }
  return t as TrustStore;
}

function loadSigners(path: string): TrustedSigner[] {
  let doc: { schema?: unknown; signers?: unknown };
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    die(`could not read signers file: ${(err as Error).message}`);
  }
  if (doc?.schema !== "sheaf.trusted-signers/1" || !Array.isArray(doc.signers)) {
    die(`${path} is not a sheaf.trusted-signers/1 document`);
  }
  return doc.signers as TrustedSigner[];
}

function isDisputeBundle(bundle: unknown): boolean {
  const schema = (bundle as { schema?: unknown } | null)?.schema;
  return schema === DISPUTE_BUNDLE_SCHEMA || schema === DISPUTE_BUNDLE_SCHEMA_V2;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bundle = (await readBundle(args.bundlePath)) as BundleShape;

  if (isDisputeBundle(bundle)) {
    if (args.recorderKey || args.recorderUrl) {
      die("--recorder-key/--recorder-url do not apply to dispute bundles; use --trust");
    }
    const result = await verifyDisputeBundle(bundle, {
      trust: args.trustPath ? loadTrust(args.trustPath) : defaultTrustStore(),
      ...(args.offline ? {} : { base_rpc: args.rpc }),
      ...(args.signersPath ? { trusted_signers: loadSigners(args.signersPath) } : {}),
    });
    process.stdout.write(formatDisputeVerification(result));
    if (!result.valid) process.exit(1);
    if (args.offline && !result.anchor_confirmed && !args.allowUnconfirmedAnchor) process.exit(3);
    process.exit(0);
  }

  if (!args.dispute) {
    if (args.offline) die("--offline requires --dispute or a dispute bundle");
    if (args.trustPath) die("--trust requires --dispute or a dispute bundle");
  }
  if (args.signersPath) die("--signers applies to dispute bundles only");
  if (args.allowUnconfirmedAnchor) die("--allow-unconfirmed-anchor applies to dispute bundles only");

  if (args.dispute) {
    const disclosure = bundle as unknown as DisclosureSet;
    const trust = args.trustPath ? loadTrust(args.trustPath) : defaultTrustStore();
    const result = await verifyDisclosures(disclosure, {
      mode: "dispute",
      trust,
      ...(args.offline ? {} : { base_rpc: args.rpc }),
    });

    const marks = { true: "✓", false: "✗", null: "–" } as const;
    const suffix = result.anchor_confirmed
      ? " (anchor confirmed)"
      : " (integrity only; anchor unconfirmed)";
    console.log(result.valid ? `VALID${suffix}` : "NOT VALID");
    if (result.code) console.log(`code: ${result.code}`);
    if (result.reason) console.log(`reason: ${result.reason}`);
    if (result.failed_event_ref) {
      console.log(
        `failed event: ${result.failed_event_ref.chain_id}/${result.failed_event_ref.seq}`,
      );
    }
    console.log(
      `chain: ${disclosure.chain_id} seq ${disclosure.from_seq}..${disclosure.to_seq}`,
    );
    if (Array.isArray(disclosure.warnings) && disclosure.warnings.length > 0) {
      for (const warning of disclosure.warnings) {
        console.log(`warning: ${warning}`);
      }
    }
    console.log("checks:");
    for (const [k, v] of Object.entries(result.checks)) {
      const mark = marks[String(v) as "true" | "false" | "null"] ?? "?";
      console.log(`  ${mark} ${k}`);
    }
    process.exit(result.valid ? 0 : 1);
  }

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
