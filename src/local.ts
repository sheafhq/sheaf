// Local-first export and sync primitives for `sheaf local`.
//
// The local recorder writes `.sheaf/ledger.jsonl`; this module verifies that
// ledger, turns it into a local Merkle epoch, signs the case documents with the
// same local Ed25519 key, and stages a local anchor request. It never contacts
// the Sheaf Worker.

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { canonicalize } from "./canonical.js";
import { encodeAnchorCalldata } from "./disclose.js";
import { evidenceDocumentHash, stripDocumentSignature } from "./evidence.js";
import { buildMerkleTree } from "./merkle.js";
import { createX402Payer, paidFetch } from "./x402-payer.js";

export type LocalKeys = {
  schema: "sheaf.local-keys/1";
  key_id: string;
  public_key_base64: string;
  private_key_pkcs8_base64: string;
  created_at: string;
};

export type LocalLedgerRow = {
  schema: "sheaf.local-ledger/1";
  seq: number;
  chain_id: string;
  envelope: {
    v: "arca/1";
    event: Record<string, unknown>;
    chain: { chain_id: string; seq: number; prev_hash: string | null };
    signatures: { actor: null; recorder: string };
  };
  envelope_hash: string;
  recorded_at: string;
  payloads?: { arguments?: string; result?: string };
};

export type LocalAnchorState = {
  schema: "sheaf.local-anchor/1";
  chain_id: string;
  merkle_root: string;
  event_count: number;
  epoch_id: number;
  tx_hash: string;
  block_number: number | null;
  anchorer: string;
  network: "eip155:8453";
  calldata: string;
  created_at: string;
};

function mode(path: string, value: number): void {
  try {
    chmodSync(path, value);
  } catch {
    // Windows ACLs are the operating-system boundary.
  }
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}

function publicKeyFromRaw(rawBase64: string) {
  const raw = Buffer.from(rawBase64, "base64");
  if (raw.length !== 32) throw new Error("local public key must be 32 bytes");
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([prefix, raw]),
    format: "der",
    type: "spki",
  });
}

export function loadLocalKeys(chainDir: string): LocalKeys {
  const path = join(chainDir, "local-keys.json");
  if (!existsSync(path)) {
    throw new Error(
      `missing ${path}; run the local recorder at least once before export`,
    );
  }
  const keys = readJson(path) as LocalKeys;
  if (
    keys?.schema !== "sheaf.local-keys/1" ||
    !keys.key_id ||
    !keys.public_key_base64 ||
    !keys.private_key_pkcs8_base64
  ) {
    throw new Error(`invalid local key file ${path}`);
  }
  return keys;
}

export function readLocalLedger(chainDir: string): LocalLedgerRow[] {
  const path = join(chainDir, "ledger.jsonl");
  if (!existsSync(path)) throw new Error(`missing ${path}`);
  const rows: LocalLedgerRow[] = readFileSync(path, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, idx) => {
      try {
        return JSON.parse(line) as LocalLedgerRow;
      } catch (err) {
        throw new Error(`ledger line ${idx + 1}: ${(err as Error).message}`);
      }
    });
  if (rows.length === 0) throw new Error("local ledger is empty");
  return rows;
}

/** Verify the local ledger's signatures and chain links before exporting. */
export function assertLocalLedger(chainDir: string): {
  keys: LocalKeys;
  rows: LocalLedgerRow[];
} {
  const keys = loadLocalKeys(chainDir);
  const rows = readLocalLedger(chainDir);
  const publicKey = publicKeyFromRaw(keys.public_key_base64);
  let prev: string | null = null;
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i]!;
    if (row.seq !== i) throw new Error(`ledger seq ${i} is not contiguous`);
    if (row.chain_id !== rows[0]!.chain_id) {
      throw new Error(`ledger seq ${i} has a mixed chain_id`);
    }
    if (row.envelope.chain.prev_hash !== prev) {
      throw new Error(`ledger seq ${i} prev_hash mismatch`);
    }
    const core = {
      v: row.envelope.v,
      event: row.envelope.event,
      chain: row.envelope.chain,
    };
    const computed = awaitHash(core);
    if (computed !== row.envelope_hash) {
      throw new Error(`ledger seq ${i} envelope_hash mismatch`);
    }
    const ok = verify(
      null,
      Buffer.from(canonicalize(core)),
      publicKey,
      Buffer.from(row.envelope.signatures.recorder, "base64"),
    );
    if (!ok) throw new Error(`ledger seq ${i} recorder signature invalid`);
    prev = row.envelope_hash;
  }
  return { keys, rows };
}

function awaitHash(value: unknown): string {
  // The root canonical.ts hashCanonical is async; ledger hashes are plain
  // SHA-256(JCS), so use the synchronous canonicalizer + node crypto.
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

export async function buildLocalArchive(
  chainDir: string,
  archivePath: string,
): Promise<{
  root: string;
  chainId: string;
  eventCount: number;
  anchorMode: "base" | "local";
  txHash: string;
  blockNumber: number | null;
}> {
  const { keys, rows } = assertLocalLedger(chainDir);
  const leaves = rows.map((row) => row.envelope_hash);
  const { root } = await buildMerkleTree(leaves);
  const chainId = rows[0]!.chain_id;
  const state = readLocalAnchorState(chainDir);
  if (state) {
    if (state.chain_id !== chainId || state.merkle_root !== root) {
      throw new Error(
        "local anchor does not match the current ledger root; run `sheaf local sync` again",
      );
    }
  }
  const anchorMode = state ? "base" : "local";
  const txHash = state ? state.tx_hash : `local:${root}`;
  const blockNumber = state ? state.block_number : 0;
  const epochId = state ? state.epoch_id : 0;
  const anchorer = state ? state.anchorer : "local";
  const network = state ? state.network : "eip155:8453";
  const lines = [
    JSON.stringify({
      type: "meta",
      chain_id: chainId,
      recorder: {
        name: "sheaf-local",
        key_id: keys.key_id,
        public_key_base64: keys.public_key_base64,
        public_key_url: "",
      },
      anchorer,
      network,
      created_at: new Date().toISOString(),
    }),
    JSON.stringify({
      type: "epoch",
      epoch_id: epochId,
      merkle_root: root,
      anchor_tx_hash: txHash,
      anchor_block: blockNumber,
    }),
    ...rows.map((row, idx) =>
      JSON.stringify({
        type: "event",
        seq: row.seq,
        envelope: row.envelope,
        envelope_hash: row.envelope_hash,
        epoch_id: epochId,
        epoch_leaf_idx: idx,
      }),
    ),
  ];
  mkdirSync(dirname(archivePath), { recursive: true, mode: 0o700 });
  writeFileSync(archivePath, lines.join("\n") + "\n", { mode: 0o600 });
  mode(archivePath, 0o600);
  return {
    root,
    chainId,
    eventCount: rows.length,
    anchorMode,
    txHash,
    blockNumber,
  };
}

export function readLocalAnchorState(
  chainDir: string,
): LocalAnchorState | null {
  const path = join(chainDir, "anchor.json");
  if (!existsSync(path)) return null;
  const state = readJson(path) as LocalAnchorState;
  if (state?.schema !== "sheaf.local-anchor/1") {
    throw new Error(`invalid local anchor state ${path}`);
  }
  return state;
}

export function writeLocalTrust(chainDir: string): string {
  const keys = loadLocalKeys(chainDir);
  const state = readLocalAnchorState(chainDir);
  const path = join(chainDir, "trust.json");
  const anchorers = [
    {
      network: "eip155:8453",
      address: "local",
      active_from: "2020-01-01T00:00:00Z",
      active_until: null,
    },
  ];
  if (state && state.anchorer !== "local") {
    anchorers.push({
      network: "eip155:8453",
      address: state.anchorer,
      active_from: "2020-01-01T00:00:00Z",
      active_until: null,
    });
  }
  const trust = {
    recorder_keys: [
      {
        key_id: keys.key_id,
        public_key_base64: keys.public_key_base64,
        active_from: "2020-01-01T00:00:00Z",
        active_until: null,
      },
    ],
    anchorers,
  };
  writeFileSync(path, JSON.stringify(trust, null, 2) + "\n", { mode: 0o600 });
  mode(path, 0o600);
  return path;
}

async function signDocument(
  document: Record<string, any>,
  keys: LocalKeys,
): Promise<Record<string, any>> {
  const unsigned = stripDocumentSignature(document);
  const digest = Buffer.from(await evidenceDocumentHash(unsigned), "hex");
  const privateKey = createPrivateKey({
    key: Buffer.from(keys.private_key_pkcs8_base64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = sign(null, digest, privateKey).toString("base64");
  return {
    ...unsigned,
    document_signature: {
      alg: "Ed25519",
      key_id: keys.key_id,
      public_key_base64: keys.public_key_base64,
      signature_base64: signature,
    },
  };
}

export async function prepareLocalCase(
  chainDir: string,
  casePath: string,
): Promise<string> {
  const keys = loadLocalKeys(chainDir);
  const manifest = readJson(casePath);
  const base = dirname(resolve(casePath));
  const docsDir = join(chainDir, "documents");
  mkdirSync(docsDir, { recursive: true, mode: 0o700 });

  const resolveDoc = (path: string): string =>
    isAbsolute(path) ? path : resolve(base, path);
  const signTo = async (
    kind: string,
    path: string,
  ): Promise<Record<string, any>> => {
    const signed = await signDocument(readJson(resolveDoc(path)), keys);
    const out = join(docsDir, `${kind}.json`);
    writeFileSync(out, JSON.stringify(signed, null, 2) + "\n", { mode: 0o600 });
    mode(out, 0o600);
    return signed;
  };

  let signedMandate: Record<string, any> | undefined;
  if (manifest.evidence?.mandate?.document) {
    signedMandate = await signTo("mandate", manifest.evidence.mandate.document);
    manifest.evidence.mandate.document = join(docsDir, "mandate.json");
  }
  if (manifest.evidence?.delegation?.chain) {
    for (let i = 0; i < manifest.evidence.delegation.chain.length; i++) {
      const link = manifest.evidence.delegation.chain[i];
      if (!link.document) continue;
      await signTo(`delegation-${i}`, link.document);
      link.document = join(docsDir, `delegation-${i}.json`);
    }
    if (signedMandate) {
      manifest.evidence.delegation.root = {
        type: "human",
        id: signedMandate.principal?.id ?? "local-principal",
        display_name: signedMandate.principal?.display_name ?? "Local principal",
        attestation: {
          basis: "principal_signature",
          key_id: keys.key_id,
          public_key_base64: keys.public_key_base64,
          signature_base64:
            signedMandate.document_signature?.signature_base64 ?? "",
        },
      };
    }
  }
  if (manifest.evidence?.consent?.document) {
    await signTo("consent", manifest.evidence.consent.document);
    manifest.evidence.consent.document = join(docsDir, "consent.json");
  }

  if (Array.isArray(manifest.payloads)) {
    for (const item of manifest.payloads) {
      if (typeof item.path === "string" && !isAbsolute(item.path)) {
        item.path = resolve(base, item.path);
      }
    }
  }

  const out = join(chainDir, "export-case.json");
  writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600 });
  mode(out, 0o600);
  return out;
}

export async function prepareLocalExport(
  chainDir: string,
  casePath: string,
): Promise<{
  archivePath: string;
  casePath: string;
  trustPath: string;
  policyPath: string | null;
  root: string;
  chainId: string;
  eventCount: number;
  anchorMode: "base" | "local";
  txHash: string;
  blockNumber: number | null;
}> {
  const archivePath = join(chainDir, "export-archive.jsonl");
  const built = await buildLocalArchive(chainDir, archivePath);
  const signedCase = await prepareLocalCase(chainDir, casePath);
  const trustPath = writeLocalTrust(chainDir);
  const policyPath = join(chainDir, "policy.json");
  return {
    archivePath,
    casePath: signedCase,
    trustPath,
    policyPath: existsSync(policyPath) ? policyPath : null,
    ...built,
  };
}

type AnchorRequest = {
  schema: "sheaf.local-anchor-request/1";
  chain_id: string;
  merkle_root: string;
  event_count: number;
  recorder_key_id: string;
  recorder_public_key_base64: string;
  public_key: string;
  calldata: string;
  created_at: string;
  endpoint: string | null;
  note: string;
  signature_base64: string;
};

async function buildAnchorRequest(
  chainDir: string,
  endpoint: string | null,
): Promise<{
  request: AnchorRequest;
  path: string;
  root: string;
  chainId: string;
  eventCount: number;
}> {
  const { keys, rows } = assertLocalLedger(chainDir);
  const { root } = await buildMerkleTree(rows.map((r) => r.envelope_hash));
  const core = {
    schema: "sheaf.local-anchor-request/1" as const,
    chain_id: rows[0]!.chain_id,
    merkle_root: root,
    event_count: rows.length,
    recorder_key_id: keys.key_id,
    recorder_public_key_base64: keys.public_key_base64,
    public_key: keys.public_key_base64,
    calldata: encodeAnchorCalldata(0, root),
    created_at: new Date().toISOString(),
    endpoint,
    note:
      endpoint === null
        ? "Staged locally; not yet submitted."
        : "Signed local anchor request.",
  };
  const privateKey = createPrivateKey({
    key: Buffer.from(keys.private_key_pkcs8_base64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = sign(
    null,
    Buffer.from(canonicalize(core)),
    privateKey,
  ).toString("base64");
  const request: AnchorRequest = { ...core, signature_base64: signature };
  const path = join(chainDir, "anchor-request.json");
  writeFileSync(path, JSON.stringify(request, null, 2) + "\n", { mode: 0o600 });
  mode(path, 0o600);
  return {
    request,
    path,
    root,
    chainId: core.chain_id,
    eventCount: core.event_count,
  };
}

export async function stageLocalAnchorRequest(chainDir: string): Promise<{
  path: string;
  root: string;
  chainId: string;
  eventCount: number;
}> {
  const built = await buildAnchorRequest(chainDir, null);
  return {
    path: built.path,
    root: built.root,
    chainId: built.chainId,
    eventCount: built.eventCount,
  };
}

export async function syncLocalAnchor(
  chainDir: string,
  endpoint: string,
): Promise<{
  path: string;
  statePath: string;
  state: LocalAnchorState;
  response: any;
}> {
  const built = await buildAnchorRequest(chainDir, endpoint);
  const init: RequestInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(built.request),
  };
  let response = await fetch(endpoint, init);
  if (response.status === 402) {
    const payerKey = process.env.SHEAF_PAYER_PRIVATE_KEY;
    if (!payerKey) {
      throw new Error(
        "anchor endpoint returned 402 Payment Required; set SHEAF_PAYER_PRIVATE_KEY to a funded Base wallet for automatic x402 payment",
      );
    }
    response = await paidFetch(endpoint, init, createX402Payer(payerKey));
  }
  const text = await response.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`anchor endpoint returned ${response.status}: ${text}`);
  }
  if (!response.ok || !body?.tx_hash) {
    throw new Error(
      `anchor endpoint returned ${response.status}: ${body?.error ?? text}`,
    );
  }
  const state: LocalAnchorState = {
    schema: "sheaf.local-anchor/1",
    chain_id: built.chainId,
    merkle_root: built.root,
    event_count: built.eventCount,
    epoch_id: Number(body.epoch_id),
    tx_hash: String(body.tx_hash),
    block_number:
      body.block_number === null || body.block_number === undefined
        ? null
        : Number(body.block_number),
    anchorer: String(body.anchorer ?? ""),
    network: "eip155:8453",
    calldata: String(
      body.calldata ?? encodeAnchorCalldata(Number(body.epoch_id), built.root),
    ),
    created_at: new Date().toISOString(),
  };
  if (!state.anchorer) throw new Error("anchor endpoint returned no anchorer");
  const statePath = join(chainDir, "anchor.json");
  writeFileSync(statePath, JSON.stringify(state, null, 2) + "\n", {
    mode: 0o600,
  });
  mode(statePath, 0o600);
  return { path: built.path, statePath, state, response: body };
}
