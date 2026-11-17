// Local-first export and sync primitives for `sheaf local`.
//
// The local recorder writes `.sheaf/ledger.jsonl`; this module verifies that
// ledger, turns it into a local Merkle epoch, and stages a local anchor
// request. It never contacts the Sheaf Worker.
//
// SECURITY (S1, see docs/SAP-ARCHITECTURE.md §13): the local ledger key is a
// RECORDER key. It signs envelopes and anchor requests, and nothing else. It
// must never sign mandate / delegation / consent documents: a recorder
// signature is not a principal's authorisation. Case documents are passed
// through with whatever principal signatures they already carry; principals
// sign with their own key via `sheaf local sign-document`, which refuses the
// ledger key and any pinned recorder key.

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

import { verifyEd25519 as verifyEd25519Strict } from "../packages/verify/dist/index.js";
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

/** A refusal from the S1 safeguards. `code` is stable and test-visible. */
export class LocalSigningError extends Error {
  constructor(
    public readonly code:
      | "RECORDER_SIGNED_NOT_PRINCIPAL"
      | "SIGNING_KEY_IS_RECORDER_KEY"
      | "DOCUMENT_SIGNATURE_INVALID"
      | "INVALID_SIGNING_KEY",
    message: string,
  ) {
    super(message);
    this.name = "LocalSigningError";
  }
}

type DocumentSignature = {
  alg: string;
  key_id: string;
  public_key_base64: string;
  signature_base64: string;
};

/** Verify an existing document_signature under its embedded key, with the
 *  verifier's own strict Ed25519 implementation (rejects small-order keys,
 *  non-canonical points, S >= L), so local export never passes on a signature
 *  that the verifier would reject. */
async function documentSignatureValid(
  document: Record<string, any>,
): Promise<boolean> {
  const sig = document.document_signature as DocumentSignature | undefined;
  if (!sig) return false;
  if (sig.alg !== "Ed25519") return false;
  try {
    const digest = new Uint8Array(
      Buffer.from(await evidenceDocumentHash(stripDocumentSignature(document)), "hex"),
    );
    return await verifyEd25519Strict(sig.public_key_base64, sig.signature_base64, digest);
  } catch {
    return false;
  }
}

/** Raw-bytes identity (hex) of an Ed25519 public key. Every base64 spelling
 *  of one key maps to the same value; never compare key strings or key_id. */
export function keyFingerprint(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const raw = Buffer.from(value, "base64");
  return raw.length === 32 ? raw.toString("hex") : null;
}

/** Fingerprints of every key that acts as a RECORDER in this context: the
 *  local ledger key (if present) plus pinned recorder keys. */
export function recorderPublicKeys(
  chainDir: string | null,
  pinned: string[],
): Set<string> {
  const keys = new Set<string>();
  for (const k of pinned) {
    const fp = keyFingerprint(k);
    if (fp) keys.add(fp);
  }
  if (chainDir && existsSync(join(chainDir, "local-keys.json"))) {
    const fp = keyFingerprint(loadLocalKeys(chainDir).public_key_base64);
    if (fp) keys.add(fp);
  }
  return keys;
}

/** Strict base64: the string must be the canonical encoding of exactly
 *  `length` bytes. Mirrors the verifier, so export refuses what the verifier
 *  would reject. */
function isCanonicalBase64(value: unknown, length: number): boolean {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const raw = Buffer.from(value, "base64");
  return raw.length === length && raw.toString("base64") === value;
}

/**
 * Copy the case documents into the chain directory WITHOUT signing them.
 *
 * - A document that already carries a valid signature by a non-recorder key
 *   (a principal / payer / policy key) is copied byte-for-byte.
 * - A document signed with the local recorder key is refused
 *   (RECORDER_SIGNED_NOT_PRINCIPAL): it was produced by the pre-S1 code path.
 * - A document whose signature does not verify (e.g. edited after signing) is
 *   refused (DOCUMENT_SIGNATURE_INVALID); it is never silently stripped.
 * - An unsigned document stays unsigned; the bundle then reports the missing
 *   principal signature as an evidence gap.
 */
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
  const copyTo = async (
    kind: string,
    path: string,
  ): Promise<Record<string, any>> => {
    const document = readJson(resolveDoc(path));
    const sig = document.document_signature as DocumentSignature | undefined;
    if (sig) {
      if (
        typeof sig !== "object" ||
        Array.isArray(sig) ||
        !isCanonicalBase64(sig.public_key_base64, 32) ||
        !isCanonicalBase64(sig.signature_base64, 64)
      ) {
        throw new LocalSigningError(
          "DOCUMENT_SIGNATURE_INVALID",
          `${kind} document ${path} has a malformed or non-canonically encoded document_signature.`,
        );
      }
      if (keyFingerprint(sig.public_key_base64) === keyFingerprint(keys.public_key_base64)) {
        throw new LocalSigningError(
          "RECORDER_SIGNED_NOT_PRINCIPAL",
          `${kind} document ${path} is signed with the local recorder key (${keys.key_id}). ` +
            "A recorder signature is not the principal's authorisation. Remove document_signature, " +
            "or have the principal sign it with `sheaf local sign-document`.",
        );
      }
      if (!(await documentSignatureValid(document))) {
        throw new LocalSigningError(
          "DOCUMENT_SIGNATURE_INVALID",
          `${kind} document ${path} has a document_signature that does not verify ` +
            "(was the document edited after signing?). Re-sign it or remove the signature.",
        );
      }
    }
    const out = join(docsDir, `${kind}.json`);
    writeFileSync(out, JSON.stringify(document, null, 2) + "\n", { mode: 0o600 });
    mode(out, 0o600);
    return document;
  };

  let mandateDoc: Record<string, any> | undefined;
  if (manifest.evidence?.mandate?.document) {
    mandateDoc = await copyTo("mandate", manifest.evidence.mandate.document);
    manifest.evidence.mandate.document = join(docsDir, "mandate.json");
  }
  if (manifest.evidence?.delegation?.chain) {
    for (let i = 0; i < manifest.evidence.delegation.chain.length; i++) {
      const link = manifest.evidence.delegation.chain[i];
      if (!link.document) continue;
      await copyTo(`delegation-${i}`, link.document);
      link.document = join(docsDir, `delegation-${i}.json`);
    }
    if (mandateDoc) {
      // The root attestation reflects what actually exists: a principal (or
      // policy) signature on the mandate if there is one, otherwise only the
      // recorder's observation of the mandate event.
      const sig = mandateDoc.document_signature as DocumentSignature | undefined;
      const isPolicy = mandateDoc.principal?.type === "policy";
      manifest.evidence.delegation.root = {
        type: isPolicy ? "policy" : "human",
        id: mandateDoc.principal?.id ?? "local-principal",
        display_name: mandateDoc.principal?.display_name ?? "Local principal",
        attestation: sig
          ? {
              basis: isPolicy ? "policy_signature" : "principal_signature",
              key_id: sig.key_id,
              public_key_base64: sig.public_key_base64,
              signature_base64: sig.signature_base64,
            }
          : { basis: "recorder_observed" },
      };
    }
  }
  if (manifest.evidence?.consent?.document) {
    await copyTo("consent", manifest.evidence.consent.document);
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

/**
 * Sign an evidence document with a PRINCIPAL-held Ed25519 key (PKCS#8 PEM).
 *
 * Refuses (SIGNING_KEY_IS_RECORDER_KEY) when the key is the local ledger key
 * or any pinned recorder key: the recorder must never produce a principal's
 * signature. Any existing document_signature is replaced.
 */
export async function signDocumentWithPrincipalKey(opts: {
  documentPath: string;
  keyPath: string;
  keyId: string;
  outPath: string;
  recorderKeys: Set<string>;
}): Promise<{ outPath: string; keyId: string; publicKeyBase64: string }> {
  if (!opts.keyId) {
    throw new LocalSigningError("INVALID_SIGNING_KEY", "--key-id is required");
  }
  let privateKey: ReturnType<typeof createPrivateKey>;
  try {
    privateKey = createPrivateKey(readFileSync(opts.keyPath, "utf8"));
  } catch (err) {
    throw new LocalSigningError(
      "INVALID_SIGNING_KEY",
      `cannot read ${opts.keyPath} as a PKCS#8 PEM private key: ${(err as Error).message}`,
    );
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new LocalSigningError(
      "INVALID_SIGNING_KEY",
      `${opts.keyPath} is a ${privateKey.asymmetricKeyType} key; Ed25519 is required`,
    );
  }
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeyBase64 = Buffer.from(spki).subarray(-32).toString("base64");
  if (opts.recorderKeys.has(keyFingerprint(publicKeyBase64) ?? "")) {
    throw new LocalSigningError(
      "SIGNING_KEY_IS_RECORDER_KEY",
      "refusing to sign: this key is a recorder key (local ledger or pinned recorder). " +
        "A principal's authorisation must be signed with a key the principal holds.",
    );
  }
  const unsigned = stripDocumentSignature(readJson(opts.documentPath));
  const digest = Buffer.from(await evidenceDocumentHash(unsigned), "hex");
  const signature = sign(null, digest, privateKey).toString("base64");
  const signed = {
    ...unsigned,
    document_signature: {
      alg: "Ed25519",
      key_id: opts.keyId,
      public_key_base64: publicKeyBase64,
      signature_base64: signature,
    },
  };
  mkdirSync(dirname(resolve(opts.outPath)), { recursive: true });
  writeFileSync(opts.outPath, JSON.stringify(signed, null, 2) + "\n");
  return { outPath: opts.outPath, keyId: opts.keyId, publicKeyBase64 };
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
