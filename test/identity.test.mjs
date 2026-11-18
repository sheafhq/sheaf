// SAP Phase 2: identity (sheaf.identity/1, pins, inception-only resolveKey).
// docs/SAP-ARCHITECTURE.md §5.1, §8.5, §17.2 (P2 exit criteria, scoped to
// inceptions: key-event rows are covered by "fails closed").
//
// Keys are derived from fixed seeds, so every vector is deterministic and no
// private key is committed.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";

import {
  identityDocHash,
  identitySid,
  keyDigest,
  resolveKey,
  validateIdentityDocument,
  validateIdentityPins,
  verifyIdentitySignature,
} from "../packages/authority/dist/index.js";

// ---------------------------------------------------------------- helpers ---

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
function keyFromSeed(n) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.alloc(32, n)]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(12).toString("base64");
  return { priv, pub };
}
const K = Object.fromEntries(
  [["s1", 1], ["next", 2], ["r1", 3], ["r2", 4], ["r3", 5], ["a1", 10], ["a2", 11], ["x1", 20], ["o1", 30], ["or1", 31], ["on", 32]]
    .map(([name, seed]) => [name, keyFromSeed(seed)]),
);
const key = (key_id, k = K[key_id]) => ({ key_id, alg: "Ed25519", public_key: k.pub });
const NONCE = Buffer.alloc(16, 7).toString("base64");
const T0 = "2026-11-18T09:00:00Z";

/** Attach signers + signatures. entries: [{ key_id, identity?, priv }] */
async function signDoc(body, entries) {
  const doc = {
    ...body,
    signers: entries.map(({ key_id, identity }) => (identity ? { key_id, identity } : { key_id })),
    signatures: [],
  };
  const digest = await identityDocHash(doc);
  doc.signatures = entries.map((e) => sign(null, Buffer.from(digest, "hex"), e.priv).toString("base64"));
  return { doc, sid: `sid:${digest}` };
}

async function makeRoot(over = {}, entries, omit = []) {
  const body = {
    schema: "sheaf.identity/1",
    type: "organisation",
    handle: "org:acme",
    display_name: "ACME Ltd purchasing org",
    controller: null,
    keys: [key("s1")],
    next_key_digest: await keyDigest(K.next.pub),
    recovery: { threshold: 2, keys: [key("r1"), key("r2"), key("r3")] },
    created_at: T0,
    nonce: NONCE,
    ...over,
  };
  for (const k of omit) delete body[k];
  return signDoc(body, entries ?? [
    { key_id: "s1", priv: K.s1.priv },
    { key_id: "r1", priv: K.r1.priv },
    { key_id: "r2", priv: K.r2.priv },
  ]);
}

async function makeAgent(root, over = {}, entries) {
  const body = {
    schema: "sheaf.identity/1",
    type: "agent",
    handle: "agent:purchasing-eu1",
    display_name: "Purchasing agent EU1",
    controller: root.sid,
    keys: [key("a1")],
    created_at: "2026-11-18T09:05:00Z",
    nonce: NONCE,
    ...over,
  };
  return signDoc(body, entries ?? [
    { key_id: "a1", priv: K.a1.priv },
    { key_id: "s1", identity: root.sid, priv: K.s1.priv },
  ]);
}

const pins = (...sids) => ({ schema: "sheaf.identity-pins/1", pins: sids.map((sid) => ({ sid, label: "test" })) });
const AT = "2026-11-18T10:00:00Z";

async function expectFail(input, code, reasonRe) {
  const r = await resolveKey(input);
  assert.equal(r.ok, false, `expected ${code}, got ok`);
  assert.equal(r.code, code, r.reason);
  if (reasonRe) assert.match(r.reason, reasonRe);
  return r;
}

// Golden vector: changing any byte of the canonical form changes this sid.
// Cross-checked 2026-11-18 with an independent implementation (Python
// json.dumps(sort_keys, compact) + hashlib.sha256 over the same body).
const GOLDEN_ROOT_SID = "sid:37b8b9528f7bcad335d9e2e6d772ab49aa1c3dda669be9776608e22db4ad3737";

// ------------------------------------------------------------------ tests ---

test("P2 golden: a valid root inception resolves; revocation is UNVERIFIED_REVOCATION_STATE", async () => {
  const root = await makeRoot();
  assert.equal(root.sid, await identitySid(root.doc));
  assert.deepEqual(validateIdentityDocument(root.doc), []);
  assert.equal(root.sid, GOLDEN_ROOT_SID);
  const r = await resolveKey({ sid: root.sid, key_id: "s1", at: AT, identities: [root.doc], pins: pins(root.sid) });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.public_key, K.s1.pub);
  assert.deepEqual(r.path, [root.sid]);
  assert.equal(r.root_sid, root.sid);
  assert.equal(r.key_state, "INCEPTION_ONLY");
  assert.equal(r.revocation, "UNVERIFIED_REVOCATION_STATE");
  assert.ok(r.assumptions.some((a) => /Phase 6/.test(a)));
});

test("P2: root inception without a recovery set or next-key digest is rejected", async () => {
  const noRec = await makeRoot({}, [{ key_id: "s1", priv: K.s1.priv }], ["recovery"]);
  await expectFail({ sid: noRec.sid, key_id: "s1", at: AT, identities: [noRec.doc], pins: pins(noRec.sid) },
    "INVALID_IDENTITY_DOCUMENT", /recovery: required for a root/);

  const noNext = await makeRoot({}, undefined, ["next_key_digest"]);
  await expectFail({ sid: noNext.sid, key_id: "s1", at: AT, identities: [noNext.doc], pins: pins(noNext.sid) },
    "INVALID_IDENTITY_DOCUMENT", /next_key_digest: required for a root/);
});

test("P2: root inception needs >= threshold recovery signatures (k-1 rejected)", async () => {
  const root = await makeRoot({}, [{ key_id: "s1", priv: K.s1.priv }, { key_id: "r1", priv: K.r1.priv }]);
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [root.doc], pins: pins(root.sid) },
    "INVALID_SIGNATURE", /1 valid recovery signature\(s\); 2 required/);
  const ok = await makeRoot({}, [
    { key_id: "s1", priv: K.s1.priv }, { key_id: "r1", priv: K.r1.priv }, { key_id: "r2", priv: K.r2.priv }, { key_id: "r3", priv: K.r3.priv },
  ]);
  assert.equal((await resolveKey({ sid: ok.sid, key_id: "s1", at: AT, identities: [ok.doc], pins: pins(ok.sid) })).ok, true);
});

test("P2: every signing key must prove possession; recovery signatures alone are not enough", async () => {
  const root = await makeRoot({}, [{ key_id: "r1", priv: K.r1.priv }, { key_id: "r2", priv: K.r2.priv }]);
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [root.doc], pins: pins(root.sid) },
    "INVALID_SIGNATURE", /signing key s1 did not sign the inception/);
  // Listing someone else's public key as a second signing key, without its signature.
  const stolen = await makeRoot({ keys: [key("s1"), key("victim", K.x1)] });
  await expectFail({ sid: stolen.sid, key_id: "victim", at: AT, identities: [stolen.doc], pins: pins(stolen.sid) },
    "INVALID_SIGNATURE", /signing key victim did not sign the inception/);
});

test("P2: one corrupted or malleated signature fails the whole inception", async () => {
  const root = await makeRoot();
  const bad = structuredClone(root.doc);
  const sig = Buffer.from(bad.signatures[1], "base64");
  sig[5] ^= 1;
  bad.signatures[1] = sig.toString("base64");
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [bad], pins: pins(root.sid) }, "INVALID_SIGNATURE");

  // S + L (malleability): rejected by the strict profile.
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const mal = structuredClone(root.doc);
  const s = Buffer.from(mal.signatures[0], "base64");
  let n = 0n;
  for (let i = 63; i >= 32; i--) n = (n << 8n) | BigInt(s[i]);
  n += L;
  for (let i = 32; i < 64; i++) { s[i] = Number(n & 0xffn); n >>= 8n; }
  mal.signatures[0] = s.toString("base64");
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [mal], pins: pins(root.sid) }, "INVALID_SIGNATURE");
});

test("P2: a document is only found under the hash of its own content (tamper => UNKNOWN_IDENTITY)", async () => {
  const root = await makeRoot();
  const tampered = { ...root.doc, display_name: "Evil Corp" };
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [tampered], pins: pins(root.sid) },
    "UNKNOWN_IDENTITY", /no supplied identity document hashes to/);
  await expectFail({ sid: "agent:purchasing", key_id: "s1", at: AT, identities: [root.doc], pins: pins(root.sid) },
    "UNKNOWN_IDENTITY");
});

test("P2: an unpinned root is UNTRUSTED_ROOT; pinning a non-root does not help", async () => {
  const root = await makeRoot();
  const other = await makeRoot({ handle: "org:other", keys: [key("o1")], recovery: { threshold: 1, keys: [key("or1")] }, next_key_digest: await keyDigest(K.on.pub) },
    [{ key_id: "o1", priv: K.o1.priv }, { key_id: "or1", priv: K.or1.priv }]);
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [root.doc, other.doc], pins: pins(other.sid) },
    "UNTRUSTED_ROOT", /not in the relying party's pins/);

  const agent = await makeAgent(root);
  await expectFail({ sid: agent.sid, key_id: "a1", at: AT, identities: [root.doc, agent.doc], pins: pins(agent.sid) },
    "UNTRUSTED_ROOT", /resolves to root .* which is not in the relying party's pins/);
});

test("P2: a non-root resolves through its controller to a pinned root", async () => {
  const root = await makeRoot();
  const agent = await makeAgent(root);
  assert.deepEqual(validateIdentityDocument(agent.doc), []);
  const r = await resolveKey({ sid: agent.sid, key_id: "a1", at: AT, identities: [agent.doc, root.doc], pins: pins(root.sid) });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.path, [agent.sid, root.sid]);
  assert.equal(r.public_key, K.a1.pub);
});

test("P2: non-root signed by a non-controller, or missing its controller's signature, is rejected", async () => {
  const root = await makeRoot();
  // Same key_id "s1", wrong private key.
  const forged = await makeAgent(root, {}, [{ key_id: "a1", priv: K.a1.priv }, { key_id: "s1", identity: root.sid, priv: K.x1.priv }]);
  await expectFail({ sid: forged.sid, key_id: "a1", at: AT, identities: [root.doc, forged.doc], pins: pins(root.sid) },
    "INVALID_SIGNATURE", /signature by sid:[0-9a-f]+#s1 does not verify/);
  const unsigned = await makeAgent(root, {}, [{ key_id: "a1", priv: K.a1.priv }]);
  await expectFail({ sid: unsigned.sid, key_id: "a1", at: AT, identities: [root.doc, unsigned.doc], pins: pins(root.sid) },
    "INVALID_SIGNATURE", /not signed by its controller/);
  const viaRecovery = await makeAgent(root, {}, [{ key_id: "a1", priv: K.a1.priv }, { key_id: "r1", identity: root.sid, priv: K.r1.priv }]);
  await expectFail({ sid: viaRecovery.sid, key_id: "a1", at: AT, identities: [root.doc, viaRecovery.doc], pins: pins(root.sid) },
    "KEY_NOT_VALID", /controller key r1 is not a signing key/);
  const noPop = await makeAgent(root, {}, [{ key_id: "s1", identity: root.sid, priv: K.s1.priv }]);
  await expectFail({ sid: noPop.sid, key_id: "a1", at: AT, identities: [root.doc, noPop.doc], pins: pins(root.sid) },
    "INVALID_SIGNATURE", /signing key a1 did not sign/);
});

test("P2: a missing controller document is UNKNOWN_IDENTITY", async () => {
  const root = await makeRoot();
  const agent = await makeAgent(root);
  await expectFail({ sid: agent.sid, key_id: "a1", at: AT, identities: [agent.doc], pins: pins(root.sid) },
    "UNKNOWN_IDENTITY", /controller .* was not supplied/);
});

test("P2: KEY_NOT_VALID for recovery keys, unknown key ids, and times before the key existed", async () => {
  const root = await makeRoot();
  const agent = await makeAgent(root);
  const base = { identities: [root.doc, agent.doc], pins: pins(root.sid) };
  await expectFail({ ...base, sid: root.sid, key_id: "r1", at: AT }, "KEY_NOT_VALID", /recovery key/);
  await expectFail({ ...base, sid: root.sid, key_id: "nope", at: AT }, "KEY_NOT_VALID", /not a signing key/);
  await expectFail({ ...base, sid: agent.sid, key_id: "a1", at: "2026-11-18T09:04:59Z" }, "KEY_NOT_VALID", /did not exist yet/);
  await expectFail({ ...base, sid: agent.sid, key_id: "a1", at: "yesterday" }, "KEY_NOT_VALID");
  const early = await makeAgent(root, { created_at: "2026-11-18T08:00:00Z" });
  await expectFail({ ...base, identities: [root.doc, early.doc], sid: early.sid, key_id: "a1", at: AT },
    "KEY_NOT_VALID", /created before its controller/);
});

test("P2: any key event on the path fails closed (UNVERIFIED_KEY_STATE)", async () => {
  const root = await makeRoot();
  const agent = await makeAgent(root);
  const base = { sid: agent.sid, key_id: "a1", at: AT, identities: [root.doc, agent.doc], pins: pins(root.sid) };
  const rotate = { schema: "sheaf.key-event/1", identity: root.sid, sn: 1, event: "rotate" };
  await expectFail({ ...base, key_events: [rotate] }, "UNVERIFIED_KEY_STATE", /not supported before SAP Phase 6/);
  await expectFail({ ...base, key_events: [{ ...rotate, identity: agent.sid, event: "revoke_identity" }] }, "UNVERIFIED_KEY_STATE");
  await expectFail({ ...base, key_events: [{ event: "recover" }] }, "UNVERIFIED_KEY_STATE", /without a valid identity/);
  // An event about an unrelated identity cannot change this path.
  const unrelated = { ...rotate, identity: `sid:${"0".repeat(64)}` };
  assert.equal((await resolveKey({ ...base, key_events: [unrelated] })).ok, true);
});

test("P2: weak, non-canonical, duplicated and recorder keys are rejected at inception", async () => {
  const IDENTITY_POINT = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]).toString("base64");
  const cases = [
    ["small-order (identity) key", { keys: [{ key_id: "s1", alg: "Ed25519", public_key: IDENTITY_POINT }] }, /strict Ed25519 \(PUBLIC_KEY_SMALL_ORDER\)/],
    ["non-canonical base64 (padding dropped)", { keys: [{ key_id: "s1", alg: "Ed25519", public_key: K.s1.pub.replace(/=$/, "") }] }, /canonical base64/],
    ["same key as signing and recovery", { recovery: { threshold: 1, keys: [key("r1", K.s1)] } }, /same public key appears twice/],
    ["duplicate key_id", { recovery: { threshold: 1, keys: [key("s1", K.r1)] } }, /duplicate key_id s1/],
    ["unknown field", { website: "https://acme.example" }, /unknown field\(s\) website/],
    ["threshold above key count", { recovery: { threshold: 4, keys: [key("r1"), key("r2"), key("r3")] } }, /threshold/],
    ["local time without Z", { created_at: "2026-11-18T09:00:00+01:00" }, /created_at/],
    ["short nonce", { nonce: Buffer.alloc(8).toString("base64") }, /nonce/],
  ];
  for (const [name, over, re] of cases) {
    const errs = validateIdentityDocument({ ...(await makeRoot()).doc, ...over });
    assert.ok(errs.some((e) => re.test(e)), `${name}: ${errs.join(" | ")}`);
  }
  // A pinned recorder key can never be an identity key (S1).
  const withRecorder = await makeRoot();
  await expectFail({ sid: withRecorder.sid, key_id: "s1", at: AT, identities: [withRecorder.doc], pins: pins(withRecorder.sid), recorder_keys: [K.s1.pub] },
    "INVALID_IDENTITY_DOCUMENT", /pinned recorder key/);
  // Pre-rotation must commit to a new key.
  const reuse = await makeRoot({ next_key_digest: await keyDigest(K.s1.pub) });
  await expectFail({ sid: reuse.sid, key_id: "s1", at: AT, identities: [reuse.doc], pins: pins(reuse.sid) },
    "INVALID_IDENTITY_DOCUMENT", /next_key_digest commits to existing key s1/);
});

test("P2: signatures verify only under the logged key (no inline keys, no substitution)", async () => {
  const root = await makeRoot();
  const agent = await makeAgent(root);
  const ctx = { sid: agent.sid, key_id: "a1", at: AT, identities: [root.doc, agent.doc], pins: pins(root.sid) };
  const digest = Buffer.alloc(32, 0xab).toString("hex");
  const good = sign(null, Buffer.from(digest, "hex"), K.a1.priv).toString("base64");
  const ok = await verifyIdentitySignature({ ...ctx, digest_hex: digest, signature: good });
  assert.equal(ok.ok, true, ok.reason);
  // An attacker signs with their own key under the agent's key_id: rejected.
  const evil = sign(null, Buffer.from(digest, "hex"), K.x1.priv).toString("base64");
  const r = await verifyIdentitySignature({ ...ctx, digest_hex: digest, signature: evil });
  assert.equal(r.code, "INVALID_SIGNATURE");
  // An inline public key in the input is ignored.
  const r2 = await verifyIdentitySignature({ ...ctx, public_key: K.x1.pub, digest_hex: digest, signature: evil });
  assert.equal(r2.code, "INVALID_SIGNATURE");
  // The keyless "universal" signature (R = identity, S = 0) never verifies.
  const keyless = Buffer.concat([Buffer.from([1]), Buffer.alloc(63)]).toString("base64");
  assert.equal((await verifyIdentitySignature({ ...ctx, digest_hex: digest, signature: keyless })).code, "INVALID_SIGNATURE");
});

test("P2: JSON Schemas and the validator agree on the field sets (no drift)", async () => {
  const schema = JSON.parse(readFileSync("schemas/sheaf.identity-1.schema.json", "utf8"));
  const root = (await makeRoot()).doc;
  assert.deepEqual(Object.keys(schema.properties).sort(), Object.keys(root).sort());
  for (const f of Object.keys(schema.properties)) {
    const errs = validateIdentityDocument({ ...root, [`${f}_x`]: 1 });
    assert.ok(errs.some((e) => e.includes(`unknown field(s) ${f}_x`)), f);
  }
  assert.deepEqual(schema.required.sort(), ["controller", "created_at", "display_name", "handle", "keys", "nonce", "schema", "signatures", "signers", "type"]);
  const pinSchema = JSON.parse(readFileSync("schemas/sheaf.identity-pins-1.schema.json", "utf8"));
  assert.deepEqual(Object.keys(pinSchema.properties.pins.items.properties).sort(), ["label", "sid"]);
});

test("P2: pin files are validated strictly", async () => {
  const sid = `sid:${"a".repeat(64)}`;
  assert.deepEqual(validateIdentityPins(pins(sid)), []);
  assert.ok(validateIdentityPins({ schema: "sheaf.trusted-signers/1", pins: [{ sid }] }).length > 0);
  assert.ok(validateIdentityPins({ schema: "sheaf.identity-pins/1", pins: [{ sid }, { sid }] }).some((e) => /duplicate/.test(e)));
  assert.ok(validateIdentityPins({ schema: "sheaf.identity-pins/1", pins: [{ sid: "org:acme" }] }).some((e) => /sid:<64 hex>/.test(e)));
  assert.ok(validateIdentityPins({ schema: "sheaf.identity-pins/1", pins: [{ sid, public_key: "x" }] }).some((e) => /unknown field/.test(e)));
  const root = await makeRoot();
  await expectFail({ sid: root.sid, key_id: "s1", at: AT, identities: [root.doc], pins: { pins: [] } }, "INVALID_PIN_FILE");
});

test("P2: controller chains are bounded", async () => {
  // Build a chain deeper than MAX_CONTROLLER_DEPTH (8).
  let parent = await makeRoot();
  const docs = [parent.doc];
  const rootSid = parent.sid;
  for (let i = 0; i < 9; i++) {
    const child = await signDoc({
      schema: "sheaf.identity/1", type: "service", handle: `svc:${i}`, display_name: `Service ${i}`,
      controller: parent.sid, keys: [key("a1")], created_at: T0, nonce: NONCE,
    }, [{ key_id: "a1", priv: K.a1.priv }, { key_id: i === 0 ? "s1" : "a1", identity: parent.sid, priv: i === 0 ? K.s1.priv : K.a1.priv }]);
    docs.push(child.doc);
    parent = child;
  }
  await expectFail({ sid: parent.sid, key_id: "a1", at: AT, identities: docs, pins: pins(rootSid) },
    "UNTRUSTED_ROOT", /chain longer than 8/);
});

test("P2: deterministic and pure (shuffled inputs, reordered keys, no clock, no network)", async () => {
  const root = await makeRoot();
  const agent = await makeAgent(root);
  const reorder = (o) =>
    Array.isArray(o) ? o.map(reorder)
      : o && typeof o === "object" ? Object.fromEntries(Object.keys(o).reverse().map((k) => [k, reorder(o[k])]))
      : o;
  assert.notDeepEqual(Object.keys(reorder(root.doc)), Object.keys(root.doc));
  const realFetch = globalThis.fetch;
  const RealDate = globalThis.Date;
  globalThis.fetch = () => { throw new Error("network used"); };
  globalThis.Date = class extends RealDate {
    constructor(...a) { if (a.length === 0) throw new Error("clock used"); super(...a); }
    static now() { throw new Error("clock used"); }
  };
  try {
    const outputs = new Set();
    for (let i = 0; i < 50; i++) {
      const ids = i % 2 ? [agent.doc, root.doc, root.doc] : [reorder(root.doc), reorder(agent.doc)];
      outputs.add(JSON.stringify(await resolveKey({ sid: agent.sid, key_id: "a1", at: AT, identities: ids, pins: pins(root.sid) })));
    }
    assert.equal(outputs.size, 1);
    assert.equal(JSON.parse([...outputs][0]).ok, true);
  } finally {
    globalThis.fetch = realFetch;
    globalThis.Date = RealDate;
  }
  // Static: the engine imports only its own modules and verify's primitives.
  for (const f of readdirSync("packages/authority/src")) {
    const src = readFileSync(`packages/authority/src/${f}`, "utf8");
    for (const m of src.matchAll(/from\s+"([^"]+)"/g)) {
      assert.ok(m[1].startsWith("./") || m[1].startsWith("../../verify/dist/"), `${f} imports ${m[1]}`);
    }
    assert.doesNotMatch(src, /\bfetch\(|Date\.now\(|new Date\(\)|Math\.random\(|node:/, f);
  }
});
