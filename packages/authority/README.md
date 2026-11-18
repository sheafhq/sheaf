# @sheafhq/authority (unpublished)

The Sheaf Authority Protocol engine (`docs/SAP-ARCHITECTURE.md`). Pure: no
I/O, no clock, no randomness; time is always an input. It runs in-process in
the buyer firewall, the supplier middleware and the verifier (owner decision
2026-11-18). The hosted recorder never runs it.

**Status: Phase 2 (identity) only.** Grants (P3), transactions and `decide()`
(P5), revocation and key events (P6) are not implemented.

## Identity (Phase 2)

- **`sheaf.identity/1`** inception (`schemas/sheaf.identity-1.schema.json`).
  `sid = "sid:" + hex(sha256(JCS(doc − signatures)))`: self-certifying, and it
  commits to the keys, the next-key digest and the recovery set. Signatures
  are Ed25519 over the 32 raw bytes of that hash, strict profile (S1).
- **Roots** (`controller: null`) must carry `next_key_digest` (a new key) and a
  `recovery` set, and be signed by every signing key **and** at least
  `threshold` recovery keys.
- **Non-roots** (agents, services, people under an org) are signed by their
  controller's signing key and by their own keys.
- **Pins** (`sheaf.identity-pins/1`) are the relying party's own list of root
  sids. Trust is decided only at the root; pinning a non-root has no effect.
- **`resolveKey({sid, key_id, at, identities, pins, key_events?, recorder_keys?})`**
  walks controller → … → root (max depth 8), verifies every inception
  root-first, and returns the key **only** from a verified inception.
  `verifyIdentitySignature` adds a signature check; there is no way to pass a
  public key in.

### Fail-closed codes

| Code | When |
|---|---|
| `UNKNOWN_IDENTITY` | No supplied document hashes to the sid, or a controller was not supplied |
| `UNTRUSTED_ROOT` | The chain ends at a root that is not pinned; chain too deep or cyclic |
| `KEY_NOT_VALID` | Unknown key id; a recovery key used for signing; `at` before the identity existed; child created before its controller; controller key that is not a signing key |
| `INVALID_SIGNATURE` | Any inception signature fails; missing proof of possession; fewer than `threshold` recovery signatures; non-root not signed by its controller; the checked signature fails |
| `INVALID_IDENTITY_DOCUMENT` | Schema or semantic violation (unknown fields, weak/non-canonical/duplicate/recorder keys, pre-rotation to an existing key) |
| `INVALID_PIN_FILE` | The pin file is malformed |
| `UNVERIFIED_KEY_STATE` | **Any** key event for an identity on the path, or an unattributable one. Key events are evaluated from Phase 6 |

Every success carries `key_state: "INCEPTION_ONLY"`,
`revocation: "UNVERIFIED_REVOCATION_STATE"` and the assumptions it rests on.

### Rules stricter than the §5.1 text

- **Proof of possession for every signing key.** Without it, an identity
  could list someone else's public key, and that party's signatures would be
  attributed to it.
- **Non-roots also self-sign**, for the same reason.
- `next_key_digest` must not commit to a key already in the document.
- A pinned recorder key can never be an identity key (S1).

### Not yet

- Key events (rotate / recover / revoke_identity): refused, `UNVERIFIED_KEY_STATE`.
- Witnessed checkpoints / freshness of the identity log (P4/P6).
- `created_at` is self-asserted; bounded time comes with P4.
- Cross-runtime (browser/Workers) vectors: the primitives are the same code
  as the browser verifier, but the identity vectors are only run in Node so far.

Tests: `test/identity.test.mjs` (`npm run test:identity`).
