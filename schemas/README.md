# Evidence document schemas

Versioned, strict JSON Schemas for the three control-event documents:

- `sheaf.mandate-document/1`
- `sheaf.delegation-document/1`
- `sheaf.consent-document/1`
- `sheaf.policy/1` — runtime enforcement policy; hash is `sha256(JCS(policy))`

All three use `additionalProperties: false` at every object level. They are the
only documents the authoring path accepts.

## Hashing and signatures

For a document `D`:

1. Remove `document_signature` if present. Call the result `U`.
2. Canonicalize `U` with RFC 8785 JCS.
3. `document_hash = sha256(JCS(U))`, lowercase 64-hex.
4. The event that records the document sets
   `event.inputs_hash = "sha256:" + document_hash`.
5. If `document_signature` is present, it is Ed25519 over the **32 raw bytes**
   of `document_hash`:
   - `alg`: `"Ed25519"`
   - `key_id`: signer key id
   - `public_key_base64`: raw 32-byte Ed25519 public key
   - `signature_base64`: base64 signature

The signature is optional. The recorder records the event whether or not the
document is signed; the eventual Dispute Bundle uses `authorization_basis` to
distinguish a signed authorization from a recorder-observed one.

`document_signature` is excluded from the hash so signing does not create a
circular commitment. Any other field is included.

## Schema-to-kind mapping

| Document schema | Event `kind` | Default event tool |
|---|---|---|
| `sheaf.mandate-document/1` | `mandate` | `sheaf.mandate` |
| `sheaf.delegation-document/1` | `delegation` | `sheaf.delegation` |
| `sheaf.consent-document/1` | `consent` | `sheaf.consent` |

An `arca/1` event without `event.kind` is a `tool_call` and is not expected to
carry one of these documents.
