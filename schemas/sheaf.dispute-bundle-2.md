# `sheaf.dispute-bundle/2`

**Status: defined, not yet verifiable.** Decided 2026-11-18. Verifiers
recognise this schema id and refuse it (`SCHEMA_UNSUPPORTED`) until they can
verify the `authority` section (SAP phases 3–9, `docs/SAP-ARCHITECTURE.md`
§12). A verifier must never verify only the v1 part of a v2 bundle.

## Why a new version

A v1 verifier that ignored an unknown `authority` section would report
`VALID` for a bundle whose authority checks fail. Measured on 2026-11-17
against `@sheafhq/verify` 0.1.4: a v1 bundle with an extra `authority` section
holding a BLOCK decision verified as `VALID … evidence_gaps: none`.

Two rules close this:

1. **v1 is closed.** A `sheaf.dispute-bundle/1` bundle may carry only these
   top-level keys, and anything else fails check 1 with `SCHEMA_UNSUPPORTED`:
   `schema`, `created_at`, `producer`, `case`, `subject`, `recorder`,
   `disclosures`, `evidence`, `anchor`, `payloads`, `policy`, `attachments`,
   `presentation`, `bundle_id`, `verification`.
2. **v2 is opt-in.** Old verifiers reject the v2 schema id outright.

## Structure

v2 = every v1 key with v1 semantics, **plus** one top-level key:

```jsonc
{
  "schema": "sheaf.dispute-bundle/2",
  // ... all v1 keys ...
  "authority": {
    "trust_roots":      [ /* pinned root inception refs (sid) used, + witness policy */ ],
    "identities":       [ /* sheaf.identity/1 documents on the path */ ],
    "key_events":       [ /* sheaf.key-event/1 (Phase 6+) */ ],
    "grants":           [ /* sheaf.grant/1: mandate + delegations (Phase 3) */ ],
    "revocation":       [ /* tree-chain ranges + witnessed checkpoints (Phase 6) */ ],
    "transactions":     [ /* sheaf.transaction/1 + sheaf.authorisation-request/1 */ ],
    "decisions":        [ /* sheaf.authority-decision/1 */ ],
    "approvals":        [ /* sheaf.approval/1, bound to transaction_hash */ ],
    "acceptances":      [ /* sheaf.supplier-acceptance/1 */ ],
    "receipts":         [ /* sheaf.execution-receipt/1 */ ],
    "receive_receipts": [ /* recorder receive receipts */ ]
  }
}
```

- `bundle_id` keeps the v1 algorithm: `sha256(JCS(bundle − bundle_id −
  verification))`, so it covers the `authority` section.
- The member list of `authority` is closed; unknown members fail closed.
- Every authority document that `decide()` consumes is disclosed in full
  (§11): no field-level hiding.
- Until Phase 6, revocation state is reported as `UNVERIFIED_REVOCATION_STATE`,
  so a v2 report can never be fully `VERIFIED`.

The exact member schemas are fixed as each phase lands. This file is the
reservation and the compatibility contract.
