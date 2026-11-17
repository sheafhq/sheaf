# S1 regression fixtures

`legacy-recorder-signed.sheaf` is a **genuine** dispute bundle produced by the
**pre-fix** local export code (the 2026-11-13 builds of `dist-cli/` and
`packages/*/dist/`), generated on 2026-11-17 with `generate-legacy.mjs.txt`.

That code signed the mandate, delegation and consent documents with the
**local recorder (ledger) key** and labelled the delegation root
`basis: "principal_signature"` with that same key. The pre-fix verifier
reported it as:

```
VALID (complete)
evidence_gaps: none
```

even though no principal ever signed anything. See `docs/SAP-ARCHITECTURE.md`
§13.

`legacy-recorder-signed.trust.json` pins that ledger key as a recorder key, as
`sheaf local export` writes it. The ledger's private key is **not** included.

The fixed verifier must keep reporting this bundle as valid for **integrity**,
and must downgrade its **authorisation** claim: `RECORDER_SIGNED_NOT_PRINCIPAL`,
`VALID (partial)`. That is asserted in `test/local-signing.test.mjs`.

Do not regenerate this file with current code. Current code refuses to
produce it, which is the point.
