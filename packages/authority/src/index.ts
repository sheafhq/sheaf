// @sheafhq/authority — SAP engine (pure: no I/O, no clock, no randomness).
//
// Phase 2 (2026-11-18): identity only. Grants (P3), transactions and decide()
// (P5) and revocation (P6) are not implemented; see docs/SAP-ARCHITECTURE.md.

export {
  ASSUMPTIONS,
  IDENTITY_PINS_SCHEMA,
  IDENTITY_SCHEMA,
  KEY_EVENT_SCHEMA,
  MAX_CONTROLLER_DEPTH,
  identityDocHash,
  identitySid,
  keyDigest,
  parseRfc3339Utc,
  resolveKey,
  validateIdentityDocument,
  validateIdentityPins,
  verifyIdentitySignature,
} from "./identity.js";
export type {
  IdentityDocument,
  IdentityErrorCode,
  IdentityKey,
  IdentityPins,
  IdentitySigner,
  IdentityType,
  ResolveFailure,
  ResolveInput,
  ResolvedKey,
} from "./identity.js";
