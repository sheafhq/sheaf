// The ONLY place @sheafhq/authority touches cryptographic primitives.
//
// They are the S1-hardened implementations from @sheafhq/verify (canonical
// base64, strict Ed25519 with small-order / non-canonical / S >= L rejection,
// RFC 8785 JCS). They are imported, never copied: one implementation of the
// security-critical code.
//
// While @sheafhq/authority is unpublished this is a relative import of the
// sibling package's build output. When it is published (SAP P9, where
// @sheafhq/verify starts depending on authority), the primitives move here
// and verify re-exports them, so there is no dependency cycle.

export { canonicalize, sha256Hex } from "../../verify/dist/canonical.js";
export {
  decodeCanonicalBase64,
  strictEd25519Reason,
  verifyEd25519,
} from "../../verify/dist/signature.js";
