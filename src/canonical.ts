// RFC 8785 — JSON Canonicalization Scheme (JCS).
// Deterministic serialization so hashes and signatures work cross-platform.
//
// Rules:
//  - Objects are serialized with keys sorted lexicographically (code-point order)
//  - Numbers use the shortest round-trip representation (we accept JSON.stringify
//    output here; sufficient for integers and safe doubles — the envelope schema
//    only uses strings/integers/null, so number pitfalls don't bite)
//  - Strings are JSON strings with no unnecessary escapes
//  - No whitespace between tokens

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error(`JCS: unsupported value type: ${typeof value}`);
}

export async function sha256Hex(bytes: Uint8Array | string): Promise<string> {
  const buf =
    typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  const hash = await crypto.subtle.digest(
    "SHA-256",
    buf.buffer as ArrayBuffer,
  );
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function hashCanonical(value: unknown): Promise<string> {
  return sha256Hex(canonicalize(value));
}
