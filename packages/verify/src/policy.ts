// sheaf.policy/1 evaluator.
//
// Pure and deterministic: no network, no clock, no randomness. The recorder
// package carries an equivalent copy for runtime enforcement; keep the two in
// sync. The verifier uses this copy to prove that recorded events were within
// the attached policy.

export const POLICY_SCHEMA = "sheaf.policy/1";

export type PolicyVerdict = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";

export type PolicyOp =
  | "eq"
  | "neq"
  | "lt"
  | "lte"
  | "gt"
  | "gte"
  | "in"
  | "not_in"
  | "contains"
  | "required"
  | "domain_in";

export type PolicyConstraint = {
  path: string;
  op: PolicyOp;
  value?: unknown;
  reason: string;
};

export type PolicyRule = {
  tool: string;
  verdict: PolicyVerdict;
  on_violation?: "BLOCK" | "REQUIRE_APPROVAL";
  constraints: PolicyConstraint[];
};

export type PolicyDocument = {
  schema: typeof POLICY_SCHEMA;
  policy_id: string;
  issued_at: string;
  expires_at: string | null;
  default_verdict: PolicyVerdict;
  allowed_tools: string[];
  denied_tools: string[];
  rules: PolicyRule[];
};

export type PolicyDecision = {
  verdict: PolicyVerdict;
  code:
    | "POLICY_ALLOW"
    | "POLICY_VIOLATION"
    | "POLICY_APPROVAL_REQUIRED";
  reason_code: string;
  matched_rule?: string;
};

const VERDICTS: PolicyVerdict[] = ["ALLOW", "BLOCK", "REQUIRE_APPROVAL"];
const OPS: PolicyOp[] = [
  "eq",
  "neq",
  "lt",
  "lte",
  "gt",
  "gte",
  "in",
  "not_in",
  "contains",
  "required",
  "domain_in",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isIsoDate(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    return false;
  }
  return Number.isFinite(Date.parse(value));
}

function onlyKeys(
  value: Record<string, unknown>,
  allowed: string[],
  path: string,
  errors: string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) errors.push(`${path}.${key}: unexpected field`);
  }
}

function requireString(
  value: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
): boolean {
  if (typeof value[key] !== "string" || (value[key] as string).length === 0) {
    errors.push(`${path}.${key}: non-empty string required`);
    return false;
  }
  return true;
}

/** Strict validation of a policy document. Returns all errors. */
export function validatePolicy(policy: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(policy)) return ["policy: object required"];
  onlyKeys(
    policy,
    [
      "schema",
      "policy_id",
      "issued_at",
      "expires_at",
      "default_verdict",
      "allowed_tools",
      "denied_tools",
      "rules",
    ],
    "policy",
    errors,
  );
  if (policy.schema !== POLICY_SCHEMA) {
    errors.push(`policy.schema: "${POLICY_SCHEMA}" required`);
  }
  requireString(policy, "policy_id", "policy", errors);
  if (!isIsoDate(policy.issued_at)) {
    errors.push("policy.issued_at: ISO 8601 UTC timestamp required");
  }
  if (policy.expires_at !== null && !isIsoDate(policy.expires_at)) {
    errors.push("policy.expires_at: ISO 8601 UTC timestamp or null required");
  }
  if (!VERDICTS.includes(policy.default_verdict as PolicyVerdict)) {
    errors.push("policy.default_verdict: ALLOW | BLOCK | REQUIRE_APPROVAL required");
  }

  for (const key of ["allowed_tools", "denied_tools"] as const) {
    if (!Array.isArray(policy[key])) {
      errors.push(`policy.${key}: array required`);
      continue;
    }
    const seen = new Set<string>();
    policy[key].forEach((value, idx) => {
      if (typeof value !== "string" || value.length === 0) {
        errors.push(`policy.${key}[${idx}]: non-empty string required`);
      } else if (seen.has(value)) {
        errors.push(`policy.${key}[${idx}]: duplicate`);
      } else {
        seen.add(value);
      }
    });
  }

  if (!Array.isArray(policy.rules)) {
    errors.push("policy.rules: array required");
  } else {
    policy.rules.forEach((rule, ruleIdx) => {
      const path = `policy.rules[${ruleIdx}]`;
      if (!isRecord(rule)) {
        errors.push(`${path}: object required`);
        return;
      }
      onlyKeys(
        rule,
        ["tool", "verdict", "on_violation", "constraints"],
        path,
        errors,
      );
      requireString(rule, "tool", path, errors);
      if (!VERDICTS.includes(rule.verdict as PolicyVerdict)) {
        errors.push(`${path}.verdict: ALLOW | BLOCK | REQUIRE_APPROVAL required`);
      }
      if (
        rule.on_violation !== undefined &&
        rule.on_violation !== "BLOCK" &&
        rule.on_violation !== "REQUIRE_APPROVAL"
      ) {
        errors.push(`${path}.on_violation: BLOCK | REQUIRE_APPROVAL required`);
      }
      if (!Array.isArray(rule.constraints)) {
        errors.push(`${path}.constraints: array required`);
        return;
      }
      rule.constraints.forEach((constraint, cIdx) => {
        const cPath = `${path}.constraints[${cIdx}]`;
        if (!isRecord(constraint)) {
          errors.push(`${cPath}: object required`);
          return;
        }
        onlyKeys(constraint, ["path", "op", "value", "reason"], cPath, errors);
        requireString(constraint, "path", cPath, errors);
        if (!OPS.includes(constraint.op as PolicyOp)) {
          errors.push(`${cPath}.op: unsupported operator`);
        }
        requireString(constraint, "reason", cPath, errors);
        if (constraint.op !== "required" && !("value" in constraint)) {
          errors.push(`${cPath}.value: required for ${String(constraint.op)}`);
        }
      });
    });
  }

  return errors;
}

function matchesTool(pattern: string, tool: string): boolean {
  const escaped = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`).test(tool);
}

function readPath(value: unknown, path: string): unknown {
  const clean = path.replace(/^\$\.?/, "");
  if (!clean) return value;
  let current: unknown = value;
  for (const part of clean.split(".")) {
    if (current === null || current === undefined) return undefined;
    if (Array.isArray(current)) {
      if (!/^\d+$/.test(part)) return undefined;
      current = current[Number(part)];
    } else if (typeof current === "object") {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return current;
}

function jsonEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

function hostname(value: string): string | null {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    const host = value.split("/")[0]?.split(":")[0]?.toLowerCase();
    return host || null;
  }
}

function checkConstraint(
  args: unknown,
  constraint: PolicyConstraint,
): boolean {
  const actual = readPath(args, constraint.path);
  switch (constraint.op) {
    case "required":
      return actual !== undefined && actual !== null && actual !== "";
    case "eq":
      return jsonEqual(actual, constraint.value);
    case "neq":
      return !jsonEqual(actual, constraint.value);
    case "lt":
      return typeof actual === "number" && actual < Number(constraint.value);
    case "lte":
      return typeof actual === "number" && actual <= Number(constraint.value);
    case "gt":
      return typeof actual === "number" && actual > Number(constraint.value);
    case "gte":
      return typeof actual === "number" && actual >= Number(constraint.value);
    case "in":
      return Array.isArray(constraint.value)
        ? constraint.value.some((v) => jsonEqual(v, actual))
        : false;
    case "not_in":
      return Array.isArray(constraint.value)
        ? !constraint.value.some((v) => jsonEqual(v, actual))
        : false;
    case "contains":
      return Array.isArray(actual)
        ? actual.some((v) => jsonEqual(v, constraint.value))
        : typeof actual === "string" &&
          actual.includes(String(constraint.value));
    case "domain_in": {
      if (typeof actual !== "string") return false;
      const host = hostname(actual);
      if (!host) return false;
      const domains = Array.isArray(constraint.value)
        ? constraint.value
        : [constraint.value];
      return domains.some((domain) => {
        if (typeof domain !== "string") return false;
        const d = domain.toLowerCase();
        return host === d || host.endsWith(`.${d}`);
      });
    }
    default:
      return false;
  }
}

/**
 * Evaluate one tool call. Deterministic and side-effect free.
 *
 * Precedence: denied_tools -> allowed_tools (if non-empty) -> matching rule ->
 * default_verdict. A matching rule's constraints decide ALLOW vs its
 * on_violation verdict.
 */
export function evaluatePolicy(
  tool: string,
  args: unknown,
  policy: PolicyDocument,
): PolicyDecision {
  if (policy.denied_tools.some((pattern) => matchesTool(pattern, tool))) {
    return {
      verdict: "BLOCK",
      code: "POLICY_VIOLATION",
      reason_code: "tool_denied",
    };
  }

  if (
    policy.allowed_tools.length > 0 &&
    !policy.allowed_tools.some((pattern) => matchesTool(pattern, tool))
  ) {
    return {
      verdict: "BLOCK",
      code: "POLICY_VIOLATION",
      reason_code: "tool_not_allowed",
    };
  }

  const rule = policy.rules.find((r) => matchesTool(r.tool, tool));
  if (rule) {
    for (const constraint of rule.constraints) {
      if (!checkConstraint(args, constraint)) {
        return {
          verdict: rule.on_violation ?? "BLOCK",
          code:
            (rule.on_violation ?? "BLOCK") === "BLOCK"
              ? "POLICY_VIOLATION"
              : "POLICY_APPROVAL_REQUIRED",
          reason_code: constraint.reason,
          matched_rule: rule.tool,
        };
      }
    }
    if (rule.verdict === "BLOCK") {
      return {
        verdict: "BLOCK",
        code: "POLICY_VIOLATION",
        reason_code: "rule_verdict_block",
        matched_rule: rule.tool,
      };
    }
    if (rule.verdict === "REQUIRE_APPROVAL") {
      return {
        verdict: "REQUIRE_APPROVAL",
        code: "POLICY_APPROVAL_REQUIRED",
        reason_code: "rule_requires_approval",
        matched_rule: rule.tool,
      };
    }
    return {
      verdict: "ALLOW",
      code: "POLICY_ALLOW",
      reason_code: "allowed",
      matched_rule: rule.tool,
    };
  }

  if (policy.default_verdict === "BLOCK") {
    return {
      verdict: "BLOCK",
      code: "POLICY_VIOLATION",
      reason_code: "default_block",
    };
  }
  if (policy.default_verdict === "REQUIRE_APPROVAL") {
    return {
      verdict: "REQUIRE_APPROVAL",
      code: "POLICY_APPROVAL_REQUIRED",
      reason_code: "default_requires_approval",
    };
  }
  return { verdict: "ALLOW", code: "POLICY_ALLOW", reason_code: "allowed" };
}
