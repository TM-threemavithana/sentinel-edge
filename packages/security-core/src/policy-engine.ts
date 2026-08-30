import type {
  PolicyEvaluation,
  PolicyRule,
  RequestContext,
  RuleCondition,
  ThreatSeverity,
  ThreatSignal,
} from "./types";

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function includesValue(actual: string, expected: string | string[]): boolean {
  const values = Array.isArray(expected) ? expected : [expected];
  return values.some((value) => value.toLowerCase() === actual.toLowerCase());
}

function safeRegex(pattern: string): RegExp | null {
  if (pattern.length > 256) return null;
  try {
    return new RegExp(pattern, "i");
  } catch {
    return null;
  }
}

function conditionMatches(
  condition: RuleCondition,
  context: RequestContext,
  signals: ThreatSignal[],
): boolean {
  switch (condition.field) {
    case "method":
      return condition.operator === "equals"
        ? context.method.toLowerCase() === String(condition.value).toLowerCase()
        : includesValue(context.method, condition.value);
    case "path": {
      if (condition.operator === "equals") return context.path === condition.value;
      if (condition.operator === "starts_with") return context.path.startsWith(condition.value);
      return safeRegex(condition.value)?.test(context.path) ?? false;
    }
    case "header": {
      const actual = context.headers[condition.key.toLowerCase()];
      if (condition.operator === "exists") return actual !== undefined;
      if (actual === undefined || condition.value === undefined) return false;
      return condition.operator === "equals"
        ? actual.toLowerCase() === condition.value.toLowerCase()
        : actual.toLowerCase().includes(condition.value.toLowerCase());
    }
    case "country":
      return context.country !== undefined && includesValue(context.country, condition.value);
    case "threat": {
      const categories = Array.isArray(condition.value) ? condition.value : [condition.value];
      return signals.some((signal) => categories.includes(signal.category));
    }
    case "severity":
      return signals.some((signal) => SEVERITY_RANK[signal.severity] >= SEVERITY_RANK[condition.value]);
    case "body": {
      if (condition.operator === "contains") {
        return context.bodyText.toLowerCase().includes(condition.value.toLowerCase());
      }
      return safeRegex(condition.value)?.test(context.bodyText) ?? false;
    }
  }
}

export function evaluatePolicies(
  rules: PolicyRule[],
  context: RequestContext,
  signals: ThreatSignal[],
): PolicyEvaluation {
  const orderedRules = rules
    .filter((rule) => rule.enabled)
    .sort((left, right) => left.priority - right.priority);

  for (const rule of orderedRules) {
    if (rule.conditions.length > 0 && rule.conditions.every((condition) => conditionMatches(condition, context, signals))) {
      return {
        decision: rule.action,
        matchedRuleId: rule.id,
        matchedRuleName: rule.name,
        reason: `Matched policy rule: ${rule.name}`,
        rateLimit: rule.rateLimit ?? null,
      };
    }
  }

  return {
    decision: "allow",
    matchedRuleId: null,
    matchedRuleName: null,
    reason: "No blocking policy matched",
    rateLimit: null,
  };
}
