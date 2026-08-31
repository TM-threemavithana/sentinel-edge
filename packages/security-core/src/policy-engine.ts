import type {
  PolicyEvaluation,
  PolicyRule,
  RequestContext,
  RuleCondition,
  ThreatSeverity,
  ThreatSignal,
} from "./types";
import { RE2JS } from "re2js";

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

const regexCache = new Map<string, RE2JS>();
const MAX_REGEX_CACHE_ENTRIES = 256;
const MAX_REGEX_PROGRAM_SIZE = 1_000;

function compileSafeRegex(pattern: string): RE2JS | null {
  if (pattern.length > 256) return null;
  const cached = regexCache.get(pattern);
  if (cached) return cached;
  try {
    const compiled = RE2JS.compile(pattern, RE2JS.CASE_INSENSITIVE);
    if (compiled.programSize() > MAX_REGEX_PROGRAM_SIZE) return null;
    if (regexCache.size >= MAX_REGEX_CACHE_ENTRIES) {
      const oldest = regexCache.keys().next().value;
      if (oldest !== undefined) regexCache.delete(oldest);
    }
    regexCache.set(pattern, compiled);
    return compiled;
  } catch {
    return null;
  }
}

export function isValidPolicyRegex(pattern: string): boolean {
  return compileSafeRegex(pattern) !== null;
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
      return compileSafeRegex(condition.value)?.test(context.path) ?? false;
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
      return compileSafeRegex(condition.value)?.test(context.bodyText) ?? false;
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
