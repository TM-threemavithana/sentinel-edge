const SENSITIVE_KEY = /(?:authorization|cookie|token|secret|password|api[-_]?key|private[-_]?key)/i;
const BEARER = /Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const SECRET_VALUE = /(?:sk-(?:proj-)?[a-z0-9_-]{12,}|AKIA[0-9A-Z]{16})/gi;

export function redactText(value: string, maxLength = 16_384): string {
  return value
    .slice(0, maxLength)
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(SECRET_VALUE, "[REDACTED]");
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key.toLowerCase(),
      SENSITIVE_KEY.test(key) ? "[REDACTED]" : redactText(value, 2_048),
    ]),
  );
}

export function redactJson(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[MAX_DEPTH]";
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => redactJson(item, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .slice(0, 100)
        .map(([key, item]) => [key, SENSITIVE_KEY.test(key) ? "[REDACTED]" : redactJson(item, depth + 1)]),
    );
  }
  return value;
}
