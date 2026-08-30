import type { RequestContext, ThreatCategory, ThreatSeverity, ThreatSignal } from "./types";

const PATTERNS: ReadonlyArray<{
  category: ThreatCategory;
  severity: ThreatSeverity;
  expression: RegExp;
  summary: string;
}> = [
  {
    category: "prompt_injection",
    severity: "high",
    expression: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:(?:previous|prior)(?:\s+system)?|system)\s+(?:instructions?|prompts?)/i,
    summary: "Instruction override language detected",
  },
  {
    category: "prompt_injection",
    severity: "critical",
    expression: /(?:reveal|print|return|show)\s+(?:the\s+)?(?:system\s+prompt|hidden\s+instructions|developer\s+message)/i,
    summary: "System prompt extraction attempt detected",
  },
  {
    category: "sqli",
    severity: "critical",
    expression: /(?:\bunion\s+(?:all\s+)?select\b|\bdrop\s+table\b|(?:'|%27)\s*or\s+(?:'1'='1|1=1))/i,
    summary: "SQL injection token sequence detected",
  },
  {
    category: "xss",
    severity: "high",
    expression: /(?:<script\b|javascript\s*:|on(?:error|load|click)\s*=)/i,
    summary: "Executable browser markup detected",
  },
  {
    category: "ssrf",
    severity: "critical",
    expression: /(?:https?:\/\/)?(?:169\.254\.169\.254|127\.0\.0\.1|localhost|\[?::1\]?)(?:\b|\/)/i,
    summary: "Private or metadata endpoint reference detected",
  },
  {
    category: "path_traversal",
    severity: "high",
    expression: /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|%5c))/i,
    summary: "Path traversal sequence detected",
  },
  {
    category: "secret_exposure",
    severity: "high",
    expression: /(?:sk-(?:proj-)?[a-z0-9_-]{20,}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|AKIA[0-9A-Z]{16})/i,
    summary: "Credential-shaped value detected",
  },
];

function sourceText(context: RequestContext): string {
  const queryVals = Object.values(context.query).flatMap(v => Array.isArray(v) ? v : [v]).join("\n");
  return [
    context.path,
    queryVals,
    context.bodyText.slice(0, 128_000),
  ].join("\n");
}

export function inspectRequest(context: RequestContext, maxBodyBytes = 1_048_576): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const source = sourceText(context);

  if (context.contentLength > maxBodyBytes) {
    signals.push({
      category: "oversized_payload",
      severity: "high",
      confidence: 1,
      source: "deterministic",
      summary: `Payload exceeds the ${maxBodyBytes} byte inspection limit`,
    });
  }

  for (const pattern of PATTERNS) {
    if (pattern.expression.test(source)) {
      signals.push({
        category: pattern.category,
        severity: pattern.severity,
        confidence: 0.98,
        source: "deterministic",
        summary: pattern.summary,
      });
    }
  }

  return deduplicateSignals(signals);
}

export function deduplicateSignals(signals: ThreatSignal[]): ThreatSignal[] {
  const severityRank: Record<ThreatSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  const byCategory = new Map<ThreatCategory, ThreatSignal>();

  for (const signal of signals) {
    const current = byCategory.get(signal.category);
    if (
      !current ||
      severityRank[signal.severity] > severityRank[current.severity] ||
      signal.confidence > current.confidence
    ) {
      byCategory.set(signal.category, signal);
    }
  }

  return [...byCategory.values()].sort(
    (left, right) => severityRank[right.severity] - severityRank[left.severity],
  );
}
