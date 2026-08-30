export type Role = "admin" | "analyst" | "viewer";
export type Decision = "allow" | "block" | "challenge" | "log";
export type ThreatSeverity = "low" | "medium" | "high" | "critical";

export type ThreatCategory =
  | "prompt_injection"
  | "sqli"
  | "xss"
  | "ssrf"
  | "path_traversal"
  | "secret_exposure"
  | "oversized_payload"
  | "malicious_file"
  | "unknown";

export interface ThreatSignal {
  category: ThreatCategory;
  severity: ThreatSeverity;
  confidence: number;
  source: "deterministic" | "workers_ai";
  summary: string;
}

export interface RequestContext {
  method: string;
  path: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  bodyText: string;
  contentType: string;
  contentLength: number;
  clientIp?: string;
  country?: string;
}

export type RuleCondition =
  | { field: "method"; operator: "equals" | "in"; value: string | string[] }
  | { field: "path"; operator: "equals" | "starts_with" | "matches"; value: string }
  | { field: "header"; operator: "equals" | "contains" | "exists"; key: string; value?: string }
  | { field: "country"; operator: "equals" | "in"; value: string | string[] }
  | { field: "threat"; operator: "equals" | "in"; value: ThreatCategory | ThreatCategory[] }
  | { field: "severity"; operator: "at_least"; value: ThreatSeverity }
  | { field: "body"; operator: "contains" | "matches"; value: string };

export interface PolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  action: Decision;
  conditions: RuleCondition[];
  rateLimit?: {
    requests: number;
    windowSeconds: number;
    keyBy: "api_key" | "ip" | "workspace";
  };
}

export interface PolicyEvaluation {
  decision: Decision;
  matchedRuleId: string | null;
  matchedRuleName: string | null;
  reason: string;
  rateLimit: PolicyRule["rateLimit"] | null;
}
