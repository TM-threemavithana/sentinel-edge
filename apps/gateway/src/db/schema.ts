/**
 * Lightweight schema contract for code that consumes D1 rows.
 * The executable source of truth is migrations/0001_initial.sql.
 */
export const tables = {
  workspaces: "workspaces",
  users: "users",
  memberships: "memberships",
  sessions: "sessions",
  apiKeys: "api_keys",
  upstreams: "upstreams",
  policies: "policies",
  requestEvents: "request_events",
  analysisResults: "analysis_results",
  auditEvents: "audit_events",
  artifactMetadata: "artifact_metadata",
} as const;

export interface RequestEventRow {
  id: string;
  workspace_id: string;
  request_id: string;
  method: string;
  path: string;
  status_code: number | null;
  decision: "allow" | "block" | "challenge" | "log" | "rate_limited" | "error";
  threat_categories_json: string;
  risk_score: number;
  latency_ms: number | null;
  created_at: string;
}

export interface AuditEventRow {
  id: string;
  workspace_id: string;
  actor_type: "user" | "api_key" | "system";
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  metadata_json: string;
  created_at: string;
}
