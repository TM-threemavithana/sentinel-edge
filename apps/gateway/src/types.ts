import type { Role, ThreatSignal } from "@sentinel/security-core";

export interface SessionUser {
  id: string;
  email: string;
  displayName: string;
  workspaceId: string;
  workspaceName: string;
  role: Role;
  sessionId: string;
}

export interface ApiKeyPrincipal {
  id: string;
  workspaceId: string;
  name: string;
  scopes: string[];
}

export interface AnalysisMessage {
  requestEventId: string;
  requestId: string;
  workspaceId: string;
  redactedBody: string;
  path: string;
  method: string;
  deterministicSignals: ThreatSignal[];
}

export interface PolicyRow {
  id: string;
  name: string;
  priority: number;
  action: "allow" | "block" | "challenge" | "log";
  conditions_json: string;
  rate_limit_json: string | null;
  enabled: number;
}
