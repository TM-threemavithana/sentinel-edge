import type { Role, ThreatSignal } from "@sentinel/security-core";
import type { Env } from "./env";
import type { SessionUser } from "./types";
import { authenticateSession, hasRole } from "./auth";
import { hmacSha256 } from "./crypto";

export type AppBindings = {
  Bindings: Env;
  Variables: {
    requestId: string;
    user: SessionUser;
    apiKey?: { id: string; workspaceId: string };
  };
};

export const DUMMY_PASSWORD_HASH =
  "pbkdf2$120000$SwRxgVG_lqKA00TyfbX1bQ$PGrFNsT9VquFZPxRd3ppXgb3lT8z9XnEIJbGDaip9XY";

export function errorResponse(
  code: string,
  message: string,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 500 | 502 | 504,
): Response {
  return Response.json({ error: { code, message } }, { status });
}

export function allowedOrigins(env: Env): Set<string> {
  const configured = (env.ALLOWED_ORIGINS ?? "").split(",").map((v) => v.trim()).filter(Boolean);
  if (env.ENVIRONMENT === "development") configured.push("http://localhost:3000", "http://127.0.0.1:3000");
  return new Set(configured);
}

export function coordinator(env: Env, workspaceId: string): DurableObjectStub {
  if (env.ENVIRONMENT === "development") {
    return {
      fetch: async (urlOrReq: string | Request, _init?: RequestInit) => {
        const url = new URL(typeof urlOrReq === "string" ? urlOrReq : urlOrReq.url);
        if (url.pathname === "/rate-limit") {
          return Response.json({ allowed: true, remaining: 10, resetAt: new Date(Date.now() + 60000).toISOString() });
        }
        if (url.pathname === "/snapshot") {
          return Response.json({ live: { requests: 0, blocked: 0, bytes: 0 }, activeUsers: 1 });
        }
        if (url.pathname === "/counter/increment" || url.pathname === "/presence/touch") {
          return Response.json({ status: "ok" });
        }
        return Response.json({ error: "not_found" }, { status: 404 });
      },
    } as unknown as DurableObjectStub;
  }
  return env.EDGE_COORDINATOR.get(env.EDGE_COORDINATOR.idFromName(workspaceId));
}

export function requireSession(roles: Role[] = ["admin", "analyst", "viewer"]) {
  return async (c: any, next: () => Promise<void>) => {
    const user = await authenticateSession(c.req.raw, c.env as Env);
    if (!user) return errorResponse("unauthenticated", "Sign in to continue", 401);
    if (!hasRole(user.role, roles)) return errorResponse("forbidden", "Your role cannot perform this action", 403);
    c.set("user", user);
    await next();
  };
}

export function riskScore(signals: ThreatSignal[]): number {
  const weights = { low: 15, medium: 40, high: 70, critical: 95 } as const;
  return signals.reduce((score, s) => Math.max(score, Math.round(weights[s.severity] * s.confidence)), 0);
}

export function headersRecord(headers: Headers): Record<string, string> {
  return Object.fromEntries([...headers.entries()].map(([k, v]) => [k.toLowerCase(), v]));
}

export async function recordRequest(
  env: Env,
  input: {
    eventId: string; workspaceId: string; apiKeyId: string; upstreamId: string;
    requestId: string; context: { method: string; path: string; contentType: string; contentLength: number; clientIp?: string | null; country?: string | null };
    statusCode: number; decision: string; policyId: string | null;
    signals: ThreatSignal[]; latencyMs: number; responseBytes: number | null;
  },
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO request_events
      (id, workspace_id, api_key_id, upstream_id, request_id, method, path, status_code, decision,
       matched_policy_id, threat_categories_json, risk_score, country, client_ip_hash,
       latency_ms, request_bytes, response_bytes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    input.eventId, input.workspaceId, input.apiKeyId, input.upstreamId, input.requestId,
    input.context.method, input.context.path, input.statusCode, input.decision, input.policyId,
    JSON.stringify(input.signals.map((s) => s.category)), riskScore(input.signals),
    input.context.country ?? null, input.context.clientIp ? await hmacSha256(env.SESSION_SECRET, input.context.clientIp) : null, input.latencyMs, input.context.contentLength, input.responseBytes,
  ).run();
}
