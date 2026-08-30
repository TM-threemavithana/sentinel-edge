import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  evaluatePolicies,
  inspectRequest,
  redactHeaders,
  redactText,
  type PolicyRule,
  type RequestContext,
  type Role,
  type ThreatSignal,
} from "@sentinel/security-core";
import type { Env } from "./env";
import type { AnalysisMessage, SessionUser } from "./types";
import { authenticateApiKey, authenticateSession, createSession, destroySession, hasRole } from "./auth";
import { decryptValue, encryptValue, hmacSha256, randomToken, sha256, verifyPassword } from "./crypto";
import { getPolicies, invalidatePolicies } from "./policies";
import { classifyThreat } from "./ai";
import { storeAnalysisReport, storeRequestArtifact } from "./artifacts";
import { writeAudit } from "./audit";
import { EdgeCoordinator } from "./coordinator";
import {
  apiKeySchema,
  loginSchema,
  policyPatchSchema,
  policySchema,
  upstreamSchema,
} from "./validation";

type AppBindings = {
  Bindings: Env;
  Variables: {
    requestId: string;
    user: SessionUser;
  };
};

const app = new Hono<AppBindings>();
const DUMMY_PASSWORD_HASH =
  "pbkdf2$1000$ia1H7laZEelYQh329v4Lrw$GcKjSLTYBipVuM_Xuj9IGt_lJHOlKuVJeCM7vzBeN6Q";

function errorResponse(
  code: string,
  message: string,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 500 | 502 | 504,
): Response {
  return Response.json({ error: { code, message } }, { status });
}

function allowedOrigins(env: Env): Set<string> {
  const configured = (env.ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  if (env.ENVIRONMENT === "development") configured.push("http://localhost:3000", "http://127.0.0.1:3000");
  return new Set(configured);
}

function coordinator(env: Env, workspaceId: string): DurableObjectStub {
  if (env.ENVIRONMENT === "development") {
    return {
      fetch: async (urlOrReq: string | Request, init?: RequestInit) => {
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

function requireSession(roles: Role[] = ["admin", "analyst", "viewer"]) {
  return async (c: Parameters<typeof app.use>[1] extends never ? never : any, next: () => Promise<void>) => {
    const user = await authenticateSession(c.req.raw, c.env as Env);
    if (!user) return errorResponse("unauthenticated", "Sign in to continue", 401);
    if (!hasRole(user.role, roles)) return errorResponse("forbidden", "Your role cannot perform this action", 403);
    c.set("user", user);
    await next();
  };
}

app.use("*", async (c, next) => {
  const requestId = c.req.header("cf-ray") ?? crypto.randomUUID();
  c.set("requestId", requestId);
  const startedAt = Date.now();
  await next();
  c.header("x-request-id", requestId);
  c.header("x-content-type-options", "nosniff");
  c.header("referrer-policy", "no-referrer");
  c.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
  c.header("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  console.log(JSON.stringify({ requestId, method: c.req.method, path: c.req.path, status: c.res.status, latencyMs: Date.now() - startedAt }));
});

app.use("/v1/*", cors({
  origin: (origin, c) => {
    const allowed = allowedOrigins(c.env as Env);
    return (origin && allowed.has(origin)) ? origin : null;
  },
  credentials: true,
}));

app.use("/v1/*", async (c, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(c.req.method) || c.req.path.startsWith("/v1/gateway/")) {
    await next();
    return;
  }
  const origin = c.req.header("origin");
  if (origin && !allowedOrigins(c.env).has(origin)) {
    return errorResponse("invalid_origin", "The request origin is not allowed", 403);
  }
  await next();
});

app.onError((error, c) => {
  console.error(JSON.stringify({ requestId: c.get("requestId"), error: error.message, stack: error.stack }));
  return errorResponse("internal_error", "The gateway could not complete the request", 500);
});

app.get("/health", async (c) => {
  try {
    const res = await coordinator(c.env, "auth").fetch("https://coordinator/snapshot");
    const json = await res.json();
    return c.json({ status: "ok", coordinator: json });
  } catch (e: any) {
    return c.json({ status: "error", error: e.message, stack: e.stack });
  }
});

app.post("/v1/auth/login", async (c) => {
  const parsed = loginSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return errorResponse("invalid_credentials", "Email or password is invalid", 401);

  const rateKey = await hmacSha256(c.env.SESSION_SECRET, `${parsed.data.email}:${c.req.header("cf-connecting-ip") ?? "local"}`);
  const rateResponse = await coordinator(c.env, "auth").fetch("https://coordinator/rate-limit", {
    method: "POST",
    body: JSON.stringify({ key: rateKey, limit: 8, windowSeconds: 300 }),
  });
  const rate = (await rateResponse.json()) as { allowed: boolean; resetAt: string };
  if (!rate.allowed) return errorResponse("too_many_attempts", `Try again after ${rate.resetAt}`, 429);

  const row = await c.env.DB.prepare(
    `SELECT u.id, u.email, u.display_name, u.password_hash, m.workspace_id, m.role, w.name AS workspace_name
       FROM users u
       JOIN memberships m ON m.user_id = u.id
       JOIN workspaces w ON w.id = m.workspace_id
      WHERE u.email = ? COLLATE NOCASE AND u.status = 'active' AND u.auth_provider = 'local'
      ORDER BY m.created_at ASC LIMIT 1`,
  )
    .bind(parsed.data.email)
    .first<{
      id: string;
      email: string;
      display_name: string;
      password_hash: string | null;
      workspace_id: string;
      workspace_name: string;
      role: Role;
    }>();

  const passwordValid = await verifyPassword(parsed.data.password, row?.password_hash ?? DUMMY_PASSWORD_HASH);
  if (!row || !passwordValid) return errorResponse("invalid_credentials", "Email or password is invalid", 401);

  const session = await createSession(c.req.raw, c.env, row.id, row.workspace_id);
  await c.env.DB.prepare("UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
    .bind(row.id)
    .run();
  c.header("set-cookie", session.cookie);
  c.executionCtx.waitUntil(
    writeAudit(c.env, {
      workspaceId: row.workspace_id,
      actorType: "user",
      actorId: row.id,
      action: "auth.login",
      resourceType: "session",
      resourceId: session.sessionId,
      request: c.req.raw,
      requestId: c.get("requestId"),
    }),
  );
  return c.json({
    user: {
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      workspaceId: row.workspace_id,
      workspaceName: row.workspace_name,
      role: row.role,
    },
  });
});

app.post("/v1/auth/logout", async (c) => {
  const user = await authenticateSession(c.req.raw, c.env);
  c.header("set-cookie", await destroySession(c.req.raw, c.env));
  if (user) {
    c.executionCtx.waitUntil(
      writeAudit(c.env, {
        workspaceId: user.workspaceId,
        actorType: "user",
        actorId: user.id,
        action: "auth.logout",
        resourceType: "session",
        resourceId: user.sessionId,
        request: c.req.raw,
        requestId: c.get("requestId"),
      }),
    );
  }
  return c.json({ ok: true });
});

app.get("/v1/auth/me", requireSession(), async (c) => {
  const user = c.get("user");
  c.executionCtx.waitUntil(
    coordinator(c.env, user.workspaceId).fetch("https://coordinator/presence/touch", {
      method: "POST",
      body: JSON.stringify({ sessionId: user.sessionId, userId: user.id }),
    }).then(() => undefined),
  );
  return c.json({ user });
});

app.get("/v1/analytics/overview", requireSession(), async (c) => {
  const user = c.get("user");
  const [summaryResult, seriesResult, topThreatsResult] = await c.env.DB.batch([
    c.env.DB.prepare(
      `SELECT COUNT(*) AS total_requests,
              SUM(CASE WHEN decision IN ('block', 'challenge') THEN 1 ELSE 0 END) AS blocked,
              SUM(CASE WHEN decision = 'rate_limited' THEN 1 ELSE 0 END) AS rate_limited,
              ROUND(AVG(CASE WHEN latency_ms IS NOT NULL THEN latency_ms END), 1) AS average_latency,
              ROUND(AVG(risk_score), 1) AS average_risk
         FROM request_events WHERE workspace_id = ? AND created_at >= datetime('now', '-24 hours')`,
    ).bind(user.workspaceId),
    c.env.DB.prepare(
      `SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) AS bucket,
              COUNT(*) AS requests,
              SUM(CASE WHEN decision IN ('block', 'challenge') THEN 1 ELSE 0 END) AS blocked
         FROM request_events
        WHERE workspace_id = ? AND created_at >= datetime('now', '-24 hours')
        GROUP BY bucket ORDER BY bucket ASC`,
    ).bind(user.workspaceId),
    c.env.DB.prepare(
      `SELECT je.value AS category, COUNT(*) AS count
         FROM request_events re, json_each(re.threat_categories_json) je
        WHERE re.workspace_id = ? AND re.created_at >= datetime('now', '-7 days')
        GROUP BY je.value ORDER BY count DESC LIMIT 5`,
    ).bind(user.workspaceId),
  ]);

  const summary = (summaryResult?.results[0] ?? {}) as Record<string, unknown>;
  return c.json({
    summary: {
      totalRequests: Number(summary.total_requests ?? 0),
      blocked: Number(summary.blocked ?? 0),
      rateLimited: Number(summary.rate_limited ?? 0),
      averageLatency: Number(summary.average_latency ?? 0),
      averageRisk: Number(summary.average_risk ?? 0),
    },
    series: seriesResult?.results ?? [],
    topThreats: topThreatsResult?.results ?? [],
  });
});

app.get("/v1/analytics/live", requireSession(), async (c) => {
  const snapshot = await coordinator(c.env, c.get("user").workspaceId).fetch("https://coordinator/snapshot");
  return new Response(snapshot.body, { status: snapshot.status, headers: snapshot.headers });
});

app.get("/v1/requests", requireSession(), async (c) => {
  const limit = Math.min(100, Math.max(1, Number(c.req.query("limit")) || 50));
  const decision = c.req.query("decision");
  const user = c.get("user");
  const base = `SELECT id, request_id, method, path, status_code, decision, threat_categories_json,
                       risk_score, country, latency_ms, request_bytes, response_bytes, artifact_key, created_at
                  FROM request_events WHERE workspace_id = ?`;
  const statement = decision
    ? c.env.DB.prepare(`${base} AND decision = ? ORDER BY created_at DESC LIMIT ?`).bind(user.workspaceId, decision, limit)
    : c.env.DB.prepare(`${base} ORDER BY created_at DESC LIMIT ?`).bind(user.workspaceId, limit);
  const rows = await statement.all();
  return c.json({ data: rows.results });
});

app.get("/v1/audit", requireSession(["admin", "analyst"]), async (c) => {
  const limit = Math.min(100, Math.max(1, Number(c.req.query("limit")) || 50));
  const rows = await c.env.DB.prepare(
    `SELECT id, actor_type, actor_id, action, resource_type, resource_id, metadata_json, request_id, created_at
       FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ?`,
  )
    .bind(c.get("user").workspaceId, limit)
    .all();
  return c.json({ data: rows.results });
});

app.get("/v1/api-keys", requireSession(), async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, key_prefix, scopes_json, status, expires_at, last_used_at, created_at
       FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC`,
  )
    .bind(c.get("user").workspaceId)
    .all();
  return c.json({ data: rows.results });
});

app.post("/v1/api-keys", requireSession(["admin"]), async (c) => {
  const parsed = apiKeySchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid API key", 422);
  const user = c.get("user");
  const rawKey = `sg_live_${randomToken(32)}`;
  const id = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO api_keys (id, workspace_id, name, key_prefix, key_hash, scopes_json, expires_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      user.workspaceId,
      parsed.data.name,
      rawKey.slice(0, 16),
      await sha256(rawKey),
      JSON.stringify(parsed.data.scopes),
      parsed.data.expiresAt ?? null,
      user.id,
    )
    .run();
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "api_key.created",
    resourceType: "api_key", resourceId: id, metadata: { name: parsed.data.name, scopes: parsed.data.scopes },
    request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ id, name: parsed.data.name, key: rawKey, prefix: rawKey.slice(0, 16) }, 201);
});

app.delete("/v1/api-keys/:id", requireSession(["admin"]), async (c) => {
  const user = c.get("user");
  const result = await c.env.DB.prepare(
    `UPDATE api_keys SET status = 'revoked', revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ? AND workspace_id = ? AND status = 'active'`,
  )
    .bind(c.req.param("id"), user.workspaceId)
    .run();
  if (!result.meta.changes) return errorResponse("not_found", "Active API key not found", 404);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "api_key.revoked",
    resourceType: "api_key", resourceId: c.req.param("id"), request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ ok: true });
});

app.get("/v1/policies", requireSession(), async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, description, priority, action, conditions_json, rate_limit_json, enabled, version, updated_at
       FROM policies WHERE workspace_id = ? ORDER BY priority ASC`,
  )
    .bind(c.get("user").workspaceId)
    .all();
  return c.json({ data: rows.results });
});

app.post("/v1/policies", requireSession(["admin", "analyst"]), async (c) => {
  const parsed = policySchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid policy", 422);
  const user = c.get("user");
  const id = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO policies
        (id, workspace_id, name, description, priority, action, conditions_json, rate_limit_json, enabled, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        id, user.workspaceId, parsed.data.name, parsed.data.description, parsed.data.priority,
        parsed.data.action, JSON.stringify(parsed.data.conditions),
        parsed.data.rateLimit ? JSON.stringify(parsed.data.rateLimit) : null,
        parsed.data.enabled ? 1 : 0, user.id,
      )
      .run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      return errorResponse("priority_conflict", "Another policy already uses this priority", 409);
    }
    throw error;
  }
  await invalidatePolicies(c.env, user.workspaceId);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "policy.created",
    resourceType: "policy", resourceId: id, metadata: { name: parsed.data.name }, request: c.req.raw,
    requestId: c.get("requestId"),
  }));
  return c.json({ id, ...parsed.data }, 201);
});

app.patch("/v1/policies/:id", requireSession(["admin", "analyst"]), async (c) => {
  const user = c.get("user");
  const current = await c.env.DB.prepare(
    `SELECT id, name, description, priority, action, conditions_json, rate_limit_json, enabled
       FROM policies WHERE id = ? AND workspace_id = ?`,
  )
    .bind(c.req.param("id"), user.workspaceId)
    .first<Record<string, unknown>>();
  if (!current) return errorResponse("not_found", "Policy not found", 404);
  const patch = await c.req.json().catch(() => null);
  const parsed = policyPatchSchema.safeParse({ ...(patch as object), id: c.req.param("id") });
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid policy", 422);
  const merged = policySchema.parse({
    name: current.name, description: current.description, priority: current.priority, action: current.action,
    conditions: JSON.parse(String(current.conditions_json)),
    rateLimit: current.rate_limit_json ? JSON.parse(String(current.rate_limit_json)) : null,
    enabled: current.enabled === 1,
    ...parsed.data,
  });
  await c.env.DB.prepare(
    `UPDATE policies SET name = ?, description = ?, priority = ?, action = ?, conditions_json = ?,
                         rate_limit_json = ?, enabled = ?, version = version + 1,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ? AND workspace_id = ?`,
  )
    .bind(
      merged.name, merged.description, merged.priority, merged.action, JSON.stringify(merged.conditions),
      merged.rateLimit ? JSON.stringify(merged.rateLimit) : null, merged.enabled ? 1 : 0,
      c.req.param("id"), user.workspaceId,
    )
    .run();
  await invalidatePolicies(c.env, user.workspaceId);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "policy.updated",
    resourceType: "policy", resourceId: c.req.param("id"), metadata: { name: merged.name }, request: c.req.raw,
    requestId: c.get("requestId"),
  }));
  return c.json({ id: c.req.param("id"), ...merged });
});

app.get("/v1/upstreams", requireSession(), async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, base_url, auth_header_name, timeout_ms, status, created_at
       FROM upstreams WHERE workspace_id = ? ORDER BY name ASC`,
  )
    .bind(c.get("user").workspaceId)
    .all();
  return c.json({ data: rows.results });
});

app.post("/v1/upstreams", requireSession(["admin"]), async (c) => {
  const parsed = upstreamSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid upstream", 422);
  const user = c.get("user");
  const id = crypto.randomUUID();
  const encrypted = parsed.data.authValue
    ? await encryptValue(c.env.UPSTREAM_ENCRYPTION_KEY, parsed.data.authValue)
    : null;
  await c.env.DB.prepare(
    `INSERT INTO upstreams
      (id, workspace_id, name, base_url, auth_header_name, encrypted_auth_value, timeout_ms, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id, user.workspaceId, parsed.data.name, parsed.data.baseUrl.replace(/\/$/u, ""),
      parsed.data.authHeaderName.toLowerCase(), encrypted, parsed.data.timeoutMs, user.id,
    )
    .run();
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "upstream.created",
    resourceType: "upstream", resourceId: id, metadata: { name: parsed.data.name, baseUrl: parsed.data.baseUrl },
    request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ id, name: parsed.data.name, baseUrl: parsed.data.baseUrl }, 201);
});

app.get("/v1/artifacts/:id", requireSession(["admin", "analyst"]), async (c) => {
  const row = await c.env.DB.prepare(
    `SELECT object_key, content_type FROM artifact_metadata WHERE id = ? AND workspace_id = ?`,
  )
    .bind(c.req.param("id"), c.get("user").workspaceId)
    .first<{ object_key: string; content_type: string }>();
  if (!row) return errorResponse("not_found", "Artifact not found", 404);
  const object = await c.env.ARTIFACTS.get(row.object_key);
  if (!object) return errorResponse("not_found", "Artifact object is missing", 404);
  return new Response(object.body, {
    headers: {
      "content-type": row.content_type,
      "content-disposition": `attachment; filename="${row.object_key.split("/").at(-1) ?? "report.json"}"`,
      "cache-control": "private, no-store",
    },
  });
});

function riskScore(signals: ThreatSignal[]): number {
  const weights = { low: 15, medium: 40, high: 70, critical: 95 } as const;
  return signals.reduce((score, signal) => Math.max(score, Math.round(weights[signal.severity] * signal.confidence)), 0);
}

function headersRecord(headers: Headers): Record<string, string> {
  return Object.fromEntries([...headers.entries()].map(([key, value]) => [key.toLowerCase(), value]));
}

async function recordRequest(
  env: Env,
  input: {
    eventId: string;
    workspaceId: string;
    apiKeyId: string;
    upstreamId: string;
    requestId: string;
    context: RequestContext;
    statusCode: number;
    decision: string;
    policyId: string | null;
    signals: ThreatSignal[];
    latencyMs: number;
    responseBytes: number | null;
  },
): Promise<void> {
  const ipHash = input.context.clientIp ? await hmacSha256(env.SESSION_SECRET, input.context.clientIp) : null;
  await env.DB.prepare(
    `INSERT INTO request_events
      (id, workspace_id, api_key_id, upstream_id, request_id, method, path, status_code, decision,
       matched_policy_id, threat_categories_json, risk_score, country, client_ip_hash, latency_ms,
       request_bytes, response_bytes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      input.eventId, input.workspaceId, input.apiKeyId, input.upstreamId, input.requestId,
      input.context.method, input.context.path, input.statusCode, input.decision, input.policyId,
      JSON.stringify(input.signals.map((signal) => signal.category)), riskScore(input.signals),
      input.context.country ?? null, ipHash, input.latencyMs, input.context.contentLength, input.responseBytes,
    )
    .run();
}

app.all("/v1/gateway/:upstreamId/*", async (c) => {
  const principal = await authenticateApiKey(c.req.raw, c.env);
  if (!principal || !principal.scopes.includes("gateway:invoke")) {
    return errorResponse("invalid_api_key", "Provide an active API key with gateway:invoke scope", 401);
  }
  const upstream = await c.env.DB.prepare(
    `SELECT id, base_url, auth_header_name, encrypted_auth_value, timeout_ms
       FROM upstreams WHERE id = ? AND workspace_id = ? AND status = 'active'`,
  )
    .bind(c.req.param("upstreamId"), principal.workspaceId)
    .first<{
      id: string;
      base_url: string;
      auth_header_name: string;
      encrypted_auth_value: string | null;
      timeout_ms: number;
    }>();
  if (!upstream) return errorResponse("upstream_not_found", "The requested upstream is unavailable", 404);

  const startedAt = Date.now();
  const requestId = c.get("requestId");
  const eventId = crypto.randomUUID();
  const bodyBytes = ["GET", "HEAD"].includes(c.req.method)
    ? new Uint8Array()
    : new Uint8Array(await c.req.raw.clone().arrayBuffer());
  const maxBytes = Number(c.env.MAX_INSPECTION_BYTES) || 1_048_576;
  const bodyText = new TextDecoder().decode(bodyBytes.slice(0, maxBytes + 1));
  const url = new URL(c.req.url);
  const context: RequestContext = {
    method: c.req.method,
    path: `/${c.req.param("*")}`,
    headers: headersRecord(c.req.raw.headers),
    query: Object.fromEntries(url.searchParams.entries()),
    bodyText,
    contentType: c.req.header("content-type") ?? "application/octet-stream",
    contentLength: bodyBytes.byteLength || Number(c.req.header("content-length")) || 0,
    ...(c.req.header("cf-connecting-ip") ? { clientIp: c.req.header("cf-connecting-ip")! } : {}),
    ...(c.req.header("cf-ipcountry") ? { country: c.req.header("cf-ipcountry")! } : {}),
  };

  let signals = inspectRequest(context, maxBytes);
  if (c.env.AI_MODE === "inline" && bodyText.length > 0 && bodyText.length <= 12_000) {
    try {
      const ai = await classifyThreat(c.env, {
        method: context.method,
        path: context.path,
        redactedBody: redactText(bodyText),
        deterministicSignals: signals,
      });
      if (ai.category !== "unknown" && ai.confidence >= 0.6) {
        signals = [...signals, {
          category: ai.category,
          confidence: ai.confidence,
          source: "workers_ai",
          severity: ai.recommendedAction === "block" ? "high" : "medium",
          summary: ai.explanation,
        }];
      }
    } catch (error) {
      console.warn(JSON.stringify({ requestId, message: "inline_ai_failed", error: String(error) }));
    }
  }

  const policies = await getPolicies(c.env, principal.workspaceId);
  const evaluation = evaluatePolicies(policies, context, signals);
  let decision: "allow" | "block" | "challenge" | "log" | "rate_limited" = evaluation.decision;
  let rateHeaders: Record<string, string> = {};
  if (evaluation.rateLimit) {
    const key = evaluation.rateLimit.keyBy === "api_key"
      ? principal.id
      : evaluation.rateLimit.keyBy === "ip"
        ? (context.clientIp ?? "unknown")
        : principal.workspaceId;
    const result = await coordinator(c.env, principal.workspaceId).fetch("https://coordinator/rate-limit", {
      method: "POST",
      body: JSON.stringify({ key: `${evaluation.matchedRuleId}:${key}`, limit: evaluation.rateLimit.requests, windowSeconds: evaluation.rateLimit.windowSeconds }),
    });
    const rate = (await result.json()) as { allowed: boolean; limit: number; remaining: number; resetAt: string };
    rateHeaders = { "x-ratelimit-limit": String(rate.limit), "x-ratelimit-remaining": String(rate.remaining), "x-ratelimit-reset": rate.resetAt };
    if (!rate.allowed) decision = "rate_limited";
  }

  if (context.contentLength > maxBytes) decision = "block";
  if (decision === "block" || decision === "challenge" || decision === "rate_limited") {
    const status = decision === "rate_limited" ? 429 : decision === "challenge" ? 403 : context.contentLength > maxBytes ? 413 : 403;
    await recordRequest(c.env, {
      eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id,
      requestId, context, statusCode: status, decision, policyId: evaluation.matchedRuleId,
      signals, latencyMs: Date.now() - startedAt, responseBytes: null,
    });
    c.executionCtx.waitUntil(Promise.all([
      coordinator(c.env, principal.workspaceId).fetch("https://coordinator/counter/increment", {
        method: "POST", body: JSON.stringify({ decision: decision === "rate_limited" ? "rate_limited" : "blocked" }),
      }).then(() => undefined),
      storeRequestArtifact(c.env, {
        workspaceId: principal.workspaceId, requestEventId: eventId, requestId, method: context.method,
        path: context.path, headers: context.headers, body: bodyText,
      }).then(() => undefined),
      processAnalysis({
        requestEventId: eventId, requestId, workspaceId: principal.workspaceId, redactedBody: redactText(bodyText),
        path: context.path, method: context.method, deterministicSignals: signals,
      }, c.env).catch(e => console.error(JSON.stringify({ message: "analysis_failed", requestEventId: eventId, error: String(e) }))),
    ]).then(() => undefined));
    return new Response(JSON.stringify({ error: { code: decision, message: evaluation.reason }, requestId }), {
      status, headers: { "content-type": "application/json", ...rateHeaders },
    });
  }

  const prefix = `/v1/gateway/${c.req.param("upstreamId")}`;
  let upstreamPath = url.pathname.slice(prefix.length);
  if (!upstreamPath.startsWith("/")) upstreamPath = "/" + upstreamPath;
  const destination = new URL(upstreamPath + url.search, upstream.base_url);
  const forwardHeaders = new Headers(c.req.raw.headers);
  for (const header of ["host", "cookie", "authorization", "x-sentinel-key", "cf-connecting-ip", "cf-ipcountry", "content-length"]) {
    forwardHeaders.delete(header);
  }
  if (upstream.encrypted_auth_value) {
    forwardHeaders.set(upstream.auth_header_name, await decryptValue(c.env.UPSTREAM_ENCRYPTION_KEY, upstream.encrypted_auth_value));
  }
  forwardHeaders.set("x-sentinel-request-id", requestId);
  forwardHeaders.set("host", destination.host);

  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(destination, {
      method: context.method,
      headers: forwardHeaders,
      ...(bodyBytes.byteLength > 0 ? { body: bodyBytes } : {}),
      redirect: "manual",
      signal: AbortSignal.timeout(upstream.timeout_ms),
    });
  } catch (error) {
    const isTimeout = error instanceof Error && error.name === "TimeoutError";
    await recordRequest(c.env, {
      eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id,
      requestId, context, statusCode: isTimeout ? 504 : 502, decision: "error", policyId: evaluation.matchedRuleId,
      signals, latencyMs: Date.now() - startedAt, responseBytes: null,
    });
    return errorResponse(isTimeout ? "upstream_timeout" : "upstream_error", "The upstream did not complete the request", isTimeout ? 504 : 502);
  }

  const responseBytes = Number(upstreamResponse.headers.get("content-length")) || null;
  await recordRequest(c.env, {
    eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id,
    requestId, context, statusCode: upstreamResponse.status, decision, policyId: evaluation.matchedRuleId,
    signals, latencyMs: Date.now() - startedAt, responseBytes,
  });
  c.executionCtx.waitUntil(Promise.all([
    c.env.DB.prepare("UPDATE api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(principal.id).run(),
    coordinator(c.env, principal.workspaceId).fetch("https://coordinator/counter/increment", {
      method: "POST", body: JSON.stringify({ decision: "allowed" }),
    }),
    processAnalysis({
      requestEventId: eventId, requestId, workspaceId: principal.workspaceId, redactedBody: redactText(bodyText),
      path: context.path, method: context.method, deterministicSignals: signals,
    }, c.env).catch(e => console.error(JSON.stringify({ message: "analysis_failed", requestEventId: eventId, error: String(e) }))),
    ...(signals.length > 0 ? [storeRequestArtifact(c.env, {
      workspaceId: principal.workspaceId, requestEventId: eventId, requestId, method: context.method,
      path: context.path, headers: redactHeaders(context.headers), body: bodyText,
    })] : []),
  ]).then(() => undefined));

  const responseHeaders = new Headers(upstreamResponse.headers);
  responseHeaders.set("x-sentinel-request-id", requestId);
  for (const [key, value] of Object.entries(rateHeaders)) responseHeaders.set(key, value);
  return new Response(upstreamResponse.body, { status: upstreamResponse.status, headers: responseHeaders });
});

async function processAnalysis(input: AnalysisMessage, env: Env): Promise<void> {
  const classification = await classifyThreat(env, {
    method: input.method,
    path: input.path,
    redactedBody: input.redactedBody,
    deterministicSignals: input.deterministicSignals,
  });
  const report = {
    requestId: input.requestId,
    generatedAt: new Date().toISOString(),
    model: env.AI_MODEL,
    classification,
    deterministicSignals: input.deterministicSignals,
    handling: "Request content was redacted and truncated before analysis.",
  };
  const artifactKey = await storeAnalysisReport(env, {
    workspaceId: input.workspaceId,
    requestEventId: input.requestEventId,
    requestId: input.requestId,
    report,
  });
  await env.DB.prepare(
    `INSERT INTO analysis_results
      (id, request_event_id, model, category, confidence, explanation, recommended_action, artifact_key)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(request_event_id) DO UPDATE SET
       model = excluded.model, category = excluded.category, confidence = excluded.confidence,
       explanation = excluded.explanation, recommended_action = excluded.recommended_action,
       artifact_key = excluded.artifact_key`,
  )
    .bind(
      crypto.randomUUID(), input.requestEventId, env.AI_MODEL, classification.category,
      classification.confidence, classification.explanation, classification.recommendedAction, artifactKey,
    )
    .run();
}

export default {
  fetch: app.fetch,
};

export { EdgeCoordinator };
