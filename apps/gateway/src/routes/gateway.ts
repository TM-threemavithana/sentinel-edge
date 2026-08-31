import { Hono } from "hono";
import { errorResponse, AppBindings, recordRequest, coordinator, headersRecord } from "../helpers";
import { redactHeaders, redactBody } from "@sentinel/security-core";
import { storeRequestArtifact } from "../artifacts";
import type { RequestContext, ThreatSignal } from "@sentinel/security-core";
import { evaluatePolicies, inspectRequest } from "@sentinel/security-core";
import { classifyThreat, type AiClassification } from "../ai";
import { authenticateApiKey } from "../auth";
import { getPolicies } from "../policies";
import { dispatchAnalysis } from "../analysis";


type ClassificationResult = AiClassification;

const gateway = new Hono<AppBindings>();

gateway.use("*", async (c, next) => {
  const principal = await authenticateApiKey(c.req.raw, c.env);
  if (!principal) {
    return errorResponse("unauthenticated", "A valid Sentinel API key is required", 401);
  }
  if (!principal.scopes.includes("gateway:invoke")) {
    return errorResponse("insufficient_scope", "This API key cannot invoke the gateway", 403);
  }
  c.set("apiKey", principal);
  await next();
});

gateway.all("/:upstreamId/*", async (c) => {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const principal = c.get("apiKey");

  const upstream = await c.env.DB.prepare("SELECT * FROM upstreams WHERE id = ? AND workspace_id = ? AND status = 'active'").bind(c.req.param("upstreamId"), principal.workspaceId).first<{
    id: string;
    base_url: string;
    auth_header_name: string;
    encrypted_auth_value: string | null;
    timeout_ms: number;
  }>();

  if (!upstream) {
    return errorResponse("upstream_not_found", "The specified upstream does not exist.", 404);
  }

  // Derive paths properly before inspection
  const prefix = `/v1/gateway/${c.req.param("upstreamId")}`;
  const url = new URL(c.req.url);
  let upstreamPath = url.pathname.slice(prefix.length);
  if (!upstreamPath.startsWith("/")) upstreamPath = "/" + upstreamPath;
  const cleanPath = upstreamPath.replace(/^\/+/, "/");
  
  // Construct destination URL safely (SSRF defense)
  const base = new URL(upstream.base_url);
  const destination = new URL(base.pathname.replace(/\/$/, "") + cleanPath + url.search, base.origin);

  // Parse queries preserving arrays for HPP defense
  const query: Record<string, string | string[]> = {};
  url.searchParams.forEach((_, key) => {
    const values = url.searchParams.getAll(key);
    query[key] = values.length === 1 ? values[0]! : values;
  });

  const maxBytes = Number(c.env.MAX_INSPECTION_BYTES);
  
  // Enforce streaming body size limit (OOM Defense)
  let bodyBytes = new Uint8Array();
  if (c.req.raw.body) {
    const reader = c.req.raw.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalLength = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        totalLength += value.length;
        if (totalLength > maxBytes) {
           return errorResponse("payload_too_large", "Request body exceeds maximum inspection size", 413);
        }
        chunks.push(value);
      }
    }
    bodyBytes = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      bodyBytes.set(chunk, offset);
      offset += chunk.length;
    }
  }

  const bodyText = new TextDecoder().decode(bodyBytes);
  const clientIp = c.req.header("cf-connecting-ip") ?? undefined;
  const country = c.req.header("cf-ipcountry") ?? undefined;

  const context: RequestContext = {
    method: c.req.method,
    path: cleanPath, // Inspect the upstream path
    headers: headersRecord(c.req.raw.headers),
    query, // Pass canonicalized queries
    bodyText,
    contentType: c.req.header("content-type") ?? "",
    contentLength: bodyBytes.byteLength,
    ...(clientIp ? { clientIp } : {}),
    ...(country ? { country } : {}),
  };

  let signals: ThreatSignal[] = inspectRequest(context, maxBytes);
  let precomputedAi: ClassificationResult | undefined;

  if (c.env.FREE_TIER_MODE !== "true" && c.env.AI_MODE === "inline" && signals.length === 0 && bodyText.length > 0) {
    try {
      precomputedAi = await classifyThreat(c.env, { method: context.method, path: context.path, redactedBody: redactBody(bodyText, context.contentType), deterministicSignals: signals });
      if (precomputedAi.confidence >= 0.85 && precomputedAi.recommendedAction === "block") {
        signals = [...signals, { category: precomputedAi.category, confidence: precomputedAi.confidence, source: "workers_ai", severity: "high", summary: precomputedAi.explanation }];
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
    const key = evaluation.rateLimit.keyBy === "api_key" ? principal.id : evaluation.rateLimit.keyBy === "ip" ? (context.clientIp ?? "unknown") : principal.workspaceId;
    const result = await coordinator(c.env, principal.workspaceId).fetch("https://coordinator/rate-limit", {
      method: "POST", body: JSON.stringify({ key: `${evaluation.matchedRuleId}:${key}`, limit: evaluation.rateLimit.requests, windowSeconds: evaluation.rateLimit.windowSeconds }),
    });
    const rate = (await result.json()) as { allowed: boolean; limit: number; remaining: number; resetAt: string };
    rateHeaders = { "x-ratelimit-limit": String(rate.limit), "x-ratelimit-remaining": String(rate.remaining), "x-ratelimit-reset": rate.resetAt };
    if (!rate.allowed) decision = "rate_limited";
  }

  if (decision === "block" || decision === "challenge" || decision === "rate_limited") {
    const status = decision === "rate_limited" ? 429 : decision === "challenge" ? 403 : 403;
    await recordRequest(c.env, { eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id, requestId, context, statusCode: status, decision, policyId: evaluation.matchedRuleId, signals, latencyMs: Date.now() - startedAt, responseBytes: null });
    
    c.executionCtx.waitUntil(Promise.all([
      coordinator(c.env, principal.workspaceId).fetch("https://coordinator/counter/increment", { method: "POST", body: JSON.stringify({ decision: decision === "rate_limited" ? "rate_limited" : "blocked" }) }).then(() => undefined),
      storeRequestArtifact(c.env, { workspaceId: principal.workspaceId, requestEventId: eventId, requestId, method: context.method, path: context.path, headers: context.headers, body: bodyText }).then(() => undefined),
      dispatchAnalysis({ requestEventId: eventId, requestId, workspaceId: principal.workspaceId, redactedBody: redactBody(bodyText, context.contentType).slice(0, 12_000), path: context.path, method: context.method, deterministicSignals: signals }, c.env, precomputedAi).catch(e => console.error(JSON.stringify({ message: "analysis_failed", requestEventId: eventId, error: String(e) }))),
    ]).then(() => undefined));
    return new Response(JSON.stringify({ error: { code: decision, message: evaluation.reason }, requestId }), { status, headers: { "content-type": "application/json", ...rateHeaders } });
  }

  const forwardHeaders = new Headers(c.req.raw.headers);
  for (const header of ["host", "cookie", "authorization", "x-sentinel-key", "cf-connecting-ip", "cf-ipcountry", "content-length"]) forwardHeaders.delete(header);
  
  if (upstream.encrypted_auth_value) {
    const { decryptValue } = await import("../crypto");
    forwardHeaders.set(upstream.auth_header_name, await decryptValue(c.env.UPSTREAM_ENCRYPTION_KEY, upstream.encrypted_auth_value));
  }
  
  forwardHeaders.set("x-sentinel-request-id", requestId);
  forwardHeaders.set("host", destination.host);

  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(destination, { method: context.method, headers: forwardHeaders, ...(bodyBytes.byteLength > 0 ? { body: bodyBytes } : {}), redirect: "manual", signal: AbortSignal.timeout(upstream.timeout_ms) });
  } catch (error) {
    const isTimeout = error instanceof Error && error.name === "TimeoutError";
    await recordRequest(c.env, { eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id, requestId, context, statusCode: isTimeout ? 504 : 502, decision: "error", policyId: evaluation.matchedRuleId, signals, latencyMs: Date.now() - startedAt, responseBytes: null });
    return errorResponse(isTimeout ? "upstream_timeout" : "upstream_error", "The upstream did not complete the request", isTimeout ? 504 : 502);
  }

  const responseBytes = Number(upstreamResponse.headers.get("content-length")) || null;
  await recordRequest(c.env, { eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id, requestId, context, statusCode: upstreamResponse.status, decision, policyId: evaluation.matchedRuleId, signals, latencyMs: Date.now() - startedAt, responseBytes });
  
  c.executionCtx.waitUntil(Promise.all([
    c.env.DB.prepare("UPDATE api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(principal.id).run(),
    coordinator(c.env, principal.workspaceId).fetch("https://coordinator/counter/increment", { method: "POST", body: JSON.stringify({ decision: "allowed" }) }),
    dispatchAnalysis({ requestEventId: eventId, requestId, workspaceId: principal.workspaceId, redactedBody: redactBody(bodyText, context.contentType).slice(0, 12_000), path: context.path, method: context.method, deterministicSignals: signals }, c.env, precomputedAi).catch(e => console.error(JSON.stringify({ message: "analysis_failed", requestEventId: eventId, error: String(e) }))),
    ...(signals.length > 0 ? [storeRequestArtifact(c.env, { workspaceId: principal.workspaceId, requestEventId: eventId, requestId, method: context.method, path: context.path, headers: redactHeaders(context.headers), body: bodyText })] : []),
  ]).then(() => undefined));

  const responseHeaders = new Headers(upstreamResponse.headers);
  responseHeaders.set("x-sentinel-request-id", requestId);
  for (const [key, value] of Object.entries(rateHeaders)) responseHeaders.set(key, value);
  return new Response(upstreamResponse.body, { status: upstreamResponse.status, headers: responseHeaders });
});

export { gateway };
