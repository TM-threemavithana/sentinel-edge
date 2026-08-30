import { Hono } from "hono";
import { evaluatePolicies, inspectRequest, redactHeaders, redactText, type RequestContext, type ThreatSignal } from "@sentinel/security-core";
import type { AppBindings } from "../helpers";
import type { Env } from "../env";
import type { AnalysisMessage } from "../types";
import { coordinator, errorResponse, headersRecord, recordRequest } from "../helpers";
import { authenticateApiKey } from "../auth";
import { decryptValue } from "../crypto";
import { getPolicies } from "../policies";
import { classifyThreat } from "../ai";
import { storeAnalysisReport, storeRequestArtifact } from "../artifacts";

const gateway = new Hono<AppBindings>();

gateway.all("/:upstreamId/*", async (c) => {
  const startedAt = Date.now();
  const requestId = c.get("requestId");
  const eventId = crypto.randomUUID();
  const url = new URL(c.req.url);

  const principal = await authenticateApiKey(c.req.raw, c.env);
  if (!principal) return errorResponse("unauthenticated", "Provide a valid API key via x-sentinel-key or Authorization header", 401);
  if (!principal.scopes.includes("gateway:invoke")) return errorResponse("forbidden", "This key does not have gateway:invoke scope", 403);

  const upstream = await c.env.DB.prepare(
    `SELECT id, base_url, auth_header_name, encrypted_auth_value, timeout_ms
       FROM upstreams WHERE id = ? AND workspace_id = ? AND status = 'active'`,
  ).bind(c.req.param("upstreamId"), principal.workspaceId)
    .first<{ id: string; base_url: string; auth_header_name: string; encrypted_auth_value: string | null; timeout_ms: number }>();
  if (!upstream) return errorResponse("upstream_not_found", "The specified upstream is not configured or active", 404);

  const maxBytes = Number(c.env.MAX_INSPECTION_BYTES) || 1_048_576;
  const bodyBytes = await c.req.arrayBuffer();
  const bodyText = new TextDecoder().decode(bodyBytes).slice(0, maxBytes);
  const clientIp = c.req.header("cf-connecting-ip");
  const country = c.req.header("cf-ipcountry");
  const context: RequestContext = {
    method: c.req.method, path: url.pathname, headers: headersRecord(c.req.raw.headers),
    query: Object.fromEntries(url.searchParams), bodyText,
    contentType: c.req.header("content-type") ?? "", contentLength: bodyBytes.byteLength,
    ...(clientIp ? { clientIp } : {}),
    ...(country ? { country } : {}),
  };

  let signals: ThreatSignal[] = inspectRequest(context, maxBytes);

  if (c.env.FREE_TIER_MODE !== "true" && c.env.AI_MODE === "inline" && signals.length === 0 && bodyText.length > 0) {
    try {
      const ai = await classifyThreat(c.env, { method: context.method, path: context.path, redactedBody: redactText(bodyText), deterministicSignals: signals });
      if (ai.confidence >= 0.85 && ai.recommendedAction === "block") {
        signals = [...signals, { category: ai.category, confidence: ai.confidence, source: "workers_ai", severity: "high", summary: ai.explanation }];
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

  if (context.contentLength > maxBytes) decision = "block";
  if (decision === "block" || decision === "challenge" || decision === "rate_limited") {
    const status = decision === "rate_limited" ? 429 : decision === "challenge" ? 403 : context.contentLength > maxBytes ? 413 : 403;
    await recordRequest(c.env, { eventId, workspaceId: principal.workspaceId, apiKeyId: principal.id, upstreamId: upstream.id, requestId, context, statusCode: status, decision, policyId: evaluation.matchedRuleId, signals, latencyMs: Date.now() - startedAt, responseBytes: null });
    c.executionCtx.waitUntil(Promise.all([
      coordinator(c.env, principal.workspaceId).fetch("https://coordinator/counter/increment", { method: "POST", body: JSON.stringify({ decision: decision === "rate_limited" ? "rate_limited" : "blocked" }) }).then(() => undefined),
      storeRequestArtifact(c.env, { workspaceId: principal.workspaceId, requestEventId: eventId, requestId, method: context.method, path: context.path, headers: context.headers, body: bodyText }).then(() => undefined),
      processAnalysis({ requestEventId: eventId, requestId, workspaceId: principal.workspaceId, redactedBody: redactText(bodyText), path: context.path, method: context.method, deterministicSignals: signals }, c.env).catch(e => console.error(JSON.stringify({ message: "analysis_failed", requestEventId: eventId, error: String(e) }))),
    ]).then(() => undefined));
    return new Response(JSON.stringify({ error: { code: decision, message: evaluation.reason }, requestId }), { status, headers: { "content-type": "application/json", ...rateHeaders } });
  }

  const prefix = `/v1/gateway/${c.req.param("upstreamId")}`;
  let upstreamPath = url.pathname.slice(prefix.length);
  if (!upstreamPath.startsWith("/")) upstreamPath = "/" + upstreamPath;
  const destination = new URL(upstreamPath + url.search, upstream.base_url);
  const forwardHeaders = new Headers(c.req.raw.headers);
  for (const header of ["host", "cookie", "authorization", "x-sentinel-key", "cf-connecting-ip", "cf-ipcountry", "content-length"]) forwardHeaders.delete(header);
  if (upstream.encrypted_auth_value) forwardHeaders.set(upstream.auth_header_name, await decryptValue(c.env.UPSTREAM_ENCRYPTION_KEY, upstream.encrypted_auth_value));
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
    processAnalysis({ requestEventId: eventId, requestId, workspaceId: principal.workspaceId, redactedBody: redactText(bodyText), path: context.path, method: context.method, deterministicSignals: signals }, c.env).catch(e => console.error(JSON.stringify({ message: "analysis_failed", requestEventId: eventId, error: String(e) }))),
    ...(signals.length > 0 ? [storeRequestArtifact(c.env, { workspaceId: principal.workspaceId, requestEventId: eventId, requestId, method: context.method, path: context.path, headers: redactHeaders(context.headers), body: bodyText })] : []),
  ]).then(() => undefined));

  const responseHeaders = new Headers(upstreamResponse.headers);
  responseHeaders.set("x-sentinel-request-id", requestId);
  for (const [key, value] of Object.entries(rateHeaders)) responseHeaders.set(key, value);
  return new Response(upstreamResponse.body, { status: upstreamResponse.status, headers: responseHeaders });
});

async function processAnalysis(input: AnalysisMessage, env: Env): Promise<void> {
  const classification = await classifyThreat(env, { method: input.method, path: input.path, redactedBody: input.redactedBody, deterministicSignals: input.deterministicSignals });
  const report = { requestId: input.requestId, generatedAt: new Date().toISOString(), model: env.AI_MODEL, classification, deterministicSignals: input.deterministicSignals, handling: "Request content was redacted and truncated before analysis." };
  const artifactKey = await storeAnalysisReport(env, { workspaceId: input.workspaceId, requestEventId: input.requestEventId, requestId: input.requestId, report });
  await env.DB.prepare(
    `INSERT INTO analysis_results (id, request_event_id, model, category, confidence, explanation, recommended_action, artifact_key)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(request_event_id) DO UPDATE SET
       model = excluded.model, category = excluded.category, confidence = excluded.confidence,
       explanation = excluded.explanation, recommended_action = excluded.recommended_action, artifact_key = excluded.artifact_key`,
  ).bind(crypto.randomUUID(), input.requestEventId, env.AI_MODEL, classification.category, classification.confidence, classification.explanation, classification.recommendedAction, artifactKey).run();
}

export { gateway };
