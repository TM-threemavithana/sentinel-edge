import type { NextRequest } from "next/server";
import {
  buildDemoGatewayUrl,
  DEMO_BODY_LIMIT,
  isSameOriginRequest,
  validateDemoChatPayload,
} from "@/lib/demo-chat";

export const dynamic = "force-dynamic";

type GatewayFetcher = {
  fetch(request: Request): Promise<Response>;
};

type DemoRuntime = {
  gateway: GatewayFetcher;
  gatewayOrigin: string;
  sentinelKey: string;
  upstreamId: string;
  model: string;
};

async function readBoundedJson(request: Request): Promise<unknown> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (!Number.isFinite(declared) || declared < 0 || declared > DEMO_BODY_LIMIT) throw new Error("payload_too_large");
  if (!request.body) return null;

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > DEMO_BODY_LIMIT) {
      await reader.cancel();
      throw new Error("payload_too_large");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(body));
}

async function runtime(): Promise<DemoRuntime | null> {
  if (process.env.NODE_ENV === "development") {
    const gatewayOrigin = process.env.GATEWAY_ORIGIN ?? "http://127.0.0.1:8787";
    const sentinelKey = process.env.DEMO_SENTINEL_API_KEY;
    const upstreamId = process.env.DEMO_UPSTREAM_ID;
    if (!sentinelKey || !upstreamId) return null;
    return {
      gateway: { fetch: (request) => fetch(request) },
      gatewayOrigin,
      sentinelKey,
      upstreamId,
      model: process.env.DEMO_MODEL ?? "openai/gpt-oss-20b",
    };
  }

  const { env } = await import("cloudflare:workers");
  if (!env.GATEWAY_SERVICE || !env.DEMO_SENTINEL_API_KEY || !env.DEMO_UPSTREAM_ID) return null;
  return {
    gateway: env.GATEWAY_SERVICE,
    gatewayOrigin: env.GATEWAY_ORIGIN,
    sentinelKey: env.DEMO_SENTINEL_API_KEY,
    upstreamId: env.DEMO_UPSTREAM_ID,
    model: env.DEMO_MODEL ?? "openai/gpt-oss-20b",
  };
}

function jsonError(code: string, message: string, status: number, requestId?: string | null): Response {
  return Response.json(
    { error: { code, message }, ...(requestId ? { requestId } : {}) },
    { status, headers: { "cache-control": "private, no-store", "x-content-type-options": "nosniff" } },
  );
}

export async function POST(request: NextRequest) {
  if (!isSameOriginRequest(request.url, request.headers.get("origin"))) {
    return jsonError("invalid_origin", "The request origin is not allowed", 403);
  }

  const configured = await runtime();
  if (!configured) return jsonError("demo_unavailable", "The protected demo is not configured", 503);

  const cookie = request.headers.get("cookie");
  if (!cookie) return jsonError("unauthenticated", "Sign in to use the protected demo", 401);

  const sessionRequest = new Request(new URL("/v1/auth/me", configured.gatewayOrigin), {
    headers: { cookie, "user-agent": request.headers.get("user-agent") ?? "Sentinel Edge demo" },
  });
  const sessionResponse = await configured.gateway.fetch(sessionRequest);
  if (!sessionResponse.ok) return jsonError("unauthenticated", "Your console session has expired", 401);

  let body: unknown;
  try {
    body = await readBoundedJson(request);
  } catch (error) {
    if (error instanceof Error && error.message === "payload_too_large") {
      return jsonError("payload_too_large", "Demo messages are limited to 8 KiB", 413);
    }
    return jsonError("invalid_input", "Send a valid JSON message", 422);
  }
  const payload = validateDemoChatPayload(body);
  if (!payload) return jsonError("invalid_input", "Enter a message between 1 and 2,000 characters", 422);

  let destination: URL;
  try {
    destination = buildDemoGatewayUrl(configured.gatewayOrigin, configured.upstreamId);
  } catch {
    return jsonError("demo_unavailable", "The protected demo route is invalid", 503);
  }

  const gatewayResponse = await configured.gateway.fetch(new Request(destination, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-sentinel-key": configured.sentinelKey,
      "user-agent": "Sentinel-Edge-Demo/1.0",
    },
    body: JSON.stringify({
      model: configured.model,
      messages: [{ role: "user", content: payload.message }],
      max_tokens: 400,
      temperature: 0.2,
    }),
  }));

  const requestId = gatewayResponse.headers.get("x-sentinel-request-id");
  const result = await gatewayResponse.json().catch(() => null) as {
    choices?: Array<{ message?: { content?: string } }>;
    error?: { code?: string; message?: string };
    requestId?: string;
  } | null;

  if (!gatewayResponse.ok) {
    return jsonError(
      result?.error?.code ?? "gateway_error",
      result?.error?.message ?? "Sentinel Edge rejected the request",
      gatewayResponse.status,
      result?.requestId ?? requestId,
    );
  }

  const message = result?.choices?.[0]?.message?.content?.trim();
  if (!message) return jsonError("invalid_upstream_response", "The model returned an empty response", 502, requestId);
  return Response.json(
    { message, decision: "allow", requestId, model: configured.model },
    { headers: { "cache-control": "private, no-store", "x-content-type-options": "nosniff" } },
  );
}
