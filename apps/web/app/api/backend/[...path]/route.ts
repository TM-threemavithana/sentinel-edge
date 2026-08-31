import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

const FORWARDED_RESPONSE_HEADERS = [
  "content-disposition",
  "content-language",
  "content-type",
  "retry-after",
  "x-request-id",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "x-ratelimit-reset",
] as const;

const ACTIVE_CONTENT_TYPES = new Set([
  "application/xhtml+xml",
  "application/xml",
  "image/svg+xml",
  "text/html",
  "text/xml",
]);

const MANAGEMENT_BODY_LIMIT = 64 * 1024;
const GATEWAY_BODY_LIMIT = 1024 * 1024;

export type BoundedBodyResult =
  | { ok: true; body: Uint8Array }
  | { ok: false; reason: "too_large" };

export async function readBoundedRequestBody(request: Request, limit: number): Promise<BoundedBodyResult> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const value = Number(declaredLength);
    if (!Number.isSafeInteger(value) || value < 0 || value > limit) return { ok: false, reason: "too_large" };
  }
  if (!request.body) return { ok: true, body: new Uint8Array() };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > limit) {
      await reader.cancel();
      return { ok: false, reason: "too_large" };
    }
    chunks.push(value);
  }

  const body = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, body };
}

export function buildGatewayDestination(path: string[], requestUrl: string, configuredOrigin: string): URL {
  const gatewayOrigin = new URL(configuredOrigin);
  const originIsCanonical =
    (gatewayOrigin.protocol === "https:" || gatewayOrigin.protocol === "http:") &&
    gatewayOrigin.pathname === "/" &&
    gatewayOrigin.search === "" &&
    gatewayOrigin.hash === "" &&
    gatewayOrigin.username === "" &&
    gatewayOrigin.password === "";

  if (!originIsCanonical) throw new Error("invalid_gateway_origin");
  if (
    path.length === 0 ||
    path.some((segment) =>
      segment.length === 0 ||
      segment === "." ||
      segment === ".." ||
      segment.includes("/") ||
      segment.includes("\\") ||
      segment.includes("\0"),
    )
  ) {
    throw new Error("invalid_backend_path");
  }

  const incoming = new URL(requestUrl);
  const destination = new URL(gatewayOrigin.origin);
  destination.pathname = `/${path.map((segment) => encodeURIComponent(segment)).join("/")}`;
  destination.search = incoming.search;
  if (destination.origin !== gatewayOrigin.origin) throw new Error("invalid_backend_destination");
  return destination;
}

export function buildSafeResponseHeaders(upstreamHeaders: Headers): Headers {
  const headers = new Headers();
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = upstreamHeaders.get(name);
    if (value) headers.set(name, value);
  }
  const cookieHeaders = typeof upstreamHeaders.getSetCookie === "function"
    ? upstreamHeaders.getSetCookie()
    : (upstreamHeaders.get("set-cookie") ? [upstreamHeaders.get("set-cookie")!] : []);
  for (const cookie of cookieHeaders) headers.append("set-cookie", cookie);

  const contentType = headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (!contentType || ACTIVE_CONTENT_TYPES.has(contentType)) {
    headers.set("content-type", "application/octet-stream");
    headers.set("content-disposition", "attachment");
  }
  headers.set("cache-control", "private, no-store");
  headers.set("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox");
  headers.set("x-content-type-options", "nosniff");
  return headers;
}

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const isDev = process.env.NODE_ENV === "development";
  const origin = process.env.GATEWAY_ORIGIN || (isDev ? "http://127.0.0.1:8787" : "");
  if (!origin) {
    return Response.json({ error: { code: "gateway_not_configured", message: "The backend gateway is not configured" } }, { status: 503 });
  }
  let destination: URL;
  try {
    destination = buildGatewayDestination(path, request.url, origin);
  } catch {
    return Response.json({ error: { code: "invalid_backend_path", message: "The backend path is invalid" } }, { status: 400 });
  }
  const headers = new Headers(request.headers);
  for (const name of ["host", "content-length", "connection", "transfer-encoding", "upgrade"]) {
    headers.delete(name);
  }
  let body: Uint8Array | undefined;
  if (!["GET", "HEAD"].includes(request.method)) {
    const limit = path[0] === "v1" && path[1] === "gateway" ? GATEWAY_BODY_LIMIT : MANAGEMENT_BODY_LIMIT;
    const bounded = await readBoundedRequestBody(request, limit);
    if (!bounded.ok) {
      return Response.json(
        { error: { code: "payload_too_large", message: `Request body exceeds ${limit / 1024} KiB` } },
        { status: 413, headers: { "cache-control": "private, no-store", "x-content-type-options": "nosniff" } },
      );
    }
    body = bounded.body;
  }
  const gatewayRequest = new Request(destination, {
    method: request.method,
    headers,
    ...(body && body.byteLength > 0
      ? { body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer }
      : {}),
    redirect: "manual",
  });
  let response: Response;
  if (isDev) {
    response = await fetch(gatewayRequest);
  } else {
    const { env } = await import("cloudflare:workers");
    const gateway = env.GATEWAY_SERVICE;
    if (!gateway) {
      return Response.json({ error: { code: "gateway_not_configured", message: "The backend gateway service is not configured" } }, { status: 503 });
    }
    response = await gateway.fetch(gatewayRequest);
  }
  const responseHeaders = buildSafeResponseHeaders(response.headers);
  return new Response(response.body, { status: response.status, headers: responseHeaders });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
