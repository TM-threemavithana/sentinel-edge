import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const isDev = process.env.NODE_ENV === "development";
  const origin = process.env.GATEWAY_ORIGIN && process.env.GATEWAY_ORIGIN !== ""
    ? process.env.GATEWAY_ORIGIN
    : (isDev ? "http://127.0.0.1:8787" : "https://sentinel-edge-gateway.tharukamaduwantha62.workers.dev");
  const incoming = new URL(request.url);
  const destination = new URL(`/${path.join("/")}${incoming.search}`, origin);
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");
  const response = await fetch(destination, {
    method: request.method,
    headers,
    ...(["GET", "HEAD"].includes(request.method) ? {} : { body: await request.arrayBuffer() }),
    redirect: "manual",
    cache: "no-store",
  });
  const responseHeaders = new Headers(response.headers);
  responseHeaders.set("cache-control", "private, no-store");
  responseHeaders.delete("content-security-policy");
  return new Response(response.body, { status: response.status, headers: responseHeaders });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
