import { Hono } from "hono";
import { cors } from "hono/cors";
import type { AppBindings } from "./helpers";
import { allowedOrigins, errorResponse } from "./helpers";
import { validateCsrf } from "./csrf";
import { auth } from "./routes/auth";
import { apiKeys } from "./routes/api-keys";
import { policies } from "./routes/policies";
import { upstreams } from "./routes/upstreams";
import { analytics } from "./routes/analytics";
import { artifacts } from "./routes/artifacts";
import { gateway } from "./routes/gateway";
import { EdgeCoordinator } from "./coordinator";

const app = new Hono<AppBindings>();

// ── Global middleware ──────────────────────────────────────────────
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

// ── CORS ───────────────────────────────────────────────────────────
app.use("/v1/*", cors({
  origin: (origin, c) => {
    const allowed = allowedOrigins(c.env);
    return (origin && allowed.has(origin)) ? origin : null;
  },
  credentials: true,
}));

// ── CSRF + Origin validation on mutations ─────────────────────────
app.use("/v1/*", async (c, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(c.req.method) || c.req.path.startsWith("/v1/gateway/")) {
    await next();
    return;
  }
  const origin = c.req.header("origin");
  if (origin && !allowedOrigins(c.env).has(origin)) {
    return errorResponse("invalid_origin", "The request origin is not allowed", 403);
  }
  if (!c.req.path.startsWith("/v1/auth/") && !validateCsrf(c.req.raw)) {
    return errorResponse("csrf_invalid", "Missing or invalid CSRF token", 403);
  }
  await next();
});

// ── Error handler ─────────────────────────────────────────────────
app.onError((error, c) => {
  console.error(JSON.stringify({ requestId: c.get("requestId"), error: error.message, stack: error.stack }));
  return errorResponse("internal_error", "The gateway could not complete the request", 500);
});

// ── Health check ──────────────────────────────────────────────────
app.get("/health", async (c) => {
  try {
    const { coordinator } = await import("./helpers");
    const res = await coordinator(c.env, "auth").fetch("https://coordinator/snapshot");
    const json = await res.json();
    return c.json({ status: "ok", coordinator: json });
  } catch (e: any) {
    return c.json({ status: "error", error: e.message, stack: e.stack });
  }
});

// ── Route modules ─────────────────────────────────────────────────
app.route("/v1/auth", auth);
app.route("/v1/api-keys", apiKeys);
app.route("/v1/policies", policies);
app.route("/v1/upstreams", upstreams);
app.route("/v1/analytics", analytics);
app.route("/v1/artifacts", artifacts);
app.route("/v1/gateway", gateway);

export default {
  fetch: app.fetch,
  scheduled: async (event: any, env: any, ctx: any) => {
    ctx.waitUntil((async () => {
      const expired = await env.DB.prepare("SELECT object_key FROM artifact_metadata WHERE expires_at < datetime('now') LIMIT 500").all();
      if (!expired.results || expired.results.length === 0) return;
      const keys = expired.results.map((r: any) => r.object_key);
      await env.ARTIFACTS.delete(keys);
      const marks = keys.map(() => "?").join(",");
      await env.DB.prepare(`DELETE FROM artifact_metadata WHERE object_key IN (${marks})`).bind(...keys).run();
    })());
  }
};

export { EdgeCoordinator };
