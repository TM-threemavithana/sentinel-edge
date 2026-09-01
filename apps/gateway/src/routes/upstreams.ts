import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { errorResponse, requireSession } from "../helpers";
import { encryptValue } from "../crypto";
import { writeAudit } from "../audit";
import { readJsonBody, upstreamSchema } from "../validation";

const upstreams = new Hono<AppBindings>();

export function isDuplicateUpstreamNameError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes("UNIQUE constraint failed: upstreams.workspace_id, upstreams.name");
}

upstreams.get("/", requireSession(), async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, base_url, auth_header_name, timeout_ms, status, created_at
       FROM upstreams WHERE workspace_id = ? ORDER BY name ASC`,
  ).bind(c.get("user").workspaceId).all();
  return c.json({ data: rows.results });
});

upstreams.post("/", requireSession(["admin"]), async (c) => {
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const parsed = upstreamSchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid upstream", 422);
  const user = c.get("user");
  const id = crypto.randomUUID();
  const encrypted = parsed.data.authValue
    ? await encryptValue(c.env.UPSTREAM_ENCRYPTION_KEY, parsed.data.authValue)
    : null;
  try {
    await c.env.DB.prepare(
      `INSERT INTO upstreams (id, workspace_id, name, base_url, auth_header_name, encrypted_auth_value, timeout_ms, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, user.workspaceId, parsed.data.name, parsed.data.baseUrl.replace(/\/$/u, ""),
      parsed.data.authHeaderName.toLowerCase(), encrypted, parsed.data.timeoutMs, user.id).run();
  } catch (error) {
    if (isDuplicateUpstreamNameError(error)) {
      return errorResponse("upstream_name_conflict", "An upstream with this name already exists", 409);
    }
    throw error;
  }
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "upstream.created",
    resourceType: "upstream", resourceId: id, metadata: { name: parsed.data.name, baseUrl: parsed.data.baseUrl },
    request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ id, name: parsed.data.name, baseUrl: parsed.data.baseUrl }, 201);
});

export { upstreams };
