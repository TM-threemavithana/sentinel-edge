import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { errorResponse, requireSession } from "../helpers";
import { randomToken, sha256 } from "../crypto";
import { writeAudit } from "../audit";
import { apiKeySchema, readJsonBody } from "../validation";

const apiKeys = new Hono<AppBindings>();

apiKeys.get("/", requireSession(), async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, key_prefix, scopes_json, status, expires_at, last_used_at, created_at
       FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC`,
  ).bind(c.get("user").workspaceId).all();
  return c.json({ data: rows.results });
});

apiKeys.post("/", requireSession(["admin"]), async (c) => {
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const parsed = apiKeySchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid API key", 422);
  const user = c.get("user");
  const id = crypto.randomUUID();
  const rawKey = "sg_live_" + randomToken(32);
  const keyHash = await sha256(rawKey);
  await c.env.DB.prepare(
    `INSERT INTO api_keys (id, workspace_id, name, key_prefix, key_hash, scopes_json, expires_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(id, user.workspaceId, parsed.data.name, rawKey.slice(0, 16), keyHash,
    JSON.stringify(parsed.data.scopes), parsed.data.expiresAt ?? null, user.id).run();
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "api_key.created",
    resourceType: "api_key", resourceId: id, metadata: { name: parsed.data.name, scopes: parsed.data.scopes },
    request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ id, name: parsed.data.name, key: rawKey, prefix: rawKey.slice(0, 16) }, 201);
});

apiKeys.delete("/:id", requireSession(["admin"]), async (c) => {
  const user = c.get("user");
  const result = await c.env.DB.prepare(
    `UPDATE api_keys SET status = 'revoked', revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ? AND workspace_id = ? AND status = 'active'`,
  ).bind(c.req.param("id"), user.workspaceId).run();
  if (!result.meta.changes) return errorResponse("not_found", "Active API key not found", 404);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "api_key.revoked",
    resourceType: "api_key", resourceId: c.req.param("id"), request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ ok: true });
});

export { apiKeys };
