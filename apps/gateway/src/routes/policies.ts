import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { errorResponse, requireSession } from "../helpers";
import { writeAudit } from "../audit";
import { invalidatePolicies } from "../policies";
import { policySchema, policyPatchSchema, readJsonBody } from "../validation";

const policies = new Hono<AppBindings>();

policies.get("/", requireSession(), async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, description, priority, action, conditions_json, rate_limit_json, enabled, version, updated_at
       FROM policies WHERE workspace_id = ? ORDER BY priority ASC`,
  ).bind(c.get("user").workspaceId).all();
  return c.json({ data: rows.results });
});

policies.post("/", requireSession(["admin", "analyst"]), async (c) => {
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const parsed = policySchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid policy", 422);
  const user = c.get("user");
  const id = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO policies (id, workspace_id, name, description, priority, action, conditions_json, rate_limit_json, enabled, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, user.workspaceId, parsed.data.name, parsed.data.description, parsed.data.priority,
      parsed.data.action, JSON.stringify(parsed.data.conditions),
      parsed.data.rateLimit ? JSON.stringify(parsed.data.rateLimit) : null,
      parsed.data.enabled ? 1 : 0, user.id).run();
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

policies.patch("/:id", requireSession(["admin", "analyst"]), async (c) => {
  const user = c.get("user");
  const current = await c.env.DB.prepare(
    `SELECT id, name, description, priority, action, conditions_json, rate_limit_json, enabled
       FROM policies WHERE id = ? AND workspace_id = ?`,
  ).bind(c.req.param("id"), user.workspaceId).first<Record<string, unknown>>();
  if (!current) return errorResponse("not_found", "Policy not found", 404);
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const patch = body.success ? body.data : null;
  const parsed = policyPatchSchema.safeParse({ ...(patch as object), id: c.req.param("id") });
  if (!parsed.success) return errorResponse("invalid_input", parsed.error.issues[0]?.message ?? "Invalid policy", 422);
  const merged = policySchema.parse({
    name: current.name, description: current.description, priority: current.priority, action: current.action,
    conditions: JSON.parse(String(current.conditions_json)),
    rateLimit: current.rate_limit_json ? JSON.parse(String(current.rate_limit_json)) : null,
    enabled: current.enabled === 1, ...parsed.data,
  });
  await c.env.DB.prepare(
    `UPDATE policies SET name = ?, description = ?, priority = ?, action = ?, conditions_json = ?,
       rate_limit_json = ?, enabled = ?, version = version + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ? AND workspace_id = ?`,
  ).bind(merged.name, merged.description, merged.priority, merged.action, JSON.stringify(merged.conditions),
    merged.rateLimit ? JSON.stringify(merged.rateLimit) : null, merged.enabled ? 1 : 0,
    c.req.param("id"), user.workspaceId).run();
  await invalidatePolicies(c.env, user.workspaceId);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "policy.updated",
    resourceType: "policy", resourceId: c.req.param("id"), metadata: { name: merged.name }, request: c.req.raw,
    requestId: c.get("requestId"),
  }));
  return c.json({ id: c.req.param("id"), ...merged });
});

export { policies };
