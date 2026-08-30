import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { coordinator, requireSession } from "../helpers";

const analytics = new Hono<AppBindings>();

analytics.get("/overview", requireSession(), async (c) => {
  const user = c.get("user");
  const dayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const batchResults = await c.env.DB.batch([
    c.env.DB.prepare(
      `SELECT COUNT(*) AS total_requests,
              SUM(CASE WHEN decision IN ('block', 'challenge') THEN 1 ELSE 0 END) AS blocked,
              SUM(CASE WHEN decision = 'rate_limited' THEN 1 ELSE 0 END) AS rate_limited,
              ROUND(AVG(CASE WHEN latency_ms IS NOT NULL THEN latency_ms END), 1) AS average_latency,
              ROUND(AVG(risk_score), 1) AS average_risk
         FROM request_events WHERE workspace_id = ? AND created_at >= ?`,
    ).bind(user.workspaceId, dayAgo),
    c.env.DB.prepare(
      `SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) AS bucket,
              COUNT(*) AS requests,
              SUM(CASE WHEN decision IN ('block', 'challenge') THEN 1 ELSE 0 END) AS blocked
         FROM request_events
        WHERE workspace_id = ? AND created_at >= ?
        GROUP BY bucket ORDER BY bucket ASC`,
    ).bind(user.workspaceId, dayAgo),
    c.env.DB.prepare(
      `SELECT je.value AS category, COUNT(*) AS count
         FROM request_events re, json_each(re.threat_categories_json) je
        WHERE re.workspace_id = ? AND re.created_at >= ?
        GROUP BY je.value ORDER BY count DESC LIMIT 10`,
    ).bind(user.workspaceId, dayAgo),
  ]);
  const [summaryResult, seriesResult, topThreatsResult] = batchResults;
  return c.json({ summary: summaryResult?.results[0] ?? {}, series: seriesResult?.results ?? [], topThreats: topThreatsResult?.results ?? [] });
});

analytics.get("/live", requireSession(), async (c) => {
  const res = await coordinator(c.env, c.get("user").workspaceId).fetch("https://coordinator/snapshot");
  return c.json(await res.json());
});

analytics.get("/requests", requireSession(), async (c) => {
  const user = c.get("user");
  const limit = Math.max(1, Math.min(Number(c.req.query("limit")) || 50, 200));
  const offset = Math.max(Number(c.req.query("offset")) || 0, 0);
  const decision = c.req.query("decision");
  const where = decision ? "WHERE workspace_id = ? AND decision = ?" : "WHERE workspace_id = ?";
  const binds = decision ? [user.workspaceId, decision] : [user.workspaceId];
  const rows = await c.env.DB.prepare(
    `SELECT id, request_id, method, path, status_code, decision, threat_categories_json, risk_score,
            country, latency_ms, request_bytes, response_bytes, created_at
       FROM request_events ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  ).bind(...binds, limit, offset).all();
  return c.json({ data: rows.results });
});

analytics.get("/audit", requireSession(["admin"]), async (c) => {
  const user = c.get("user");
  const limit = Math.max(1, Math.min(Number(c.req.query("limit")) || 50, 200));
  const offset = Math.max(Number(c.req.query("offset")) || 0, 0);
  const rows = await c.env.DB.prepare(
    `SELECT id, actor_type, actor_id, action, resource_type, resource_id, metadata_json, created_at
       FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  ).bind(user.workspaceId, limit, offset).all();
  return c.json({ data: rows.results });
});

export { analytics };
