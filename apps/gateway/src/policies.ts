import type { PolicyRule } from "@sentinel/security-core";
import type { Env } from "./env";
import type { PolicyRow } from "./types";

export async function getPolicies(env: Env, workspaceId: string): Promise<PolicyRule[]> {
  const cacheKey = `policies:${workspaceId}`;
  const cached = await env.POLICY_CACHE.get<PolicyRule[]>(cacheKey, "json");
  if (cached) return cached;

  const rows = await env.DB.prepare(
    `SELECT id, name, priority, action, conditions_json, rate_limit_json, enabled
       FROM policies WHERE workspace_id = ? ORDER BY priority ASC`,
  )
    .bind(workspaceId)
    .all<PolicyRow>();

  const policies: PolicyRule[] = rows.results.map((row) => ({
    id: row.id,
    name: row.name,
    priority: row.priority,
    action: row.action,
    enabled: row.enabled === 1,
    conditions: JSON.parse(row.conditions_json) as PolicyRule["conditions"],
    ...(row.rate_limit_json
      ? { rateLimit: JSON.parse(row.rate_limit_json) as NonNullable<PolicyRule["rateLimit"]> }
      : {}),
  }));
  await env.POLICY_CACHE.put(cacheKey, JSON.stringify(policies), { expirationTtl: 60 });
  return policies;
}

export async function invalidatePolicies(env: Env, workspaceId: string): Promise<void> {
  await env.POLICY_CACHE.delete(`policies:${workspaceId}`);
}
