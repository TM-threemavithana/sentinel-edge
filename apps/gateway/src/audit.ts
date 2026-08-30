import { redactJson } from "@sentinel/security-core";
import type { Env } from "./env";
import { hmacSha256 } from "./crypto";

export async function writeAudit(
  env: Env,
  input: {
    workspaceId: string;
    actorType: "user" | "api_key" | "system";
    actorId: string | null;
    action: string;
    resourceType: string;
    resourceId: string | null;
    metadata?: unknown;
    request?: Request;
    requestId?: string;
  },
): Promise<void> {
  const ip = input.request?.headers.get("cf-connecting-ip");
  const ipHash = ip ? await hmacSha256(env.SESSION_SECRET, ip) : null;
  await env.DB.prepare(
    `INSERT INTO audit_events
      (id, workspace_id, actor_type, actor_id, action, resource_type, resource_id, metadata_json, ip_hash, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      input.workspaceId,
      input.actorType,
      input.actorId,
      input.action,
      input.resourceType,
      input.resourceId,
      JSON.stringify(redactJson(input.metadata ?? {})),
      ipHash,
      input.requestId ?? null,
    )
    .run();
}
