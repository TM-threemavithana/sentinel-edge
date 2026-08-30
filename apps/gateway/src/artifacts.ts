import { redactHeaders, redactBody } from "@sentinel/security-core";
import type { Env } from "./env";
import { sha256 } from "./crypto";

export async function storeRequestArtifact(
  env: Env,
  input: {
    workspaceId: string;
    requestEventId: string;
    requestId: string;
    method: string;
    path: string;
    headers: Record<string, string>;
    body: string;
    retentionDays?: number;
  },
): Promise<string> {
  if (env.FREE_TIER_MODE === "true") return "";
  const key = `${input.workspaceId}/requests/${new Date().toISOString().slice(0, 10)}/${input.requestId}.json`;
  const document = JSON.stringify(
    {
      requestId: input.requestId,
      capturedAt: new Date().toISOString(),
      method: input.method,
      path: input.path,
      headers: redactHeaders(input.headers),
      body: redactBody(input.body, input.headers["content-type"] || ""),
    },
    null,
    2,
  );
  const bytes = new TextEncoder().encode(document);
  const checksum = await sha256(bytes);
  await env.ARTIFACTS.put(key, bytes, {
    httpMetadata: { contentType: "application/json" },
    customMetadata: { workspaceId: input.workspaceId, requestEventId: input.requestEventId, sha256: checksum },
  });
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO artifact_metadata
        (id, workspace_id, object_key, kind, content_type, size_bytes, sha256, request_event_id, expires_at)
       VALUES (?, ?, ?, 'request_sample', 'application/json', ?, ?, ?, datetime('now', '+${input.retentionDays || 30} days'))`,
    ).bind(crypto.randomUUID(), input.workspaceId, key, bytes.byteLength, checksum, input.requestEventId),
    env.DB.prepare("UPDATE request_events SET artifact_key = ? WHERE id = ?").bind(key, input.requestEventId),
  ]);
  return key;
}

export async function storeAnalysisReport(
  env: Env,
  input: {
    workspaceId: string;
    requestEventId: string;
    requestId: string;
    report: unknown;
    retentionDays?: number;
  },
): Promise<string> {
  if (env.FREE_TIER_MODE === "true") return "";
  const key = `${input.workspaceId}/analysis/${new Date().toISOString().slice(0, 10)}/${input.requestId}.json`;
  const bytes = new TextEncoder().encode(JSON.stringify(input.report, null, 2));
  const checksum = await sha256(bytes);
  await env.ARTIFACTS.put(key, bytes, {
    httpMetadata: { contentType: "application/json" },
    customMetadata: { workspaceId: input.workspaceId, requestEventId: input.requestEventId, sha256: checksum },
  });
  await env.DB.prepare(
    `INSERT INTO artifact_metadata
      (id, workspace_id, object_key, kind, content_type, size_bytes, sha256, request_event_id, expires_at)
     VALUES (?, ?, ?, 'analysis_report', 'application/json', ?, ?, ?, datetime('now', '+${input.retentionDays || 30} days'))`,
  )
    .bind(crypto.randomUUID(), input.workspaceId, key, bytes.byteLength, checksum, input.requestEventId)
    .run();
  return key;
}
