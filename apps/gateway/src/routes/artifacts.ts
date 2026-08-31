import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { errorResponse, requireSession } from "../helpers";

const artifacts = new Hono<AppBindings>();

artifacts.get("/:id", requireSession(["admin", "analyst"]), async (c) => {
  if (!c.env.ARTIFACTS) {
    return errorResponse("artifact_storage_disabled", "Artifact storage is disabled", 503);
  }
  const row = await c.env.DB.prepare(
    `SELECT object_key, content_type FROM artifact_metadata WHERE id = ? AND workspace_id = ?`,
  ).bind(c.req.param("id"), c.get("user").workspaceId).first<{ object_key: string; content_type: string }>();
  if (!row) return errorResponse("not_found", "Artifact not found", 404);
  const object = await c.env.ARTIFACTS.get(row.object_key);
  if (!object) return errorResponse("not_found", "Artifact object is missing", 404);
  return new Response(object.body, {
    headers: {
      "content-type": row.content_type,
      "content-disposition": `attachment; filename="${row.object_key.split("/").at(-1) ?? "report.json"}"`,
      "cache-control": "private, no-store",
    },
  });
});

export { artifacts };
