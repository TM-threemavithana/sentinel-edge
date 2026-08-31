import { describe, expect, it } from "vitest";
import { gateway } from "../src/routes/gateway";

function environmentFor(scopes: string[]) {
  const statements: string[] = [];
  const env = {
    DB: {
      prepare(sql: string) {
        statements.push(sql);
        return {
          bind() {
            return {
              async first() {
                if (sql.includes("FROM api_keys")) {
                  return {
                    id: "key_test",
                    workspace_id: "ws_test",
                    name: "Test key",
                    scopes_json: JSON.stringify(scopes),
                  };
                }
                return null;
              },
            };
          },
        };
      },
    },
  } as any;
  return { env, statements };
}

describe("gateway API-key boundary", () => {
  it("rejects requests without an API key", async () => {
    const response = await gateway.request("/ups_test/v1/models", {}, {} as any);
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "unauthenticated" } });
  });

  it("rejects keys without gateway:invoke", async () => {
    const { env } = environmentFor(["analytics:read"]);
    const response = await gateway.request(
      "/ups_test/v1/models",
      { headers: { "x-sentinel-key": "sg_live_test" } },
      env,
    );
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "insufficient_scope" } });
  });

  it("continues to the handler for a valid gateway key", async () => {
    const { env, statements } = environmentFor(["gateway:invoke"]);
    const response = await gateway.request(
      "/ups_missing/v1/models",
      { headers: { authorization: "Bearer sg_live_test" } },
      env,
    );
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "upstream_not_found" } });
    expect(statements.some((sql) => sql.includes("status = 'active'"))).toBe(true);
  });
});
