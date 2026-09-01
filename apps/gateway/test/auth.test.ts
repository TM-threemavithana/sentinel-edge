import { describe, expect, it } from "vitest";
import { encryptValue, hmacSha256 } from "../src/crypto";
import { auth } from "../src/routes/auth";

describe("auth routes", () => {
  it("exports auth hono instance", () => {
    expect(auth).toBeDefined();
  });

  // Real integration test logic would mock env.DB, env.SESSION_SECRET etc.
  it("returns 401 on missing credentials", async () => {
    const res = await auth.request("/login", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(401);
  });

  it("reuses an existing pending MFA secret across enrollment retries", async () => {
    const masterKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const secret = "JBSWY3DPEHPK3PXP";
    const ciphertext = await encryptValue(await hmacSha256(masterKey, "sentinel-edge:totp:v1"), secret);
    let writes = 0;
    const env = {
      MFA_REQUIRED: "true",
      SESSION_COOKIE: "sentinel_session",
      UPSTREAM_ENCRYPTION_KEY: masterKey,
      DB: {
        prepare(sql: string) {
          return {
            bind() {
              return {
                first: async () => {
                  if (sql.includes("FROM sessions")) return {
                    session_id: "session_test", id: "user_test", email: "admin@example.com",
                    display_name: "Admin", workspace_id: "workspace_test", workspace_name: "Test",
                    role: "admin", mfa_verified: 0,
                  };
                  if (sql.includes("SELECT mf.confirmed_at")) return {
                    confirmed_at: null, secret_ciphertext: ciphertext, auth_provider: "local",
                  };
                  throw new Error(`Unexpected query: ${sql}`);
                },
                run: async () => { writes += 1; },
              };
            },
          };
        },
      },
    } as any;
    const request = {
      method: "POST",
      headers: { cookie: "sentinel_session=test-token" },
    };

    const first = await auth.request("/mfa/enroll", request, env);
    const second = await auth.request("/mfa/enroll", request, env);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    await expect(first.json()).resolves.toMatchObject({ secret });
    await expect(second.json()).resolves.toMatchObject({ secret });
    expect(writes).toBe(0);
  });
});
