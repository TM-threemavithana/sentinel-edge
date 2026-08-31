import { describe, expect, it } from "vitest";
import { authenticateSession } from "../src/auth";

function environment(mfaVerified: number) {
  return {
    MFA_REQUIRED: "true",
    SESSION_COOKIE: "sentinel_session",
    DB: {
      prepare() {
        return {
          bind() {
            return {
              first: async () => ({
                session_id: "session_test",
                id: "user_test",
                email: "admin@example.com",
                display_name: "Admin",
                workspace_id: "workspace_test",
                workspace_name: "Test",
                role: "admin",
                mfa_verified: mfaVerified,
              }),
            };
          },
        };
      },
    },
  } as any;
}

const request = new Request("https://gateway.example/v1/auth/me", {
  headers: { cookie: "sentinel_session=test-token" },
});

describe("MFA session boundary", () => {
  it("blocks a password-only session from normal APIs", async () => {
    await expect(authenticateSession(request, environment(0))).resolves.toBeNull();
  });

  it("allows the restricted session only for enrollment", async () => {
    await expect(authenticateSession(request, environment(0), { allowUnverified: true })).resolves.toMatchObject({ id: "user_test" });
  });

  it("allows a fully verified session", async () => {
    await expect(authenticateSession(request, environment(1))).resolves.toMatchObject({ sessionId: "session_test" });
  });
});
