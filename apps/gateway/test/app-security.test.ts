import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { assertRuntimeConfiguration } from "../src/runtime-config";

function validEnvironment() {
  return {
    ENVIRONMENT: "production",
    ALLOWED_ORIGINS: "https://console.example",
    DB: {},
    POLICY_CACHE: {},
    EDGE_COORDINATOR: {},
    SESSION_COOKIE: "sentinel_session",
    SESSION_SECRET: "s".repeat(32),
    UPSTREAM_ENCRYPTION_KEY: "A".repeat(43),
    SESSION_TTL_SECONDS: "28800",
    MAX_INSPECTION_BYTES: "1048576",
    FREE_TIER_MODE: "true",
    MFA_REQUIRED: "true",
  } as any;
}

const executionContext = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
} as any;

describe("application security middleware", () => {
  it("rejects state-changing management requests without an Origin", async () => {
    const response = await worker.fetch(
      new Request("https://gateway.example/v1/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      validEnvironment(),
      executionContext,
    );
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "invalid_origin" } });
  });

  it("requires CSRF validation for logout", async () => {
    const response = await worker.fetch(
      new Request("https://gateway.example/v1/auth/logout", {
        method: "POST",
        headers: { origin: "https://console.example" },
      }),
      validEnvironment(),
      executionContext,
    );
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "csrf_invalid" } });
  });

  it("rejects oversized management request bodies even without Content-Length", async () => {
    const response = await worker.fetch(
      new Request("https://gateway.example/v1/auth/login", {
        method: "POST",
        headers: { origin: "https://console.example", "content-type": "application/json" },
        body: JSON.stringify({ padding: "x".repeat(65_536) }),
      }),
      validEnvironment(),
      executionContext,
    );
    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "payload_too_large" } });
  });

  it("adds transport and cache protection to management responses", async () => {
    const response = await worker.fetch(
      new Request("https://gateway.example/not-found"),
      validEnvironment(),
      executionContext,
    );
    expect(response.headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

describe("runtime configuration", () => {
  it("rejects weak or missing production secrets", () => {
    expect(() => assertRuntimeConfiguration({
      ...validEnvironment(),
      SESSION_SECRET: "short",
      UPSTREAM_ENCRYPTION_KEY: "invalid",
    })).toThrow("Invalid runtime configuration");
  });

  it("permits an omitted R2 binding in free-tier mode", () => {
    expect(() => assertRuntimeConfiguration(validEnvironment())).not.toThrow();
  });

  it("requires complete Cloudflare Access configuration when Access is enforced", () => {
    expect(() => assertRuntimeConfiguration({
      ...validEnvironment(),
      ACCESS_REQUIRED: "true",
    })).toThrow("ACCESS_TEAM_DOMAIN");
  });

  it("accepts a canonical Cloudflare Access configuration", () => {
    expect(() => assertRuntimeConfiguration({
      ...validEnvironment(),
      ACCESS_REQUIRED: "true",
      ACCESS_TEAM_DOMAIN: "sentinel.cloudflareaccess.com",
      ACCESS_AUD: "0123456789abcdef0123456789abcdef",
    })).not.toThrow();
  });

  it("rejects password-only production authentication", () => {
    expect(() => assertRuntimeConfiguration({
      ...validEnvironment(),
      MFA_REQUIRED: "false",
    })).toThrow("authenticator MFA");
  });
});
