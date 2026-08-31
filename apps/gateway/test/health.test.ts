import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";

describe("health endpoint", () => {
  it("returns 503 without exposing dependency exceptions", async () => {
    const env = {
      ENVIRONMENT: "production",
      ALLOWED_ORIGINS: "https://console.example",
      DB: {},
      POLICY_CACHE: {},
      SESSION_COOKIE: "sentinel_session",
      SESSION_SECRET: "s".repeat(32),
      UPSTREAM_ENCRYPTION_KEY: "A".repeat(43),
      SESSION_TTL_SECONDS: "28800",
      MAX_INSPECTION_BYTES: "1048576",
      FREE_TIER_MODE: "true",
      MFA_REQUIRED: "true",
      EDGE_COORDINATOR: {
        idFromName: vi.fn(() => ({ toString: () => "coordinator" })),
        get: vi.fn(() => {
          throw new Error("internal durable object binding detail");
        }),
      },
    } as any;

    const response = await worker.fetch(
      new Request("https://gateway.example/health"),
      env,
      { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as any,
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ status: "error" });
  });
});
