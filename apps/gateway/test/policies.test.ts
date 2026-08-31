import { describe, expect, it, vi } from "vitest";
import { getPolicies } from "../src/policies";

describe("policy loading", () => {
  it("parses the schema JSON columns and writes the canonical cache key", async () => {
    const put = vi.fn(async () => undefined);
    const env = {
      POLICY_CACHE: {
        get: vi.fn(async () => null),
        put,
      },
      DB: {
        prepare: vi.fn(() => ({
          bind: vi.fn(() => ({
            all: vi.fn(async () => ({
              results: [{
                id: "pol_test",
                name: "Test policy",
                priority: 10,
                action: "block",
                conditions_json: '[{"field":"path","operator":"starts_with","value":"/admin"}]',
                rate_limit_json: '{"requests":10,"windowSeconds":60,"keyBy":"api_key"}',
                enabled: 1,
              }],
            })),
          })),
        })),
      },
    } as any;

    const policies = await getPolicies(env, "ws_test");

    expect(policies).toEqual([expect.objectContaining({
      id: "pol_test",
      enabled: true,
      conditions: [{ field: "path", operator: "starts_with", value: "/admin" }],
      rateLimit: { requests: 10, windowSeconds: 60, keyBy: "api_key" },
    })]);
    expect(put).toHaveBeenCalledWith("policies:ws_test", expect.any(String), { expirationTtl: 60 });
  });
});
