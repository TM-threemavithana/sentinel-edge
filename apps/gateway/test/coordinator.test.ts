import { describe, expect, it, beforeEach } from "vitest";

// Minimal mock of DurableObjectState storage
function createMockStorage() {
  const data = new Map<string, unknown>();
  let alarm: number | null = null;
  return {
    get: async <T>(key: string) => data.get(key) as T | undefined,
    put: async (key: string, value: unknown) => { data.set(key, value); },
    delete: async (key: string) => data.delete(key),
    list: async <T>(opts: { prefix: string }) => {
      const result = new Map<string, T>();
      for (const [k, v] of data.entries()) {
        if (k.startsWith(opts.prefix)) result.set(k, v as T);
      }
      return result;
    },
    setAlarm: async (ms: number) => { alarm = ms; },
    getAlarm: () => alarm,
    _data: data,
  };
}

// We test the coordinator logic directly by importing and instantiating
// Since EdgeCoordinator uses DurableObjectState, we mock it
describe("EdgeCoordinator", () => {
  let storage: ReturnType<typeof createMockStorage>;
  let coordinator: any;

  beforeEach(async () => {
    storage = createMockStorage();
    // Dynamically import to get the class
    const mod = await import("../src/coordinator");
    coordinator = new mod.EdgeCoordinator(
      { storage } as any,
      { ENVIRONMENT: "production" } as any,
    );
  });

  describe("rate limiting", () => {
    it("allows requests under the limit", async () => {
      const req = new Request("https://coordinator/rate-limit", {
        method: "POST",
        body: JSON.stringify({ key: "test-key", limit: 5, windowSeconds: 60 }),
      });
      const res = await coordinator.fetch(req);
      const body = await res.json();
      expect(body.allowed).toBe(true);
      expect(body.remaining).toBe(4);
    });

    it("rejects requests over the limit", async () => {
      for (let i = 0; i < 3; i++) {
        await coordinator.fetch(new Request("https://coordinator/rate-limit", {
          method: "POST",
          body: JSON.stringify({ key: "test-key", limit: 3, windowSeconds: 60 }),
        }));
      }
      const res = await coordinator.fetch(new Request("https://coordinator/rate-limit", {
        method: "POST",
        body: JSON.stringify({ key: "test-key", limit: 3, windowSeconds: 60 }),
      }));
      const body = await res.json();
      expect(body.allowed).toBe(false);
      expect(body.remaining).toBe(0);
    });
  });

  describe("counter increment", () => {
    it("increments request count for allowed decisions", async () => {
      await coordinator.fetch(new Request("https://coordinator/counter/increment", {
        method: "POST", body: JSON.stringify({ decision: "allowed" }),
      }));
      const snapshot = await coordinator.fetch(new Request("https://coordinator/snapshot"));
      const body = await snapshot.json();
      expect(body.live.requests).toBe(1);
      expect(body.live.blocked).toBe(0);
    });

    it("increments blocked count for blocked decisions", async () => {
      await coordinator.fetch(new Request("https://coordinator/counter/increment", {
        method: "POST", body: JSON.stringify({ decision: "blocked" }),
      }));
      const snapshot = await coordinator.fetch(new Request("https://coordinator/snapshot"));
      const body = await snapshot.json();
      expect(body.live.requests).toBe(1);
      expect(body.live.blocked).toBe(1);
    });

    it("increments blocked count for rate_limited decisions", async () => {
      await coordinator.fetch(new Request("https://coordinator/counter/increment", {
        method: "POST", body: JSON.stringify({ decision: "rate_limited" }),
      }));
      const snapshot = await coordinator.fetch(new Request("https://coordinator/snapshot"));
      const body = await snapshot.json();
      expect(body.live.blocked).toBe(1);
    });
  });

  describe("presence", () => {
    it("tracks active users via touch", async () => {
      await coordinator.fetch(new Request("https://coordinator/presence/touch", {
        method: "POST", body: JSON.stringify({ userId: "user-1" }),
      }));
      const snapshot = await coordinator.fetch(new Request("https://coordinator/snapshot"));
      const body = await snapshot.json();
      expect(body.activeUsers).toBe(1);
    });
  });

  describe("alarm cleanup", () => {
    it("cleans up expired presence entries", async () => {
      // Manually set an expired presence entry
      await storage.put("presence:expired-user", Date.now() - 1000);
      await coordinator.alarm();
      const presence = await storage.list({ prefix: "presence:" });
      expect(presence.size).toBe(0);
    });
  });
});
