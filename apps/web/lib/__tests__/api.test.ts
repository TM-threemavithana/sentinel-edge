import { describe, expect, it, vi, beforeEach } from "vitest";
import { apiFetch, ApiError, setCsrfToken } from "../api";

describe("apiFetch", () => {
  beforeEach(() => {
    vi.stubGlobal("process", { env: { NEXT_PUBLIC_GATEWAY_ORIGIN: "https://test-gateway.example.com", NODE_ENV: "test" } });
  });

  it("throws ApiError on non-OK responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: { code: "unauthenticated", message: "Sign in" } }),
    }));
    await expect(apiFetch("/v1/auth/me")).rejects.toThrow(ApiError);
    await expect(apiFetch("/v1/auth/me")).rejects.toMatchObject({ status: 401, code: "unauthenticated" });
  });

  it("includes credentials in requests", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true, status: 200, json: async () => ({ data: [] }),
    });
    vi.stubGlobal("fetch", mockFetch);
    await apiFetch("/v1/api-keys");
    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("attaches CSRF token on mutations", async () => {
    setCsrfToken("test-csrf-token");
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true, status: 201, json: async () => ({ id: "123" }),
    });
    vi.stubGlobal("fetch", mockFetch);
    await apiFetch("/v1/api-keys", { method: "POST", body: "{}" });
    const calledHeaders = mockFetch.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(calledHeaders["x-csrf-token"]).toBe("test-csrf-token");
  });

  it("does not attach CSRF token on GET requests", async () => {
    setCsrfToken("test-csrf-token");
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true, status: 200, json: async () => ({ data: [] }),
    });
    vi.stubGlobal("fetch", mockFetch);
    await apiFetch("/v1/api-keys");
    const calledHeaders = mockFetch.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(calledHeaders["x-csrf-token"]).toBeUndefined();
  });
});
