import { describe, expect, it } from "vitest";
import { buildGatewayDestination, buildSafeResponseHeaders, readBoundedRequestBody } from "../app/api/backend/[...path]/route";

describe("console backend proxy", () => {
  it("constructs an origin-locked gateway URL", () => {
    const destination = buildGatewayDestination(
      ["v1", "auth", "me"],
      "https://console.example/api/backend/v1/auth/me?include=workspace",
      "https://gateway.example",
    );

    expect(destination.toString()).toBe("https://gateway.example/v1/auth/me?include=workspace");
  });

  it.each([
    [["//evil.example", "payload"]],
    [["..", "admin"]],
    [["v1\\auth", "login"]],
  ])("rejects decoded path segments that can change URL interpretation", (path) => {
    expect(() => buildGatewayDestination(path, "https://console.example/api/backend/test", "https://gateway.example")).toThrow("invalid_backend_path");
  });

  it("does not relay active content or arbitrary upstream headers", () => {
    const upstream = new Headers({
      "content-type": "text/html; charset=utf-8",
      "x-upstream-debug": "private",
    });
    upstream.append("set-cookie", "sentinel_session=test; HttpOnly; Secure");
    upstream.append("set-cookie", "__sentinel_csrf=test; HttpOnly; Secure");
    const safe = buildSafeResponseHeaders(upstream);

    expect(safe.get("content-type")).toBe("application/octet-stream");
    expect(safe.get("content-disposition")).toBe("attachment");
    expect(safe.get("set-cookie")).toContain("sentinel_session=");
    expect(safe.has("x-upstream-debug")).toBe(false);
    expect(safe.get("x-content-type-options")).toBe("nosniff");
  });

  it("rejects a declared request body larger than the proxy limit", async () => {
    const request = new Request("https://console.example/api/backend/v1/auth/login", {
      method: "POST",
      headers: { "content-length": "65537" },
      body: "{}",
    });
    await expect(readBoundedRequestBody(request, 65_536)).resolves.toEqual({ ok: false, reason: "too_large" });
  });

  it("rejects a streamed request body that exceeds the proxy limit", async () => {
    const request = new Request("https://console.example/api/backend/v1/auth/login", {
      method: "POST",
      body: new Uint8Array(65_537),
    });
    await expect(readBoundedRequestBody(request, 65_536)).resolves.toEqual({ ok: false, reason: "too_large" });
  });
});
