import { describe, expect, it } from "vitest";
import { applySecurityHeaders, createContentSecurityPolicy, securityHeaders } from "../lib/security-headers";

describe("console security headers", () => {
  it("applies browser isolation, transport, and cache protections", () => {
    const headers = new Headers();
    const policy = createContentSecurityPolicy("test-nonce", false);
    applySecurityHeaders(headers, {
      cacheControl: "private, no-cache, no-store, max-age=0, must-revalidate",
      contentSecurityPolicy: policy,
    });

    expect(headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(headers.get("content-security-policy")).toContain("'nonce-test-nonce'");
    expect(headers.get("content-security-policy")?.match(/script-src[^;]+/u)?.[0]).not.toContain("'unsafe-inline'");
    expect(headers.get("content-security-policy")?.match(/style-src[^;]+/u)?.[0]).not.toContain("'unsafe-inline'");
    expect(headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(headers.get("x-content-type-options")).toBe("nosniff");
    expect(headers.get("x-frame-options")).toBe("DENY");
    expect(headers.get("cross-origin-embedder-policy")).toBe("require-corp");
    expect(headers.get("cache-control")).toContain("no-store");
  });

  it("defines every header with a non-empty value", () => {
    expect(Object.keys(securityHeaders).length).toBeGreaterThanOrEqual(8);
    expect(Object.values(securityHeaders).every((value) => value.length > 0)).toBe(true);
  });

  it("allows React development diagnostics without weakening production scripts", () => {
    expect(createContentSecurityPolicy("dev", true)).toContain("'unsafe-eval'");
    expect(createContentSecurityPolicy("prod", false)).not.toContain("'unsafe-eval'");
  });
});
