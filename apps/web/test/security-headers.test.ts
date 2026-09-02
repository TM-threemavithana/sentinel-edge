import { describe, expect, it } from "vitest";
import { applySecurityHeaders, securityHeaders } from "../lib/security-headers";

describe("console security headers", () => {
  it("applies browser isolation, transport, and cache protections", () => {
    const headers = new Headers();
    applySecurityHeaders(headers);

    expect(headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(headers.get("x-content-type-options")).toBe("nosniff");
    expect(headers.get("x-frame-options")).toBe("DENY");
    expect(headers.get("cross-origin-embedder-policy")).toBe("require-corp");
    expect(headers.get("cache-control")).toContain("no-store");
  });

  it("defines every header with a non-empty value", () => {
    expect(Object.keys(securityHeaders).length).toBeGreaterThanOrEqual(10);
    expect(Object.values(securityHeaders).every((value) => value.length > 0)).toBe(true);
  });
});
