import { describe, expect, it } from "vitest";
import { generateCsrfCookie, validateCsrf } from "../src/csrf";

describe("CSRF protection", () => {
  it("generates a cookie with HttpOnly and correct SameSite for production", () => {
    const result = generateCsrfCookie(false);
    expect(result.token).toBeTruthy();
    expect(result.cookie).toContain("HttpOnly");
    expect(result.cookie).toContain("SameSite=None");
    expect(result.cookie).toContain("Secure");
  });

  it("generates a cookie without Secure for development", () => {
    const result = generateCsrfCookie(true);
    expect(result.cookie).not.toContain("Secure");
    expect(result.cookie).toContain("SameSite=Lax");
  });

  it("validates matching cookie and header tokens", () => {
    const { token } = generateCsrfCookie(false);
    const request = new Request("https://example.com/api", {
      method: "POST",
      headers: {
        cookie: `__sentinel_csrf=${token}`,
        "x-csrf-token": token,
      },
    });
    expect(validateCsrf(request)).toBe(true);
  });

  it("rejects mismatched tokens", () => {
    const request = new Request("https://example.com/api", {
      method: "POST",
      headers: {
        cookie: "__sentinel_csrf=token-a",
        "x-csrf-token": "token-b",
      },
    });
    expect(validateCsrf(request)).toBe(false);
  });

  it("rejects requests with missing CSRF header", () => {
    const request = new Request("https://example.com/api", {
      method: "POST",
      headers: { cookie: "__sentinel_csrf=some-token" },
    });
    expect(validateCsrf(request)).toBe(false);
  });

  it("allows GET requests without CSRF", () => {
    const request = new Request("https://example.com/api", { method: "GET" });
    expect(validateCsrf(request)).toBe(true);
  });
});
