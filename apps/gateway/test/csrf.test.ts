import { describe, expect, it } from "vitest";
import { generateCsrfToken, validateCsrf } from "../src/csrf";

const secret = "s".repeat(32);

describe("CSRF protection", () => {
  it("generates a signed token", async () => {
    const token = await generateCsrfToken(secret);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/u);
  });

  it("validates a correctly signed header token", async () => {
    const token = await generateCsrfToken(secret);
    const request = new Request("https://example.com/api", {
      method: "POST",
      headers: { "x-csrf-token": token },
    });
    await expect(validateCsrf(request, secret)).resolves.toBe(true);
  });

  it("rejects tampered tokens", async () => {
    const token = await generateCsrfToken(secret);
    const replacement = token[0] === "A" ? "B" : "A";
    const request = new Request("https://example.com/api", {
      method: "POST",
      headers: { "x-csrf-token": `${replacement}${token.slice(1)}` },
    });
    await expect(validateCsrf(request, secret)).resolves.toBe(false);
  });

  it("rejects requests with missing CSRF header", async () => {
    const request = new Request("https://example.com/api", { method: "POST" });
    await expect(validateCsrf(request, secret)).resolves.toBe(false);
  });

  it("allows GET requests without CSRF", async () => {
    const request = new Request("https://example.com/api", { method: "GET" });
    await expect(validateCsrf(request, secret)).resolves.toBe(true);
  });
});
