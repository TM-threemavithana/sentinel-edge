import { describe, expect, it } from "vitest";
import { decryptValue, encryptValue, hashPassword, sha256, verifyPassword } from "../src/crypto";
import { upstreamSchema } from "../src/validation";

describe("credential handling", () => {
  it("hashes and verifies passwords without storing plaintext", async () => {
    const hash = await hashPassword("correct horse battery staple", 1_000);
    expect(hash).not.toContain("correct horse");
    await expect(verifyPassword("correct horse battery staple", hash)).resolves.toBe(true);
    await expect(verifyPassword("wrong password", hash)).resolves.toBe(false);
  });

  it("encrypts upstream credentials with authenticated encryption", async () => {
    const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ciphertext = await encryptValue(key, "Bearer upstream-secret");
    expect(ciphertext).not.toContain("upstream-secret");
    await expect(decryptValue(key, ciphertext)).resolves.toBe("Bearer upstream-secret");
  });

  it("produces stable one-way API key digests", async () => {
    await expect(sha256("sg_live_example")).resolves.toBe(await sha256("sg_live_example"));
  });
});

describe("upstream validation", () => {
  it.each([
    "http://api.example.com",
    "https://127.0.0.1/internal",
    "https://169.254.169.254/latest/meta-data",
    "https://service.local/api",
  ])("rejects unsafe origin %s", (baseUrl) => {
    expect(upstreamSchema.safeParse({ name: "unsafe", baseUrl }).success).toBe(false);
  });

  it("accepts public HTTPS origins", () => {
    expect(upstreamSchema.safeParse({ name: "production", baseUrl: "https://api.example.com" }).success).toBe(true);
  });

  it.each(["host", "content-length", "cookie", "cf-connecting-ip", "x-sentinel-key"])(
    "rejects unsafe upstream authentication header %s",
    (authHeaderName) => {
      expect(upstreamSchema.safeParse({ name: "unsafe", baseUrl: "https://api.example.com", authHeaderName }).success).toBe(false);
    },
  );

  it("rejects upstream URLs containing a query or fragment", () => {
    expect(upstreamSchema.safeParse({ name: "unsafe", baseUrl: "https://api.example.com?token=secret" }).success).toBe(false);
    expect(upstreamSchema.safeParse({ name: "unsafe", baseUrl: "https://api.example.com#fragment" }).success).toBe(false);
  });
});
