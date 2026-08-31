import { describe, expect, it } from "vitest";
import { buildTotpUri, generateTotpCode, matchingTotpStep } from "../src/totp";

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("TOTP authentication", () => {
  it("matches the RFC 6238 SHA-1 reference vector", async () => {
    await expect(generateTotpCode(RFC_SECRET, 59_000, 8)).resolves.toBe("94287082");
  });

  it("accepts only a bounded clock window", async () => {
    const timestamp = 1_700_000_000_000;
    const code = await generateTotpCode(RFC_SECRET, timestamp);
    await expect(matchingTotpStep(RFC_SECRET, code, timestamp)).resolves.toBe(Math.floor(timestamp / 30_000));
    await expect(matchingTotpStep(RFC_SECRET, code, timestamp + 90_000)).resolves.toBeNull();
  });

  it("builds a standards-compatible enrollment URI", () => {
    const uri = new URL(buildTotpUri(RFC_SECRET, "admin@example.com"));
    expect(uri.protocol).toBe("otpauth:");
    expect(uri.searchParams.get("secret")).toBe(RFC_SECRET);
    expect(uri.searchParams.get("issuer")).toBe("Sentinel Edge");
  });
});
