import { describe, expect, it, vi } from "vitest";
import { assertPublicUpstreamDestination, isPublicIpAddress, isSafeUpstreamUrl } from "../src/upstream-safety";

function cache(initial: string | null = null) {
  return {
    get: vi.fn().mockResolvedValue(initial),
    put: vi.fn().mockResolvedValue(undefined),
  } as any;
}

function dnsFetcher(records: Record<string, string[]>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    const type = url.searchParams.get("type") ?? "A";
    const answerType = type === "AAAA" ? 28 : 1;
    return Response.json({ Status: 0, Answer: (records[type] ?? []).map((data) => ({ type: answerType, data })) });
  }) as unknown as typeof fetch;
}

describe("upstream URL safety", () => {
  it("accepts canonical public HTTPS origins", () => {
    expect(isSafeUpstreamUrl("https://api.groq.com/openai/v1")).toBe(true);
    expect(isSafeUpstreamUrl("https://8.8.8.8/v1")).toBe(true);
    expect(isSafeUpstreamUrl("https://[2606:4700:4700::1111]/v1")).toBe(true);
  });

  it.each([
    "http://api.example.com",
    "https://localhost",
    "https://service.internal",
    "https://127.0.0.1",
    "https://10.0.0.1",
    "https://100.64.0.1",
    "https://169.254.169.254",
    "https://192.168.1.1",
    "https://[::1]",
    "https://user:secret@example.com",
    "https://example.com/path?destination=internal",
  ])("rejects unsafe origin %s", (value) => {
    expect(isSafeUpstreamUrl(value)).toBe(false);
  });

  it.each(["0.0.0.0", "127.0.0.1", "169.254.1.1", "192.0.2.1", "198.51.100.2", "203.0.113.3", "::1", "fc00::1", "fe80::1", "2001:db8::1"])(
    "classifies non-public address %s",
    (value) => expect(isPublicIpAddress(value)).toBe(false),
  );

  it("accepts DNS names only when every resolved address is public", async () => {
    const policyCache = cache();
    const fetcher = dnsFetcher({ A: ["104.16.1.2"], AAAA: ["2606:4700::1111"] });
    await expect(assertPublicUpstreamDestination("https://api.example.com/v1", { POLICY_CACHE: policyCache }, fetcher)).resolves.toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(policyCache.put).toHaveBeenCalledWith("upstream-dns-safe:api.example.com", "safe", { expirationTtl: 60 });
  });

  it("fails closed when DNS returns a private address", async () => {
    const fetcher = dnsFetcher({ A: ["104.16.1.2", "10.0.0.5"], AAAA: [] });
    await expect(assertPublicUpstreamDestination("https://api.example.com", { POLICY_CACHE: cache() }, fetcher)).rejects.toThrow("non-public");
  });

  it("fails closed when the hostname has no address records", async () => {
    await expect(assertPublicUpstreamDestination("https://api.example.com", { POLICY_CACHE: cache() }, dnsFetcher({}))).rejects.toThrow("did not resolve");
  });

  it("uses a short-lived safe result without another lookup", async () => {
    const fetcher = dnsFetcher({});
    await expect(assertPublicUpstreamDestination("https://api.example.com", { POLICY_CACHE: cache("safe") }, fetcher)).resolves.toBeUndefined();
    expect(fetcher).not.toHaveBeenCalled();
  });
});
