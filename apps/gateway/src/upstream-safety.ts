import type { Env } from "./env";

const DNS_CACHE_TTL_SECONDS = 60;
const DNS_TIMEOUT_MS = 3_000;
const RESERVED_HOST_SUFFIXES = [".internal", ".invalid", ".local", ".localhost", ".test", ".home.arpa"];

type DnsJsonAnswer = { type?: number; data?: string };
type DnsJsonResponse = { Status?: number; Answer?: DnsJsonAnswer[] };

export class UnsafeUpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeUpstreamError";
  }
}

function normalizedHostname(value: string): string {
  const lower = value.replace(/^\[|\]$/gu, "").toLowerCase();
  return lower.endsWith(".") ? lower.slice(0, -1) : lower;
}

function parseIpv4(value: string): number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part))) return null;
  const octets = parts.map(Number);
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null;
}

function isPublicIpv4(value: string): boolean {
  const octets = parseIpv4(value);
  if (!octets) return false;
  const [a, b, c] = octets as [number, number, number, number];
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isPublicIpv6(value: string): boolean {
  const address = value.toLowerCase().split("%")[0] ?? "";
  if (!address.includes(":")) return false;
  if (address === "::" || address === "::1") return false;
  if (/^f[cd][0-9a-f]{2}:/u.test(address)) return false;
  if (/^fe[89ab][0-9a-f]:/u.test(address)) return false;
  if (/^ff[0-9a-f]{2}:/u.test(address)) return false;
  if (/^2001:0?db8:/u.test(address)) return false;
  const mapped = address.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/u);
  if (mapped) return isPublicIpv4(mapped[1]!);
  return /^[0-9a-f:]+$/u.test(address);
}

export function isPublicIpAddress(value: string): boolean {
  const host = normalizedHostname(value);
  return host.includes(":") ? isPublicIpv6(host) : isPublicIpv4(host);
}

export function isSafeUpstreamUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const host = normalizedHostname(url.hostname);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return false;
    if (!host || host === "localhost" || RESERVED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) return false;
    if (parseIpv4(host) || host.includes(":")) return isPublicIpAddress(host);
    return host.includes(".") && /^[a-z0-9.-]+$/u.test(host);
  } catch {
    return false;
  }
}

async function resolveAddresses(hostname: string, fetcher: typeof fetch): Promise<string[]> {
  const query = async (type: "A" | "AAAA"): Promise<string[]> => {
    const endpoint = new URL("https://cloudflare-dns.com/dns-query");
    endpoint.searchParams.set("name", hostname);
    endpoint.searchParams.set("type", type);
    const response = await fetcher(endpoint, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
    });
    if (!response.ok) throw new UnsafeUpstreamError("DNS safety validation is unavailable");
    const payload = await response.json() as DnsJsonResponse;
    if (payload.Status !== 0 && payload.Status !== 3) throw new UnsafeUpstreamError("DNS resolution failed");
    const expectedType = type === "A" ? 1 : 28;
    return (payload.Answer ?? [])
      .filter((answer) => answer.type === expectedType && typeof answer.data === "string")
      .map((answer) => answer.data!.trim());
  };

  const [ipv4, ipv6] = await Promise.all([query("A"), query("AAAA")]);
  return [...new Set([...ipv4, ...ipv6])];
}

export async function assertPublicUpstreamDestination(
  value: string,
  env: Pick<Env, "POLICY_CACHE">,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  if (!isSafeUpstreamUrl(value)) throw new UnsafeUpstreamError("Upstream must be a public HTTPS origin");
  const url = new URL(value);
  const hostname = normalizedHostname(url.hostname);
  if (parseIpv4(hostname) || hostname.includes(":")) return;

  const cacheKey = `upstream-dns-safe:${hostname}`;
  try {
    if (await env.POLICY_CACHE.get(cacheKey) === "safe") return;
  } catch {
    // DNS validation remains authoritative when the optional cache read fails.
  }

  const addresses = await resolveAddresses(hostname, fetcher);
  if (addresses.length === 0) throw new UnsafeUpstreamError("Upstream hostname did not resolve to a public address");
  if (addresses.some((address) => !isPublicIpAddress(address))) {
    throw new UnsafeUpstreamError("Upstream hostname resolved to a non-public address");
  }

  try {
    await env.POLICY_CACHE.put(cacheKey, "safe", { expirationTtl: DNS_CACHE_TTL_SECONDS });
  } catch {
    // A cache outage should add DNS latency, not disable the safety check.
  }
}
