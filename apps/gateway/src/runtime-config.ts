import type { Env } from "./env";

function isCanonicalHttpsOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin === value && url.pathname === "/" && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function hasValidEncryptionKey(value: string | undefined): boolean {
  if (!value || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    return atob(normalized.padEnd(44, "=")).length === 32;
  } catch {
    return false;
  }
}

export function assertRuntimeConfiguration(env: Env): void {
  const errors: string[] = [];
  const sessionTtl = Number(env.SESSION_TTL_SECONDS);
  const inspectionBytes = Number(env.MAX_INSPECTION_BYTES);

  if (!env.DB) errors.push("DB binding is missing");
  if (!env.POLICY_CACHE) errors.push("POLICY_CACHE binding is missing");
  if (!env.EDGE_COORDINATOR) errors.push("EDGE_COORDINATOR binding is missing");
  if (!env.SESSION_COOKIE) errors.push("SESSION_COOKIE is missing");
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) errors.push("SESSION_SECRET must contain at least 32 characters");
  if (!hasValidEncryptionKey(env.UPSTREAM_ENCRYPTION_KEY)) errors.push("UPSTREAM_ENCRYPTION_KEY must be a 32-byte base64url value");
  if (!Number.isSafeInteger(sessionTtl) || sessionTtl < 300 || sessionTtl > 86_400) errors.push("SESSION_TTL_SECONDS is outside the allowed range");
  if (!Number.isSafeInteger(inspectionBytes) || inspectionBytes < 1_024 || inspectionBytes > 10_485_760) errors.push("MAX_INSPECTION_BYTES is outside the allowed range");
  if (env.FREE_TIER_MODE !== "true" && !env.ARTIFACTS) errors.push("ARTIFACTS binding is required when FREE_TIER_MODE is disabled");
  if (env.FREE_TIER_MODE !== "true" && env.AI_MODE === "async" && !env.ANALYSIS_QUEUE) {
    errors.push("ANALYSIS_QUEUE binding is required for asynchronous AI mode");
  }
  if (env.ACCESS_REQUIRED === "true") {
    if (!env.ACCESS_TEAM_DOMAIN || !/^[a-z0-9.-]+\.cloudflareaccess\.com$/u.test(env.ACCESS_TEAM_DOMAIN)) {
      errors.push("ACCESS_TEAM_DOMAIN must be a Cloudflare Access team hostname");
    }
    if (!env.ACCESS_AUD || !/^[A-Za-z0-9_-]{16,128}$/u.test(env.ACCESS_AUD)) {
      errors.push("ACCESS_AUD must contain the Cloudflare Access application audience");
    }
  }

  if (env.ENVIRONMENT !== "development") {
    const origins = (env.ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
    if (origins.length === 0 || origins.some((origin) => !isCanonicalHttpsOrigin(origin))) {
      errors.push("ALLOWED_ORIGINS must contain canonical HTTPS origins");
    }
    if (env.ACCESS_REQUIRED !== "true" && env.MFA_REQUIRED !== "true") {
      errors.push("Production authentication must enforce Cloudflare Access or authenticator MFA");
    }
  }

  if (errors.length > 0) throw new Error(`Invalid runtime configuration: ${errors.join("; ")}`);
}
