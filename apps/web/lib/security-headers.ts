export function createContentSecurityPolicy(nonce: string, isDevelopment: boolean) {
  const developmentScriptPolicy = isDevelopment ? " 'unsafe-eval'" : "";
  return [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "manifest-src 'self'",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${developmentScriptPolicy}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "upgrade-insecure-requests",
    "worker-src 'none'",
  ].join("; ");
}

export const securityHeaders = {
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
} as const;

interface SecurityHeaderOptions {
  cacheControl: string;
  contentSecurityPolicy?: string | undefined;
}

export function applySecurityHeaders(headers: Headers, options: SecurityHeaderOptions) {
  for (const [name, value] of Object.entries(securityHeaders)) {
    headers.set(name, value);
  }
  headers.set("cache-control", options.cacheControl);
  if (options.cacheControl.includes("no-store")) {
    headers.set("expires", "0");
    headers.set("pragma", "no-cache");
  }
  if (options.contentSecurityPolicy) {
    headers.set("content-security-policy", options.contentSecurityPolicy);
  }
}
