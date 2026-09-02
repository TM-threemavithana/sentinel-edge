export const securityHeaders = {
  "cache-control": "private, no-cache, no-store, max-age=0, must-revalidate",
  "content-security-policy": [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "manifest-src 'self'",
    "object-src 'none'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "upgrade-insecure-requests",
    "worker-src 'none'",
  ].join("; "),
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  expires: "0",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
} as const;

export function applySecurityHeaders(headers: Headers) {
  for (const [name, value] of Object.entries(securityHeaders)) {
    headers.set(name, value);
  }
}
