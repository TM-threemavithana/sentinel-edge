import { type NextRequest, NextResponse } from "next/server";
import { applySecurityHeaders, createContentSecurityPolicy } from "@/lib/security-headers";

const privateCacheControl = "private, no-cache, no-store, max-age=0, must-revalidate";
const staticCacheControl = "public, max-age=31536000, immutable";

function isStaticAsset(pathname: string) {
  return pathname.startsWith("/_next/static/") || /\.(?:css|gif|ico|jpe?g|js|png|svg|webp|woff2?)$/u.test(pathname);
}

export function proxy(request: NextRequest) {
  const staticAsset = isStaticAsset(request.nextUrl.pathname);
  const requestHeaders = new Headers(request.headers);
  let contentSecurityPolicy: string | undefined;

  if (!staticAsset) {
    const nonce = btoa(crypto.randomUUID());
    contentSecurityPolicy = createContentSecurityPolicy(nonce, process.env.NODE_ENV === "development");
    requestHeaders.set("x-nonce", nonce);
    requestHeaders.set("content-security-policy", contentSecurityPolicy);
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  applySecurityHeaders(response.headers, {
    cacheControl: staticAsset ? staticCacheControl : privateCacheControl,
    contentSecurityPolicy,
  });
  return response;
}

export const config = {
  matcher: ["/((?!_next/image|favicon.ico).*)"],
};
