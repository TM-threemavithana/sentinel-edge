import { NextResponse } from "next/server";
import { applySecurityHeaders } from "@/lib/security-headers";

export function proxy() {
  const response = NextResponse.next();
  applySecurityHeaders(response.headers);
  return response;
}

export const config = {
  matcher: [
    "/",
    "/login",
    "/showcase",
    "/dashboard/:path*",
    "/api/:path*",
    "/robots.txt",
    "/sitemap.xml",
  ],
};
