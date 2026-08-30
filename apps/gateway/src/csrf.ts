import { randomToken } from "./crypto";

const CSRF_COOKIE = "__sentinel_csrf";
const CSRF_HEADER = "x-csrf-token";

export function generateCsrfCookie(isDev: boolean): { token: string; cookie: string } {
  const token = randomToken(32);
  const secure = isDev ? "" : "; Secure";
  const sameSite = isDev ? "Lax" : "None";
  return {
    token,
    cookie: `${CSRF_COOKIE}=${token}; HttpOnly; Path=/; SameSite=${sameSite}${secure}; Max-Age=28800`,
  };
}

function getCookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie");
  if (!cookie) return null;
  for (const part of cookie.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return null;
}

export function validateCsrf(request: Request): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return true;
  const cookieToken = getCookieValue(request, CSRF_COOKIE);
  const headerToken = request.headers.get(CSRF_HEADER);
  if (!cookieToken || !headerToken) return false;
  if (cookieToken.length !== headerToken.length) return false;
  let diff = 0;
  for (let i = 0; i < cookieToken.length; i++) {
    diff |= cookieToken.charCodeAt(i) ^ headerToken.charCodeAt(i);
  }
  return diff === 0;
}

export { CSRF_COOKIE, CSRF_HEADER };
