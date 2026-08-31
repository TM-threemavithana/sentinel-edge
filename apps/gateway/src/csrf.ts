import { hmacSha256, randomToken } from "./crypto";

const CSRF_HEADER = "x-csrf-token";

export async function generateCsrfToken(secret: string): Promise<string> {
  const nonce = randomToken(32);
  const signature = await hmacSha256(secret, `csrf:${nonce}`);
  return `${nonce}.${signature}`;
}

export async function validateCsrf(request: Request, secret: string): Promise<boolean> {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return true;
  const headerToken = request.headers.get(CSRF_HEADER);
  if (!headerToken || headerToken.length !== 87) return false;
  const [nonce, suppliedSignature, extra] = headerToken.split(".");
  if (!nonce || !suppliedSignature || extra || nonce.length !== 43 || suppliedSignature.length !== 43) return false;
  const expectedSignature = await hmacSha256(secret, `csrf:${nonce}`);
  let diff = 0;
  for (let i = 0; i < expectedSignature.length; i++) {
    diff |= expectedSignature.charCodeAt(i) ^ suppliedSignature.charCodeAt(i);
  }
  return diff === 0;
}

export { CSRF_HEADER };
