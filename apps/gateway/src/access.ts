import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { Env } from "./env";

const keySets = new Map<string, JWTVerifyGetKey>();

function accessIssuer(env: Env): string {
  return `https://${env.ACCESS_TEAM_DOMAIN}`;
}

function keySetFor(env: Env): JWTVerifyGetKey {
  const issuer = accessIssuer(env);
  const cached = keySets.get(issuer);
  if (cached) return cached;
  const keySet = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  keySets.set(issuer, keySet);
  return keySet;
}

export interface AccessIdentity {
  email: string;
  subject: string;
}

export async function verifyAccessIdentity(request: Request, env: Env): Promise<AccessIdentity | null> {
  if (env.ACCESS_REQUIRED !== "true" || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, keySetFor(env), {
      issuer: accessIssuer(env),
      audience: env.ACCESS_AUD,
      algorithms: ["RS256"],
    });
    if (typeof payload.email !== "string" || !payload.email.includes("@") || typeof payload.sub !== "string") return null;
    return { email: payload.email.trim().toLowerCase(), subject: payload.sub };
  } catch {
    return null;
  }
}
