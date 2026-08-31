import type { Role } from "@sentinel/security-core";
import type { Env } from "./env";
import type { ApiKeyPrincipal, SessionUser } from "./types";
import { hmacSha256, randomToken, sha256 } from "./crypto";

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie");
  if (!cookie) return null;
  for (const part of cookie.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return null;
}

export async function authenticateSession(
  request: Request,
  env: Env,
  options: { allowUnverified?: boolean } = {},
): Promise<SessionUser | null> {
  const token = cookieValue(request, env.SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT s.id AS session_id, u.id, u.email, u.display_name, m.workspace_id,
            w.name AS workspace_name, m.role, s.mfa_verified
       FROM sessions s
       JOIN users u ON u.id = s.user_id AND u.status = 'active'
       JOIN memberships m ON m.user_id = u.id AND m.workspace_id = s.workspace_id
       JOIN workspaces w ON w.id = m.workspace_id
      WHERE s.token_hash = ? AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      LIMIT 1`,
  )
    .bind(tokenHash)
    .first<{
      session_id: string;
      id: string;
      email: string;
      display_name: string;
      workspace_id: string;
      workspace_name: string;
      role: Role;
      mfa_verified: number;
    }>();

  if (!row) return null;
  if (env.MFA_REQUIRED === "true" && row.mfa_verified !== 1 && !options.allowUnverified) return null;
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    workspaceId: row.workspace_id,
    workspaceName: row.workspace_name,
    role: row.role,
    sessionId: row.session_id,
  };
}

export async function createSession(
  request: Request,
  env: Env,
  userId: string,
  workspaceId: string,
  mfaVerified = true,
): Promise<{ cookie: string; sessionId: string }> {
  const token = randomToken(32);
  const tokenHash = await sha256(token);
  const sessionId = crypto.randomUUID();
  const ttl = Number(env.SESSION_TTL_SECONDS) || 28_800;
  const expiresAt = new Date(Date.now() + ttl * 1_000).toISOString();
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const ipHash = await hmacSha256(env.SESSION_SECRET, ip);
  const userAgent = request.headers.get("user-agent")?.slice(0, 512) ?? "unknown";

  await env.DB.prepare(
    `INSERT INTO sessions (id, token_hash, user_id, workspace_id, expires_at, ip_hash, user_agent, mfa_verified)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(sessionId, tokenHash, userId, workspaceId, expiresAt, ipHash, userAgent, mfaVerified ? 1 : 0)
    .run();

  const isDev = env.ENVIRONMENT === "development";
  const secure = isDev ? "" : "; Secure";
  return { cookie: `${env.SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax${secure}`, sessionId };
}

export async function destroySession(request: Request, env: Env): Promise<string> {
  const token = cookieValue(request, env.SESSION_COOKIE);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
  }
  const isDev = env.ENVIRONMENT === "development";
  const secure = isDev ? "" : "; Secure";
  return `${env.SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

export async function authenticateApiKey(request: Request, env: Env): Promise<ApiKeyPrincipal | null> {
  const explicit = request.headers.get("x-sentinel-key");
  const authorization = request.headers.get("authorization");
  const token = explicit ?? (authorization?.startsWith("Bearer sg_") ? authorization.slice(7) : null);
  if (!token || !token.startsWith("sg_live_")) return null;
  const keyHash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT id, workspace_id, name, scopes_json
       FROM api_keys
      WHERE key_hash = ? AND status = 'active'
        AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      LIMIT 1`,
  )
    .bind(keyHash)
    .first<{ id: string; workspace_id: string; name: string; scopes_json: string }>();
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    name: row.name,
    scopes: JSON.parse(row.scopes_json) as string[],
  };
}

export function hasRole(role: Role, allowed: Role[]): boolean {
  return allowed.includes(role);
}
