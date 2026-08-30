import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { DUMMY_PASSWORD_HASH, coordinator, errorResponse, requireSession } from "../helpers";
import { hmacSha256, verifyPassword } from "../crypto";
import { createSession, destroySession, authenticateSession } from "../auth";
import { writeAudit } from "../audit";
import { loginSchema } from "../validation";
import { generateCsrfCookie } from "../csrf";
import type { Role } from "@sentinel/security-core";

const auth = new Hono<AppBindings>();

auth.post("/login", async (c) => {
  const parsed = loginSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return errorResponse("invalid_credentials", "Email or password is invalid", 401);
  const email = parsed.data.email.toLowerCase();
  const rateKey = await hmacSha256(c.env.SESSION_SECRET, `${email}:${c.req.header("cf-connecting-ip") ?? "local"}`);
  const rateResponse = await coordinator(c.env, "auth").fetch("https://coordinator/rate-limit", {
    method: "POST", body: JSON.stringify({ key: rateKey, limit: 8, windowSeconds: 300 }),
  });
  const rate = (await rateResponse.json()) as { allowed: boolean; resetAt: string };
  if (!rate.allowed) return errorResponse("too_many_attempts", `Try again after ${rate.resetAt}`, 429);
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.email, u.display_name, u.password_hash, m.workspace_id, m.role, w.name AS workspace_name
       FROM users u JOIN memberships m ON m.user_id = u.id JOIN workspaces w ON w.id = m.workspace_id
      WHERE u.email = ? COLLATE NOCASE AND u.status = 'active' AND u.auth_provider = 'local'
      ORDER BY m.created_at ASC LIMIT 1`,
  ).bind(email).first<{
    id: string; email: string; display_name: string; password_hash: string | null;
    workspace_id: string; workspace_name: string; role: Role;
  }>();
  const passwordValid = await verifyPassword(parsed.data.password, row?.password_hash ?? DUMMY_PASSWORD_HASH);
  if (!row || !passwordValid) return errorResponse("invalid_credentials", "Email or password is invalid", 401);
  const session = await createSession(c.req.raw, c.env, row.id, row.workspace_id);
  await c.env.DB.prepare("UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(row.id).run();
  const csrf = generateCsrfCookie(c.env.ENVIRONMENT === "development");
  c.res.headers.append("set-cookie", session.cookie);
  c.res.headers.append("set-cookie", csrf.cookie);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: row.workspace_id, actorType: "user", actorId: row.id, action: "auth.login",
    resourceType: "session", resourceId: session.sessionId, request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ user: { id: row.id, email: row.email, displayName: row.display_name,
    workspaceId: row.workspace_id, workspaceName: row.workspace_name, role: row.role }, csrfToken: csrf.token });
});

auth.post("/logout", async (c) => {
  const user = await authenticateSession(c.req.raw, c.env);
  c.header("set-cookie", await destroySession(c.req.raw, c.env));
  if (user) {
    c.executionCtx.waitUntil(writeAudit(c.env, {
      workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "auth.logout",
      resourceType: "session", resourceId: user.sessionId, request: c.req.raw, requestId: c.get("requestId"),
    }));
  }
  return c.json({ ok: true });
});

auth.get("/me", requireSession(), async (c) => {
  const user = c.get("user");
  c.executionCtx.waitUntil(
    coordinator(c.env, user.workspaceId).fetch("https://coordinator/presence/touch", {
      method: "POST", body: JSON.stringify({ sessionId: user.sessionId, userId: user.id }),
    }).then(() => undefined),
  );
  const csrf = generateCsrfCookie(c.env.ENVIRONMENT === "development");
  c.res.headers.append("set-cookie", csrf.cookie);
  return c.json({ user, csrfToken: csrf.token });
});

export { auth };
