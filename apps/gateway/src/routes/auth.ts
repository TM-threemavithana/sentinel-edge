import { Hono } from "hono";
import type { AppBindings } from "../helpers";
import { DUMMY_PASSWORD_HASH, coordinator, errorResponse, requireSession } from "../helpers";
import { decryptValue, encryptValue, hashPassword, hmacSha256, randomToken, sha256, verifyPassword } from "../crypto";
import { createSession, destroySession, authenticateSession } from "../auth";
import { writeAudit } from "../audit";
import { loginSchema, mfaConfirmSchema, mfaVerifySchema, readJsonBody } from "../validation";
import { generateCsrfToken } from "../csrf";
import type { Role } from "@sentinel/security-core";
import { verifyAccessIdentity } from "../access";
import { buildTotpUri, encodeBase32, generateTotpSecret, matchingTotpStep } from "../totp";

const auth = new Hono<AppBindings>();

type LoginRow = {
  id: string;
  email: string;
  display_name: string;
  password_hash: string | null;
  workspace_id: string;
  workspace_name: string;
  role: Role;
  mfa_confirmed_at: string | null;
};

function publicUser(row: LoginRow) {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    workspaceId: row.workspace_id,
    workspaceName: row.workspace_name,
    role: row.role,
  };
}

async function mfaEncryptionKey(masterKey: string): Promise<string> {
  return hmacSha256(masterKey, "sentinel-edge:totp:v1");
}

function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z2-7]/gu, "");
}

function generateRecoveryCode(): string {
  const value = encodeBase32(crypto.getRandomValues(new Uint8Array(5)));
  return `${value.slice(0, 4)}-${value.slice(4, 8)}`;
}

auth.post("/login", async (c) => {
  if (c.env?.ACCESS_REQUIRED === "true") {
    return errorResponse("access_required", "Sign in through Cloudflare Access", 403);
  }
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const parsed = loginSchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) return errorResponse("invalid_credentials", "Email or password is invalid", 401);
  const email = parsed.data.email.toLowerCase();
  const rateKey = await hmacSha256(c.env.SESSION_SECRET, `${email}:${c.req.header("cf-connecting-ip") ?? "local"}`);
  const rateResponse = await coordinator(c.env, "auth").fetch("https://coordinator/rate-limit", {
    method: "POST", body: JSON.stringify({ key: rateKey, limit: 8, windowSeconds: 300 }),
  });
  const rate = (await rateResponse.json()) as { allowed: boolean; resetAt: string };
  if (!rate.allowed) return errorResponse("too_many_attempts", `Try again after ${rate.resetAt}`, 429);
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.email, u.display_name, u.password_hash, m.workspace_id, m.role, w.name AS workspace_name,
            mf.confirmed_at AS mfa_confirmed_at
       FROM users u JOIN memberships m ON m.user_id = u.id JOIN workspaces w ON w.id = m.workspace_id
       LEFT JOIN user_mfa mf ON mf.user_id = u.id
      WHERE u.email = ? COLLATE NOCASE AND u.status = 'active' AND u.auth_provider = 'local'
      ORDER BY m.created_at ASC LIMIT 1`,
  ).bind(email).first<LoginRow>();
  const passwordValid = await verifyPassword(parsed.data.password, row?.password_hash ?? DUMMY_PASSWORD_HASH);
  if (!row || !passwordValid) return errorResponse("invalid_credentials", "Email or password is invalid", 401);

  if (c.env.MFA_REQUIRED === "true" && row.mfa_confirmed_at) {
    const challengeToken = randomToken(32);
    const challengeId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM mfa_challenges WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now') OR user_id = ?").bind(row.id),
      c.env.DB.prepare(
        "INSERT INTO mfa_challenges (id, token_hash, user_id, workspace_id, expires_at) VALUES (?, ?, ?, ?, ?)",
      ).bind(challengeId, await sha256(challengeToken), row.id, row.workspace_id, expiresAt),
    ]);
    return c.json({ mfaRequired: true, challengeToken, expiresAt });
  }

  const mfaSetupRequired = c.env.MFA_REQUIRED === "true";
  const session = await createSession(c.req.raw, c.env, row.id, row.workspace_id, !mfaSetupRequired);
  await c.env.DB.prepare("UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(row.id).run();
  const csrfToken = await generateCsrfToken(c.env.SESSION_SECRET);
  c.res.headers.append("set-cookie", session.cookie);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: row.workspace_id, actorType: "user", actorId: row.id,
    action: mfaSetupRequired ? "auth.mfa_enrollment_started" : "auth.login",
    resourceType: "session", resourceId: session.sessionId, request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ user: publicUser(row), csrfToken, mfaSetupRequired });
});

auth.post("/mfa/verify", async (c) => {
  if (c.env.MFA_REQUIRED !== "true") return errorResponse("mfa_not_enabled", "Authenticator sign-in is not enabled", 404);
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const parsed = mfaVerifySchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) return errorResponse("invalid_mfa", "The authenticator or recovery code is invalid", 401);
  const challengeHash = await sha256(parsed.data.challengeToken);
  const rateKey = await hmacSha256(c.env.SESSION_SECRET, `${challengeHash}:${c.req.header("cf-connecting-ip") ?? "local"}`);
  const rateResponse = await coordinator(c.env, "auth").fetch("https://coordinator/rate-limit", {
    method: "POST", body: JSON.stringify({ key: rateKey, limit: 6, windowSeconds: 300 }),
  });
  const rate = (await rateResponse.json()) as { allowed: boolean; resetAt: string };
  if (!rate.allowed) return errorResponse("too_many_attempts", `Try again after ${rate.resetAt}`, 429);

  const row = await c.env.DB.prepare(
    `SELECT ch.id AS challenge_id, ch.attempts, ch.user_id, ch.workspace_id,
            u.email, u.display_name, m.role, w.name AS workspace_name,
            mf.secret_ciphertext, mf.recovery_codes_json, mf.last_used_step
       FROM mfa_challenges ch
       JOIN users u ON u.id = ch.user_id AND u.status = 'active' AND u.auth_provider = 'local'
       JOIN memberships m ON m.user_id = u.id AND m.workspace_id = ch.workspace_id
       JOIN workspaces w ON w.id = ch.workspace_id
       JOIN user_mfa mf ON mf.user_id = u.id AND mf.confirmed_at IS NOT NULL
      WHERE ch.token_hash = ? AND ch.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AND ch.attempts < 5
      LIMIT 1`,
  ).bind(challengeHash).first<{
    challenge_id: string; attempts: number; user_id: string; workspace_id: string;
    email: string; display_name: string; role: Role; workspace_name: string;
    secret_ciphertext: string; recovery_codes_json: string; last_used_step: number | null;
  }>();
  if (!row) return errorResponse("invalid_mfa", "The authenticator or recovery code is invalid", 401);

  const code = parsed.data.code.trim();
  const secret = await decryptValue(await mfaEncryptionKey(c.env.UPSTREAM_ENCRYPTION_KEY), row.secret_ciphertext);
  const matchedStep = await matchingTotpStep(secret, code);
  const recoveryHashes = JSON.parse(row.recovery_codes_json) as string[];
  const recoveryHash = await sha256(normalizeRecoveryCode(code));
  const recoveryIndex = recoveryHashes.indexOf(recoveryHash);
  const totpValid = matchedStep !== null && (row.last_used_step === null || matchedStep > row.last_used_step);
  const recoveryValid = recoveryIndex >= 0;
  if (!totpValid && !recoveryValid) {
    await c.env.DB.prepare("UPDATE mfa_challenges SET attempts = MIN(attempts + 1, 5) WHERE id = ?").bind(row.challenge_id).run();
    return errorResponse("invalid_mfa", "The authenticator or recovery code is invalid", 401);
  }

  const remainingRecoveryHashes = recoveryValid
    ? recoveryHashes.filter((_, index) => index !== recoveryIndex)
    : recoveryHashes;
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM mfa_challenges WHERE id = ?").bind(row.challenge_id),
    c.env.DB.prepare(
      "UPDATE user_mfa SET last_used_step = COALESCE(?, last_used_step), recovery_codes_json = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE user_id = ?",
    ).bind(totpValid ? matchedStep : null, JSON.stringify(remainingRecoveryHashes), row.user_id),
    c.env.DB.prepare("UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(row.user_id),
  ]);
  const session = await createSession(c.req.raw, c.env, row.user_id, row.workspace_id, true);
  const csrfToken = await generateCsrfToken(c.env.SESSION_SECRET);
  c.res.headers.append("set-cookie", session.cookie);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: row.workspace_id, actorType: "user", actorId: row.user_id,
    action: recoveryValid ? "auth.recovery_login" : "auth.mfa_login",
    resourceType: "session", resourceId: session.sessionId, request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ user: { id: row.user_id, email: row.email, displayName: row.display_name,
    workspaceId: row.workspace_id, workspaceName: row.workspace_name, role: row.role }, csrfToken });
});

auth.post("/mfa/enroll", async (c) => {
  if (c.env.MFA_REQUIRED !== "true") return errorResponse("mfa_not_enabled", "Authenticator sign-in is not enabled", 404);
  const user = await authenticateSession(c.req.raw, c.env, { allowUnverified: true });
  if (!user) return errorResponse("unauthenticated", "Sign in to continue", 401);
  const existing = await c.env.DB.prepare(
    "SELECT mf.confirmed_at, u.auth_provider FROM users u LEFT JOIN user_mfa mf ON mf.user_id = u.id WHERE u.id = ?",
  ).bind(user.id).first<{ confirmed_at: string | null; auth_provider: string }>();
  if (!existing || existing.auth_provider !== "local") return errorResponse("mfa_unavailable", "Authenticator enrollment is unavailable", 403);
  if (existing.confirmed_at) return errorResponse("mfa_already_enrolled", "Authenticator sign-in is already configured", 409);

  const secret = generateTotpSecret();
  const encrypted = await encryptValue(await mfaEncryptionKey(c.env.UPSTREAM_ENCRYPTION_KEY), secret);
  await c.env.DB.prepare(
    `INSERT INTO user_mfa (user_id, secret_ciphertext) VALUES (?, ?)
     ON CONFLICT(user_id) DO UPDATE SET secret_ciphertext = excluded.secret_ciphertext,
       recovery_codes_json = '[]', last_used_step = NULL, confirmed_at = NULL,
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
  ).bind(user.id, encrypted).run();
  return c.json({ secret, uri: buildTotpUri(secret, user.email), issuer: "Sentinel Edge" });
});

auth.post("/mfa/confirm", async (c) => {
  if (c.env.MFA_REQUIRED !== "true") return errorResponse("mfa_not_enabled", "Authenticator sign-in is not enabled", 404);
  const user = await authenticateSession(c.req.raw, c.env, { allowUnverified: true });
  if (!user) return errorResponse("unauthenticated", "Sign in to continue", 401);
  const body = await readJsonBody(c.req.raw);
  if (!body.success && body.reason === "too_large") return errorResponse("payload_too_large", "Management request body exceeds 64 KiB", 413);
  const parsed = mfaConfirmSchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) return errorResponse("invalid_mfa_setup", "Enter a valid code and a new password of at least 16 characters", 422);
  const row = await c.env.DB.prepare(
    `SELECT mf.secret_ciphertext, mf.confirmed_at, u.password_hash
       FROM user_mfa mf JOIN users u ON u.id = mf.user_id
      WHERE mf.user_id = ? LIMIT 1`,
  ).bind(user.id).first<{ secret_ciphertext: string; confirmed_at: string | null; password_hash: string | null }>();
  if (!row || row.confirmed_at) return errorResponse("mfa_setup_unavailable", "Authenticator enrollment cannot be completed", 409);
  if (row.password_hash && await verifyPassword(parsed.data.newPassword, row.password_hash)) {
    return errorResponse("password_reused", "Choose a password that has not been used for this account", 422);
  }
  const secret = await decryptValue(await mfaEncryptionKey(c.env.UPSTREAM_ENCRYPTION_KEY), row.secret_ciphertext);
  const matchedStep = await matchingTotpStep(secret, parsed.data.code);
  if (matchedStep === null) return errorResponse("invalid_mfa", "The authenticator code is invalid", 401);

  const recoveryCodes = Array.from({ length: 8 }, generateRecoveryCode);
  const recoveryHashes = await Promise.all(recoveryCodes.map((code) => sha256(normalizeRecoveryCode(code))));
  const passwordHash = await hashPassword(parsed.data.newPassword);
  await c.env.DB.batch([
    c.env.DB.prepare(
      `UPDATE user_mfa SET confirmed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), recovery_codes_json = ?,
       last_used_step = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE user_id = ?`,
    ).bind(JSON.stringify(recoveryHashes), matchedStep, user.id),
    c.env.DB.prepare(
      "UPDATE users SET password_hash = ?, auth_provider = 'local', last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    ).bind(passwordHash, user.id),
    c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id <> ?").bind(user.id, user.sessionId),
    c.env.DB.prepare("UPDATE sessions SET mfa_verified = 1 WHERE id = ?").bind(user.sessionId),
    c.env.DB.prepare("DELETE FROM mfa_challenges WHERE user_id = ?").bind(user.id),
  ]);
  const csrfToken = await generateCsrfToken(c.env.SESSION_SECRET);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: user.workspaceId, actorType: "user", actorId: user.id, action: "auth.mfa_enrolled",
    resourceType: "user", resourceId: user.id, request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ ok: true, recoveryCodes, csrfToken });
});

auth.post("/access", async (c) => {
  if (c.env?.ACCESS_REQUIRED !== "true") {
    return c.json({ enabled: false });
  }
  const identity = await verifyAccessIdentity(c.req.raw, c.env);
  if (!identity) return errorResponse("access_unauthenticated", "A valid Cloudflare Access session is required", 401);
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.email, u.display_name, m.workspace_id, m.role, w.name AS workspace_name
       FROM users u JOIN memberships m ON m.user_id = u.id JOIN workspaces w ON w.id = m.workspace_id
      WHERE u.email = ? COLLATE NOCASE AND u.status = 'active'
      ORDER BY m.created_at ASC LIMIT 1`,
  ).bind(identity.email).first<{
    id: string; email: string; display_name: string; workspace_id: string; workspace_name: string; role: Role;
  }>();
  if (!row) return errorResponse("access_forbidden", "This Access identity is not provisioned for Sentinel Edge", 403);

  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE users SET auth_provider = 'access', password_hash = NULL, last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(row.id),
    c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(row.id),
  ]);
  const session = await createSession(c.req.raw, c.env, row.id, row.workspace_id);
  const csrfToken = await generateCsrfToken(c.env.SESSION_SECRET);
  c.res.headers.append("set-cookie", session.cookie);
  c.executionCtx.waitUntil(writeAudit(c.env, {
    workspaceId: row.workspace_id, actorType: "user", actorId: row.id, action: "auth.access_login",
    resourceType: "session", resourceId: session.sessionId,
    metadata: { accessSubject: identity.subject }, request: c.req.raw, requestId: c.get("requestId"),
  }));
  return c.json({ enabled: true, user: { id: row.id, email: row.email, displayName: row.display_name,
    workspaceId: row.workspace_id, workspaceName: row.workspace_name, role: row.role }, csrfToken });
});

auth.post("/logout", async (c) => {
  const user = await authenticateSession(c.req.raw, c.env, { allowUnverified: true });
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
  const csrfToken = await generateCsrfToken(c.env.SESSION_SECRET);
  return c.json({ user, csrfToken });
});

export { auth };
