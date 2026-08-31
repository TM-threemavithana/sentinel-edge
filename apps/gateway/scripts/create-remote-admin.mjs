import { pbkdf2Sync, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const target = process.env.SENTINEL_ADMIN_ENV;
const email = process.env.SENTINEL_ADMIN_EMAIL?.trim().toLowerCase();
const password = process.env.SENTINEL_ADMIN_PASSWORD;
const provider = process.env.SENTINEL_ADMIN_PROVIDER ?? "local";
const resetMfa = process.env.SENTINEL_RESET_MFA === "true";

if (target !== "staging" && target !== "production") {
  console.error("Set SENTINEL_ADMIN_ENV to staging or production.");
  process.exit(1);
}
if (!email || !email.includes("@")) {
  console.error("Set SENTINEL_ADMIN_EMAIL to a valid administrator email.");
  process.exit(1);
}
if (provider !== "local" && provider !== "access") {
  console.error("Set SENTINEL_ADMIN_PROVIDER to local or access.");
  process.exit(1);
}
if (provider === "local" && (!password || password.length < 20)) {
  console.error("Set SENTINEL_ADMIN_PASSWORD to a unique value of at least 20 characters.");
  process.exit(1);
}

function sql(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

const database = target === "staging" ? "sentinel-edge-db-staging" : "sentinel-edge-db";
const passwordHash = provider === "local" ? (() => {
  const salt = randomBytes(16);
  const iterations = 100_000;
  const digest = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2$${iterations}$${salt.toString("base64url")}$${digest.toString("base64url")}`;
})() : null;
const adminId = `usr_${randomUUID().replaceAll("-", "")}`;
const auditId = `aud_${randomUUID().replaceAll("-", "")}`;
const file = join(tmpdir(), `sentinel-${target}-admin-${process.pid}-${Date.now()}.sql`);
const statement = `
PRAGMA foreign_keys = ON;

INSERT INTO workspaces (id, name, slug, plan, retention_days)
VALUES ('ws_primary', 'Sentinel Edge', 'sentinel-edge', 'free', 30)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, plan = excluded.plan;

INSERT INTO users (id, email, display_name, password_hash, auth_provider, status)
VALUES (${sql(adminId)}, ${sql(email)}, 'Sentinel Administrator', ${passwordHash ? sql(passwordHash) : "NULL"}, ${sql(provider)}, 'active')
ON CONFLICT(email) DO UPDATE SET
  display_name = excluded.display_name,
  password_hash = excluded.password_hash,
  auth_provider = excluded.auth_provider,
  status = 'active';

DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ${sql(email)} COLLATE NOCASE);

${provider === "access" || resetMfa ? `DELETE FROM user_mfa WHERE user_id = (SELECT id FROM users WHERE email = ${sql(email)} COLLATE NOCASE);` : ""}

INSERT INTO memberships (workspace_id, user_id, role)
SELECT 'ws_primary', id, 'admin' FROM users WHERE email = ${sql(email)} COLLATE NOCASE
ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = 'admin';

INSERT INTO audit_events (id, workspace_id, actor_type, actor_id, action, resource_type, resource_id, metadata_json)
SELECT ${sql(auditId)}, 'ws_primary', 'system', id, 'bootstrap.admin_provisioned', 'user', id,
       json_object('environment', ${sql(target)}, 'email', ${sql(email)}, 'provider', ${sql(provider)}, 'mfa_reset', ${resetMfa ? "1" : "0"})
  FROM users WHERE email = ${sql(email)} COLLATE NOCASE;
`;

try {
  writeFileSync(file, statement, { encoding: "utf8", mode: 0o600 });
  const wranglerArgs = ["d1", "execute", database, "--remote", "--env", target, `--file=${file}`];
  const command = process.platform === "win32" ? process.env.ComSpec ?? "cmd.exe" : "wrangler";
  const args = process.platform === "win32" ? ["/d", "/s", "/c", `wrangler ${wranglerArgs.join(" ")}`] : wranglerArgs;
  const result = spawnSync(command, args, {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  try {
    unlinkSync(file);
  } catch {
    // The temporary file may already have been removed by the host.
  }
}
