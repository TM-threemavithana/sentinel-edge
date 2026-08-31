import { pbkdf2Sync, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const email = process.env.SENTINEL_ADMIN_EMAIL?.trim().toLowerCase();
const password = process.env.SENTINEL_ADMIN_PASSWORD;

if (!email || !email.includes("@")) {
  console.error("Set SENTINEL_ADMIN_EMAIL to a valid local administrator email.");
  process.exit(1);
}
if (!password || password.length < 16) {
  console.error("Set SENTINEL_ADMIN_PASSWORD to a unique value of at least 16 characters.");
  process.exit(1);
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function sql(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

const iterations = 100_000;
const salt = randomBytes(16);
const digest = pbkdf2Sync(password, salt, iterations, 32, "sha256");
const passwordHash = `pbkdf2$${iterations}$${base64Url(salt)}$${base64Url(digest)}`;
const adminId = "usr_local_admin";
const file = join(tmpdir(), `sentinel-local-admin-${process.pid}-${Date.now()}.sql`);
const statement = `
INSERT INTO users (id, email, display_name, password_hash, auth_provider, status)
VALUES (${sql(adminId)}, ${sql(email)}, 'Local administrator', ${sql(passwordHash)}, 'local', 'active')
ON CONFLICT(id) DO UPDATE SET
  email = excluded.email,
  password_hash = excluded.password_hash,
  auth_provider = 'local',
  status = 'active';

INSERT INTO memberships (workspace_id, user_id, role)
VALUES ('ws_demo', ${sql(adminId)}, 'admin')
ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = 'admin';
`;

try {
  writeFileSync(file, statement, { encoding: "utf8", mode: 0o600 });
  const wranglerArgs = ["d1", "execute", "sentinel-edge-db", "--local", `--file=${file}`];
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
