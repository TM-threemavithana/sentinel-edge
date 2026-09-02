import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const errors = [];

async function readJson(path) {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

function requireValue(condition, message) {
  if (!condition) errors.push(message);
}

function validateVars(label, vars) {
  const secretNames = ["SESSION_SECRET", "UPSTREAM_ENCRYPTION_KEY", "DEMO_SENTINEL_API_KEY"];
  for (const name of secretNames) {
    requireValue(!(name in vars), `${label}: ${name} must be a Worker secret, not a plain variable`);
  }
}

const gateway = await readJson("apps/gateway/wrangler.jsonc");
const web = await readJson("apps/web/wrangler.jsonc");
const packageJson = await readJson("package.json");

requireValue(packageJson.engines?.node === ">=22.0.0", "Root package must declare Node.js 22 or later");
requireValue(gateway.env?.production?.vars?.MFA_REQUIRED === "true", "Production must require MFA");
requireValue(gateway.env?.staging?.vars?.MFA_REQUIRED === "true", "Staging must require MFA");
requireValue(gateway.env?.production?.vars?.FREE_TIER_MODE === "true", "Production must retain free-tier safeguards");

for (const environment of ["staging", "production"]) {
  const config = gateway.env?.[environment];
  const origins = String(config?.vars?.ALLOWED_ORIGINS ?? "").split(",").filter(Boolean);
  requireValue(origins.length > 0 && origins.every((origin) => origin.startsWith("https://")), `${environment}: ALLOWED_ORIGINS must contain HTTPS origins`);
  requireValue(config?.d1_databases?.every((entry) => /^[0-9a-f-]{36}$/u.test(entry.database_id)), `${environment}: D1 database IDs must be configured UUIDs`);
  requireValue(config?.kv_namespaces?.every((entry) => /^[0-9a-f]{32}$/u.test(entry.id)), `${environment}: KV namespace IDs must be configured values`);
  validateVars(`gateway ${environment}`, config?.vars ?? {});
}

for (const environment of ["staging", "production"]) {
  const config = web.env?.[environment];
  requireValue(String(config?.vars?.GATEWAY_ORIGIN ?? "").startsWith("https://"), `web ${environment}: GATEWAY_ORIGIN must use HTTPS`);
  requireValue(config?.services?.[0]?.service === `sentinel-edge-gateway-${environment}`, `web ${environment}: service binding must target the matching gateway`);
  validateVars(`web ${environment}`, config?.vars ?? {});
}

if (errors.length > 0) {
  console.error(`Configuration validation failed:\n- ${errors.join("\n- ")}`);
  process.exitCode = 1;
} else {
  console.log("Configuration validation passed for local, staging, and production safety invariants.");
}
