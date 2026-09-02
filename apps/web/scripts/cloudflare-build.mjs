import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const environment = process.argv[2];
const action = process.argv[3];

if (!new Set(["staging", "production"]).has(environment)) {
  console.error("Environment must be staging or production.");
  process.exit(1);
}
if (!new Set(["build", "deploy"]).has(action)) {
  console.error("Action must be build or deploy.");
  process.exit(1);
}

const projectDirectory = new URL("..", import.meta.url);
const wranglerConfig = JSON.parse(
  readFileSync(new URL("wrangler.jsonc", projectDirectory), "utf8"),
);
const environmentVariables = wranglerConfig.env?.[environment]?.vars;

if (!environmentVariables) {
  console.error(`No Wrangler variables are configured for ${environment}.`);
  process.exit(1);
}

const spawnOptions = {
    cwd: projectDirectory,
    env: {
      ...environmentVariables,
      ...process.env,
      CLOUDFLARE_ENV: environment,
    },
    encoding: "utf8",
    stdio: "inherit",
  };

function requireSuccess(result) {
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const require = createRequire(import.meta.url);
const vinextEntry = fileURLToPath(new URL("cli.js", import.meta.resolve("vinext")));
const wranglerEntry = resolve(dirname(require.resolve("wrangler/package.json")), "bin/wrangler.js");

requireSuccess(spawnSync(process.execPath, [vinextEntry, "build", "--mode", environment], spawnOptions));
if (action === "build") {
  requireSuccess(spawnSync(process.execPath, [wranglerEntry, "deploy", "--dry-run", "--outdir", `.wrangler/dry-run/${environment}`], spawnOptions));
} else {
  requireSuccess(spawnSync(process.execPath, [wranglerEntry, "deploy"], spawnOptions));
}

process.exit(0);
