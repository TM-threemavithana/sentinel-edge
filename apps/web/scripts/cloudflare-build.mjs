import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

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

const run = (name, args) => {
  const executable = process.platform === "win32"
    ? process.env.ComSpec ?? "cmd.exe"
    : name;
  const executableArgs = process.platform === "win32"
    ? ["/d", "/s", "/c", `${name} ${args.join(" ")}`]
    : args;
  const result = spawnSync(executable, executableArgs, {
    cwd: projectDirectory,
    env: {
      ...environmentVariables,
      ...process.env,
      CLOUDFLARE_ENV: environment,
    },
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
};

run("vinext", ["build", "--mode", environment]);
if (action === "build") {
  run("wrangler", ["deploy", "--dry-run", "--outdir", `.wrangler/dry-run/${environment}`]);
} else {
  run("wrangler", ["deploy"]);
}
