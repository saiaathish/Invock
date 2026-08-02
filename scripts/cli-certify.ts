import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const checks: Array<[string, string, string[]]> = [
  ["Typecheck", "pnpm", ["typecheck"]],
  ["Tests", "pnpm", ["test"]],
  ["Build", "pnpm", ["build"]],
  ["Existing certification", "pnpm", ["certify"]],
  ["Package inspection", "npm", ["pack", "--dry-run"]],
];
let failed = 0;
const privacyDir = mkdtempSync(join(tmpdir(), "invock-cli-privacy-"));
const privacyEnv = { ...process.env, INVOCK_PRIVACY_DIR: privacyDir };
for (const [label, executable, args] of checks) {
  const result = spawnSync(executable, args, { stdio: "inherit", env: process.env });
  if (result.status !== 0) { failed += 1; console.error(`${label}: FAIL`); break; }
  console.error(`${label}: PASS`);
}
for (const [label, args] of [["Privacy status", ["privacy", "status"]], ["Privacy local verification", ["privacy", "verify-local"]], ["Privacy demo", ["privacy", "demo"]]] as const) {
  const result = spawnSync("node", ["--import", "tsx", "src/cli.ts", ...args], { stdio: "inherit", env: privacyEnv });
  if (result.status !== 0) { failed += 1; console.error(`${label}: FAIL`); break; }
  console.error(`${label}: PASS`);
}
rmSync(privacyDir, { recursive: true, force: true });
if (failed === 0) console.log("INVOCK CLI CERTIFICATION: PASS");
else { console.error("INVOCK CLI CERTIFICATION: FAIL"); process.exitCode = 1; }
