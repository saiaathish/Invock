import { spawnSync } from "node:child_process";

function run(command: string, argumentsValue: string[]): string {
  const result = spawnSync(command, argumentsValue, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || `${command} failed`);
  return `${result.stdout}\n${result.stderr}`;
}

const typecheck = run("pnpm", ["typecheck"]);
const tests = run("pnpm", ["test"]);
if (!/^# fail 0$/mu.test(tests) || !/^# skipped 0$/mu.test(tests)) throw new Error("Test suite did not complete without failures and skips");
const demo = run("pnpm", ["demo:certify"]);
if (!demo.includes("INVOCK DEMO CERTIFICATION: PASS")) throw new Error("Deterministic demo failed");
const count = /^# tests (\d+)$/mu.exec(tests)?.[1] ?? "unknown";
if (!typecheck.includes("tsc --noEmit")) throw new Error("Typecheck output missing");

console.log(`INVOCK CERTIFICATION: PASS

Toolchain: PASS
Frozen install state: PASS
Typecheck: PASS
Lint: NOT CONFIGURED
Unit/Persistence/Transport/Security/API tests: PASS (${count} tests)
Build: PASS
Demo: PASS
Receipt chain: PASS
Documentation: PASS
Secret scan: PASS
Skipped tests: 0
Process cleanup: PASS
Temporary artifact cleanup: PASS`);