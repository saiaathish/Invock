import { spawnSync } from "node:child_process";

const result = spawnSync(process.execPath, ["--import", "tsx", "--test", "test/readiness.test.ts"], { encoding: "utf8", env: { ...process.env, INVOCK_TEST_MODE: "1" } });
if (result.status !== 0) throw new Error(result.stderr || result.stdout || "Deterministic local demo assertions failed");
const output = `${result.stdout}\n${result.stderr}`;
const tests = Number(/^# tests (\d+)$/mu.exec(output)?.[1] ?? "0");
const passed = Number(/^# pass (\d+)$/mu.exec(output)?.[1] ?? "-1");
const failed = Number(/^# fail (\d+)$/mu.exec(output)?.[1] ?? "-1");
const skipped = Number(/^# skipped (\d+)$/mu.exec(output)?.[1] ?? "-1");
if (tests < 1 || passed !== tests || failed !== 0 || skipped !== 0) throw new Error("Deterministic local demo assertions failed");

console.log(`INVOCK DEMO CERTIFICATION: PASS

Readiness execution: PASS (${passed} tests, 0 failed, 0 skipped)
Evidence: derived from test/readiness.test.ts execution
Scope: local reference-monitor fixtures only`);
