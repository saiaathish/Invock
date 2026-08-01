import { spawnSync } from "node:child_process";

const result = spawnSync(process.execPath, ["--import", "tsx", "--test", "test/readiness.test.ts"], { encoding: "utf8" });
if (result.status !== 0) throw new Error(result.stderr || result.stdout || "Deterministic local demo assertions failed");
const output = `${result.stdout}\n${result.stderr}`;
if (!/^# fail 0$/mu.test(output) || !/^# skipped 0$/mu.test(output)) throw new Error("Deterministic local demo assertions failed");

console.log(`INVOCK DEMO CERTIFICATION: PASS

Safe invocation: PASS
Protected-path block: PASS
Notification mediation: PASS
Exact taint block: PASS
Base64 taint block: PASS
Base64URL taint block: PASS
URL-encoded taint block: PASS
Approval binding: PASS
Approval replay protection: PASS
Schema-drift quarantine: PASS
Receipt verification: PASS
Dashboard evidence: PASS
Process cleanup: PASS
Artifact cleanup: PASS`);