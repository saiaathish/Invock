import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const MAX_SCAN_BYTES = 1024 * 1024;
const CERTIFICATION_TIMEOUT_MS = 180_000;
const HIGH_CONFIDENCE_SECRET_PATTERNS: ReadonlyArray<RegExp> = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{40,4096}\s+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/u,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/u,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/u,
  /\bAIza[A-Za-z0-9_-]{35}\b/u,
];

function run(command: string, argumentsValue: string[]): string {
  const result = spawnSync(command, argumentsValue, { encoding: "utf8", timeout: CERTIFICATION_TIMEOUT_MS, killSignal: "SIGKILL" });
  const timedOut = result.error && "code" in result.error && result.error.code === "ETIMEDOUT";
  if (result.status !== 0) throw new Error(`${command} ${argumentsValue.join(" ")} failed${timedOut ? ": COMMAND_TIMEOUT" : ""}\n${result.stderr || result.stdout}`);
  return `${result.stdout}\n${result.stderr}`;
}

function trackedFiles(): string[] {
  const result = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { encoding: "buffer" });
  if (result.status !== 0) throw new Error(result.stderr?.toString("utf8") || "Unable to enumerate files for secret scan");
  return result.stdout.toString("utf8").split("\0").filter(Boolean);
}

function scanForSecrets(): { findings: string[]; scanned: number; skipped: string[] } {
  const findings: string[] = [];
  const skipped: string[] = [];
  let scanned = 0;
  for (const path of trackedFiles()) {
    let contents: Buffer;
    try { contents = readFileSync(path); } catch { skipped.push(`${path}:unreadable`); continue; }
    if (contents.includes(0)) continue;
    if (contents.byteLength > MAX_SCAN_BYTES) { skipped.push(`${path}:over-limit`); continue; }
    scanned += 1;
    const text = contents.toString("utf8");
    if (HIGH_CONFIDENCE_SECRET_PATTERNS.some(pattern => pattern.test(text))) findings.push(path);
  }
  return { findings, scanned, skipped };
}

run("node", ["--version"]);
run("pnpm", ["--version"]);
run("pnpm", ["build"]);
run("pnpm", ["typecheck"]);
const tests = run("pnpm", ["test"]);
if (!/^# fail 0$/mu.test(tests) || !/^# skipped 0$/mu.test(tests)) throw new Error("Test suite did not complete without failures and skips");
const demo = run("pnpm", ["demo:certify"]);
if (!demo.includes("INVOCK DEMO CERTIFICATION: PASS")) throw new Error("Deterministic demo failed");
const count = /^# tests (\d+)$/mu.exec(tests)?.[1] ?? "unknown";
const secretScan = scanForSecrets();
if (secretScan.findings.length > 0) throw new Error(`SECRET_SCAN_FAILED: ${secretScan.findings.join(", ")}`);
if (secretScan.skipped.length > 0) throw new Error(`SECRET_SCAN_INCOMPLETE: ${secretScan.skipped.join(", ")}`);

console.log(`INVOCK CERTIFICATION: PASS

Toolchain: PASS (Node and pnpm reported versions)
Frozen install state: NOT_TESTED (verified by CI only)
Typecheck: PASS
Lint: NOT CONFIGURED
Unit/Persistence/Transport/Security/API tests: PASS (${count} tests)
Build: PASS
Demo: PASS
Secret scan: PASS (${secretScan.scanned} files, 0 high-confidence findings)
Skipped tests: 0
Receipt-chain, documentation, process, and temporary-artifact claims: NOT_TESTED`);
