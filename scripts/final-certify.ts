import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type PhaseStatus = "PASS" | "FAIL" | "NOT_PROVEN";
interface Phase { name: string; status: PhaseStatus; detail: string; }
interface CommandResult { status: PhaseStatus; output: string; detail: string; }

const phases: Phase[] = [];
const root = process.cwd();

function tail(value: string): string {
  const clean = value.replace(/\u001b\[[0-9;]*m/gu, "").trim();
  return clean.length > 700 ? `...${clean.slice(-700)}` : clean;
}

function commandResult(command: string, args: string[], environment?: NodeJS.ProcessEnv): CommandResult {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", timeout: 180_000, killSignal: "SIGKILL", stdio: ["ignore", "pipe", "pipe"], ...(environment ? { env: { ...process.env, ...environment } } : {}) });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const output = `${stdout}${stderr}`;
  if (result.status === 0) return { status: "PASS", output, detail: `${command} ${args.join(" ")} exited 0` };
  if (result.status === 2 && !result.error) return { status: "NOT_PROVEN", output, detail: `${command} ${args.join(" ")} exited 2 (unsupported or degraded)` };
  const reason = result.error && "code" in result.error && result.error.code === "ETIMEDOUT" ? "timeout" : `exit ${result.status ?? "signal"}`;
  return { status: "FAIL", output, detail: `${command} ${args.join(" ")} ${reason}${tail(output) ? `: ${tail(output)}` : ""}` };
}

function record(name: string, result: CommandResult, detail = result.detail): CommandResult {
  phases.push({ name, status: result.status, detail });
  return result;
}

function run(name: string, command: string, args: string[], detailCheck?: (output: string) => string | undefined): CommandResult {
  const result = commandResult(command, args);
  const check = result.status === "PASS" && detailCheck ? detailCheck(result.output) : undefined;
  if (check) {
    const failed = { ...result, status: "FAIL" as const, detail: check };
    return record(name, failed);
  }
  return record(name, result);
}

function parseTestSummary(output: string): { tests: number; passed: number; failed: number; cancelled: number; skipped: number; todo: number } | undefined {
  const number = (label: string): number | undefined => {
    const match = new RegExp(`^# ${label} (\\d+)$`, "mu").exec(output);
    return match ? Number(match[1]) : undefined;
  };
  const tests = number("tests");
  const passed = number("pass");
  const failed = number("fail");
  const cancelled = number("cancelled");
  const skipped = number("skipped");
  const todo = number("todo");
  return tests === undefined || passed === undefined || failed === undefined || cancelled === undefined || skipped === undefined || todo === undefined
    ? undefined
    : { tests, passed, failed, cancelled, skipped, todo };
}

function testFiles(pattern: RegExp): string[] {
  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.name.endsWith(".test.ts") && pattern.test(path)) files.push(path);
    }
  };
  visit(join(root, "test"));
  return files.sort();
}

function runTests(name: string, pattern: RegExp): number | undefined {
  const files = testFiles(pattern);
  if (files.length === 0) {
    phases.push({ name, status: "FAIL", detail: `no test files matched ${pattern}` });
    return undefined;
  }
  const result = commandResult(process.execPath, ["--import", "tsx", "--test", ...files], { INVOCK_TEST_MODE: "1" });
  const summary = parseTestSummary(result.output);
  const detail = summary
    ? `${files.length} files; ${summary.tests} tests, ${summary.passed} passed, ${summary.failed} failed, ${summary.cancelled} cancelled, ${summary.skipped} skipped, ${summary.todo} todo`
    : `${files.length} files; test summary missing${tail(result.output) ? `: ${tail(result.output)}` : ""}`;
  const status: PhaseStatus = result.status !== "PASS" ? result.status : summary && summary.tests > 0 && summary.passed === summary.tests && summary.failed === 0 && summary.cancelled === 0 && summary.skipped === 0 && summary.todo === 0 ? "PASS" : "FAIL";
  phases.push({ name, status, detail });
  return summary?.tests;
}

function checkJsonOutput(output: string, predicate: (value: unknown) => boolean, failure: string): string | undefined {
  const lines = output.trim().split(/\r?\n/u).filter(Boolean).reverse();
  for (const line of lines) {
    try {
      const value: unknown = JSON.parse(line);
      return predicate(value) ? undefined : failure;
    } catch {}
  }
  return failure;
}

function advisoryScanClean(output: string): boolean {
  const candidates = [output.trim()];
  const firstObject = output.indexOf("{");
  const lastObject = output.lastIndexOf("}");
  if (firstObject >= 0 && lastObject > firstObject) candidates.push(output.slice(firstObject, lastObject + 1));
  for (const candidate of candidates) {
    try {
      const value: unknown = JSON.parse(candidate);
      if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
      const metadata = (value as Record<string, unknown>).metadata;
      if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) continue;
      const vulnerabilities = (metadata as Record<string, unknown>).vulnerabilities;
      if (vulnerabilities === null || typeof vulnerabilities !== "object" || Array.isArray(vulnerabilities)) continue;
      const counts = Object.values(vulnerabilities as Record<string, unknown>).filter(item => typeof item === "number");
      return counts.length > 0 && counts.every(item => item === 0);
    } catch {}
  }
  return false;
}

const CURRENT_AUDIT_REPORTS = [
  "post-fix-authorization.md",
  "post-fix-protocols.md",
  "post-fix-containment.md",
  "post-fix-supply-chain.md",
  "post-fix-product.md",
] as const;

function validateIndependentAudits(): Phase {
  const directory = join(root, ".artifacts", "independent-audits");
  const missing: string[] = [];
  const invalid: string[] = [];
  const verdicts: string[] = [];
  for (const file of CURRENT_AUDIT_REPORTS) {
    const path = join(directory, file);
    if (!existsSync(path)) {
      missing.push(file);
      continue;
    }
    let report: string;
    try { report = readFileSync(path, "utf8"); }
    catch { invalid.push(`${file}:unreadable`); continue; }
    const evidenceSections = [
      /source evidence|source and runtime evidence|scope and evidence posture/iu,
      /test evidence|executed checks|command results/iu,
      /runtime evidence|source and runtime evidence|arena: executable facts|dashboard, control plane/iu,
    ];
    const requiredSections = ["P0", "P1", "P2", "NOT PROVEN", "verdict"];
    if (evidenceSections.some(section => !section.test(report)) || requiredSections.some(section => !report.toLowerCase().includes(section.toLowerCase()))) {
      invalid.push(`${file}:missing-required-section`);
      continue;
    }
    const finalMarker = report.match(/(?:final verdict|verdict)[\s\S]{0,1600}/iu)?.[0] ?? report.slice(-2400);
    const verdict = /\bFAIL(?:URE|ED)?\b(?!-)/iu.test(finalMarker) ? "FAIL" : /\bNOT[_ ]PROVEN\b|\bNOT[_ ]READY\b|\bPARTIAL\b|\bDONE_WITH_CONCERNS\b/iu.test(finalMarker) ? "NOT_PROVEN" : /\bPASS\b/iu.test(finalMarker) ? "PASS" : undefined;
    if (!verdict) invalid.push(`${file}:missing-verdict`);
    else verdicts.push(`${file}=${verdict}`);
  }
  if (missing.length > 0) return { name: "Independent audits", status: "NOT_PROVEN", detail: `current five-report wave incomplete; missing ${missing.join(", ")}${verdicts.length > 0 ? `; observed ${verdicts.join(", ")}` : ""}` };
  if (invalid.length > 0) return { name: "Independent audits", status: "FAIL", detail: `current audit reports are structurally invalid: ${invalid.join(", ")}` };
  if (verdicts.every(verdict => verdict.endsWith("=PASS"))) return { name: "Independent audits", status: "PASS", detail: `five current audit reports PASS: ${verdicts.join(", ")}` };
  return { name: "Independent audits", status: "FAIL", detail: `current audit reports did not all PASS: ${verdicts.join(", ")}` };
}

function main(): number {
  let disposable: string | undefined;
  try {
    run("Toolchain", process.execPath, ["--version"]);
    run("Package manager", "pnpm", ["--version"]);
    run("Frozen install state", "pnpm", ["install", "--frozen-lockfile"]);
    run("Typecheck", "pnpm", ["typecheck"]);
    run("Lint", "pnpm", ["lint"]);

    const fullCount = runTests("Full test suite", /\.test\.ts$/u);
    runTests("Unit tests", /test\/(analysis|net|secret|lineage-transforms)\.test\.ts$/u);
    runTests("Property tests", /test\/property\//u);
    runTests("Integration tests", /test\/(integrations|judge|arena)\//u);
    runTests("Security tests", /test\/(security|authority|identity|guard)\//u);
    runTests("Fuzz smoke suite", /test\/fuzz\//u);
    runTests("Persistence tests", /test\/(evidence|control|chaos)\//u);
    runTests("Protocol tests", /test\/(protocol|mcp)|test\/(readiness|stdio-registry)\.test\.ts/u);
    runTests("SDK tests", /test\/sdk\//u);
    runTests("API tests", /test\/api\.test\.ts|test\/readiness\.test\.ts/u);
    run("Supported protocol certification command", "pnpm", ["protocol-certify"], output => {
      const summary = parseTestSummary(output);
      return summary && summary.tests > 0 && summary.passed === summary.tests && summary.failed === 0 && summary.cancelled === 0 && summary.skipped === 0 && summary.todo === 0
        ? undefined
        : "supported protocol certification command did not prove a complete test summary";
    });

    run("Dashboard build", "pnpm", ["build"]);
    run("Accessibility checks", "pnpm", ["accessibility:certify"], output => output.includes("STATUS: PASS") ? undefined : "accessibility certification did not report STATUS: PASS");
    const localContainment = commandResult(process.execPath, ["--import", "tsx", "scripts/containment-certify.ts"]);
    const localStatus = localContainment.output.includes('"status": "pass"') ? "PASS" : localContainment.status === "PASS" ? "NOT_PROVEN" : localContainment.status;
    phases.push({ name: "Local containment certification", status: localStatus, detail: localStatus === "PASS" ? "local containment reports pass" : `local containment is ${localStatus.toLowerCase()}: ${tail(localContainment.output)}` });
    const docker = record("Docker containment certification", commandResult("pnpm", ["docker-containment-test"]));
    const containmentStatus: PhaseStatus = localStatus === "PASS" && docker.status === "PASS" ? "PASS" : localStatus === "FAIL" || docker.status === "FAIL" ? "FAIL" : "NOT_PROVEN";
    phases.push({ name: "Containment certification", status: containmentStatus, detail: `local=${localStatus}, docker=${docker.status}` });

    const arena = run("Arena benchmark", "pnpm", ["arena"], output => output.includes('"benchmark":"invock-arena"') && output.includes('"p95"') ? undefined : "Arena output did not include a measured benchmark and latency percentile");
    if (arena.status === "PASS") phases.push({ name: "Performance evaluation", status: "PASS", detail: "Arena emitted measured latency and throughput fields" });
    else phases.push({ name: "Performance evaluation", status: arena.status, detail: "depends on measured Arena output" });
    runTests("Guard certification", /test\/guard\//u);

    const supply = run("Supply-chain scan", "pnpm", ["supply-chain", "--", "--sign"], output => output.includes('"lockfileStatus": "present"') && output.includes('"digestPinned": true') ? undefined : "supply-chain report lacks lockfile or pinned-container evidence");
    const supplyJson = supply.output.includes('"bomFormat": "CycloneDX"') && supply.output.includes('"signatureStatus": "verified"') && supply.output.includes('"provenance": "signed-local-evidence"') && supply.output.includes('"trust": "self-generated-local-evidence"');
    phases.push({ name: "SBOM generation", status: supply.status === "PASS" && supplyJson ? "PASS" : supply.status, detail: supplyJson ? "CycloneDX 1.5 SBOM and reproducibility payload are present with a locally verified Ed25519 signature" : "CycloneDX SBOM or local signature evidence was not verified" });
    const audit = run("Dependency advisory scan", "pnpm", ["audit", "--prod", "--json"]);
    const advisoryClean = audit.status === "PASS" && advisoryScanClean(audit.output);
    phases.push({ name: "Local supply-chain evidence", status: supply.status === "PASS" && supplyJson && advisoryClean ? "PASS" : supply.status === "FAIL" || audit.status === "FAIL" ? "FAIL" : "NOT_PROVEN", detail: advisoryClean && supplyJson ? "dependency advisory scan is clean and the local supply-chain evidence signature verified; this is not external provenance" : "advisory or signed local evidence is incomplete" });
    phases.push({ name: "External release provenance", status: "NOT_PROVEN", detail: "No trusted registry/CI artifact attestation, transparency-log inclusion, or production signing-custody evidence was presented by the local checkout" });

    run("Mutation tests", "pnpm", ["mutation-review"], output => /"killed":\s*3,\s*"total":\s*3/u.test(output) ? undefined : "mutation report did not prove all configured mutations killed");
    run("Demo certification", "pnpm", ["demo:certify"], output => output.includes("INVOCK DEMO CERTIFICATION: PASS") ? undefined : "demo certification banner missing");
    run("Base certification and secret scan", "pnpm", ["certify"], output => output.includes("Secret scan: PASS") && /Skipped tests: 0/u.test(output) ? undefined : "base certification did not prove secret scan and zero skipped tests");
    phases.push({ name: "Secret scan", status: phases.at(-1)?.status === "PASS" ? "PASS" : "FAIL", detail: "derived from the executed base certification secret scan; no independent PASS is inferred" });
    run("Double release rehearsal", "pnpm", ["release:rehearsal"], output => output.includes('"status": "completed"') && output.includes('"cleanup": "completed"') ? undefined : "release rehearsal did not report two completed independent runs and cleanup");

    disposable = mkdtempSync(join(tmpdir(), "invock-final-certify-"));
    const state = join(disposable, "control.json");
    const database = join(disposable, "receipts.sqlite");
    const keys = join(disposable, "keys");
    const help = run("CLI help", process.execPath, ["--import", "tsx", "src/cli.ts", "--help"]);
    if (help.status === "PASS") phases.push({ name: "CLI lifecycle", status: "PASS", detail: "help command completed" });
    else phases.push({ name: "CLI lifecycle", status: help.status, detail: "help command failed" });
    const init = commandResult(process.execPath, ["--import", "tsx", "src/cli.ts", "init", "--state", state]);
    const scan = commandResult(process.execPath, ["--import", "tsx", "src/cli.ts", "scan", "--state", state]);
    const evidence = commandResult(process.execPath, ["--import", "tsx", "src/cli.ts", "evidence", "bundle", "--database", database, "--key-directory", keys]);
    const lifecyclePass = init.status === "PASS" && scan.status === "PASS" && evidence.status === "PASS" && existsSync(state) && JSON.parse(readFileSync(state, "utf8")).version === 1;
    phases.push({ name: "Evidence receipts", status: lifecyclePass ? "PASS" : "FAIL", detail: lifecyclePass ? "versioned state, scan, and evidence bundle completed" : "CLI state or evidence lifecycle failed" });

    const docCheck = run("Documentation checks", process.execPath, ["--import", "tsx", "scripts/claim-consistency.ts", "--test-count", String(fullCount ?? 0), "--final-verdict", "NOT_READY"]);
    phases.push({ name: "Claim consistency", status: docCheck.status, detail: docCheck.detail });
    const requiredClean = ["LICENSE", "SECURITY.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "CHANGELOG.md", "ROADMAP.md", "SUPPORT.md"].every(file => existsSync(file) && statSync(file).size > 0);
    phases.push({ name: "Artifact checks", status: requiredClean ? "PASS" : "FAIL", detail: requiredClean ? "required release artifacts are non-empty" : "required release artifact missing or empty" });
    phases.push(validateIndependentAudits());
    const certificationSources = ["scripts/final-certify.ts", "scripts/claim-consistency.ts", "scripts/certify.ts", "scripts/release-rehearsal.ts", "scripts/docker-containment-test.ts"]
      .map(file => readFileSync(join(root, file), "utf8"));
    // Ignore synchronous child-process APIs and ordinary RegExp.prototype.exec calls.
    // Certification must reject an actual asynchronous child, not its own regex checks.
    const asynchronousProcessPattern = /(?<!\.)\b(?:spawn|exec|fork|execFile)(?!Sync)\s*\(/u;
    const asynchronousSources = certificationSources.filter(source => asynchronousProcessPattern.test(source));
    phases.push({ name: "Process cleanup", status: asynchronousSources.length === 0 ? "PASS" : "FAIL", detail: asynchronousSources.length === 0 ? "certification process sources use bounded synchronous child execution only" : "asynchronous child/process execution found in certification sources" });
    const containerCleanup = commandResult("docker", ["ps", "-aq", "--filter", "ancestor=invock-containment:local"]);
    const cleanupOutput = containerCleanup.output.trim();
    const cleanupUnavailable = containerCleanup.status !== "PASS" || /request returned \d{3} .*Internal Server Error|Cannot connect to the Docker daemon|docker: .*error/iu.test(cleanupOutput);
    const containerCleanupStatus: PhaseStatus = cleanupUnavailable ? "NOT_PROVEN" : cleanupOutput === "" ? "PASS" : "FAIL";
    const containerCleanupDetail = cleanupUnavailable
      ? `Docker cleanup query is ${containerCleanup.status.toLowerCase()}: ${tail(containerCleanup.output)}`
      : cleanupOutput === ""
        ? "no exited/running containment containers remain"
        : `container ids remain: ${tail(containerCleanup.output)}`;
    phases.push({ name: "Container cleanup", status: containerCleanupStatus, detail: containerCleanupDetail });
    const artifactDirectory = disposable;
    if (artifactDirectory) rmSync(artifactDirectory, { recursive: true, force: true });
    disposable = undefined;
    phases.push({ name: "Artifact cleanup", status: artifactDirectory && !existsSync(artifactDirectory) ? "PASS" : "FAIL", detail: artifactDirectory && !existsSync(artifactDirectory) ? "final certification temporary directory removed" : "final certification temporary directory remains" });

    const mandatoryFailures = phases.filter(phase => phase.status === "FAIL");
    const mandatoryUnproven = phases.filter(phase => phase.status === "NOT_PROVEN");
    const ready = mandatoryFailures.length === 0 && mandatoryUnproven.length === 0;
    console.log("===============================================================================");
    console.log("                    INVOCK FINAL PRODUCT CERTIFICATION");
    console.log("===============================================================================");
    for (const phase of phases) console.log(`${phase.name}: ${phase.status} — ${phase.detail}`);
    console.log(`Mandatory failures: ${mandatoryFailures.length}`);
    console.log(`Mandatory skips / unproven: ${mandatoryUnproven.length}`);
    console.log(`VERDICT: ${ready ? "READY FOR HACKATHON SUBMISSION AND DESIGN-PARTNER EVALUATION" : "NOT READY"}`);
    return ready ? 0 : 1;
  } catch (error) {
    console.error(`INVOCK FINAL PRODUCT CERTIFICATION: FAIL\n${error instanceof Error ? error.message : String(error)}`);
    return 1;
  } finally {
    if (disposable) rmSync(disposable, { recursive: true, force: true });
  }
}

process.exitCode = main();
