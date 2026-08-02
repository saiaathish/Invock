import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { startApi } from "../src/api/server.js";
import { InvockStore } from "../src/storage/store.js";

const COMMAND_TIMEOUT_MS = 180_000;
const REHEARSAL_SCHEMA = "invock/release-rehearsal/v1";
const CHILD_FLAG = "--child";

export interface CommandEvidence {
  readonly label: string;
  readonly command: string;
  readonly status: number | null;
  readonly timedOut: boolean;
  readonly durationMs: number;
}

export interface ChildRehearsalResult {
  readonly schemaVersion: typeof REHEARSAL_SCHEMA;
  readonly runId: string;
  readonly status: "completed" | "blocked";
  readonly blockers: readonly string[];
  readonly localChecks: readonly CommandEvidence[];
  readonly runtime: {
    readonly port: number;
    readonly instanceId: string;
    readonly statePath: string;
    readonly receiptDatabasePath: string;
    readonly keyDirectory: string;
    readonly stateCreated: boolean;
    readonly receiptDatabaseCreated: boolean;
    readonly keyFilesCreated: number;
  };
  readonly externalEvidence: {
    readonly docker: "not-run";
    readonly browser: "not-run";
  };
}

export interface DoubleRehearsalResult {
  readonly schemaVersion: typeof REHEARSAL_SCHEMA;
  readonly status: "completed" | "blocked";
  readonly blockers: readonly string[];
  readonly rehearsals: readonly [ChildRehearsalResult, ChildRehearsalResult];
  readonly independent: {
    readonly projectCopies: boolean;
    readonly pnpmStores: boolean;
    readonly runtimeIdentities: boolean;
    readonly receiptDatabases: boolean;
    readonly ephemeralPorts: boolean;
  };
  readonly cleanup: "completed";
  readonly externalEvidence: {
    readonly docker: "not-run";
    readonly browser: "not-run";
  };
}

interface RehearsalSandbox {
  readonly projectCopy: string;
  readonly storeDirectory: string;
}

function isTimedOut(error: Error | undefined): boolean {
  return Boolean(error && "code" in error && error.code === "ETIMEDOUT");
}

function tail(value: string, limit = 4_000): string {
  return value.length <= limit ? value : value.slice(-limit);
}

function commandText(command: string, args: readonly string[]): string {
  return [command, ...args].join(" ");
}

function runCommand(
  label: string,
  command: string,
  args: readonly string[],
  cwd: string,
  evidence: CommandEvidence[],
): string {
  const startedAt = Date.now();
  const result = spawnSync(command, [...args], {
    cwd,
    encoding: "utf8",
    timeout: COMMAND_TIMEOUT_MS,
    killSignal: "SIGKILL",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const timedOut = isTimedOut(result.error);
  evidence.push({
    label,
    command: commandText(command, args),
    status: result.status,
    timedOut,
    durationMs: Date.now() - startedAt,
  });
  if (result.status !== 0) {
    const output = `${result.stderr ?? ""}${result.stdout ?? ""}`.trim();
    const marker = output.split("\n").find(line => /not ok|failureType|Error:|# fail [1-9]\d*/u.test(line));
    const detail = marker ?? tail(output);
    throw new Error(`${label} failed${timedOut ? ": COMMAND_TIMEOUT" : ""} (status ${result.status ?? "signal"})${detail ? `: ${detail.trim()}` : ""}`);
  }
  return result.stdout ?? "";
}

function option(name: string, args: readonly string[]): string | undefined {
  const index = args.indexOf(name);
  if (index < 0) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  return value;
}

function requiredOption(name: string, args: readonly string[]): string {
  const value = option(name, args);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function copyProject(source: string, destination: string): void {
  const excludedRoots = new Set([".git", "node_modules", "dist", "coverage", ".pnpm-store", ".invock"]);
  cpSync(source, destination, {
    recursive: true,
    filter: sourcePath => {
      const relativePath = relative(source, sourcePath);
      if (!relativePath) return true;
      const firstComponent = relativePath.split(sep)[0];
      return firstComponent !== undefined && !excludedRoots.has(firstComponent) && firstComponent !== ".DS_Store";
    },
  });
}

function createSandbox(parent: string, source: string, ordinal: number): RehearsalSandbox {
  const projectCopy = mkdtempSync(join(parent, `project-${ordinal}-`));
  const storeDirectory = mkdtempSync(join(parent, `pnpm-store-${ordinal}-`));
  if (readdirSync(storeDirectory).length !== 0) throw new Error("PNPM_STORE_NOT_EMPTY_BEFORE_INSTALL");
  copyProject(source, projectCopy);
  if (!existsSync(join(projectCopy, "package.json")) || !existsSync(join(projectCopy, "pnpm-lock.yaml"))) {
    throw new Error("PROJECT_COPY_MISSING_PACKAGE_OR_LOCKFILE");
  }
  return { projectCopy, storeDirectory };
}

function removeStrict(path: string): void {
  rmSync(path, { recursive: true, force: false, maxRetries: 0, retryDelay: 0 });
  if (existsSync(path)) throw new Error(`CLEANUP_PATH_REMAINS:${path}`);
}

function parseResult(output: string): ChildRehearsalResult {
  const line = output.split("\n").find(candidate => candidate.startsWith("REHEARSAL_RESULT "));
  if (!line) throw new Error("CHILD_RESULT_MISSING");
  const parsed: unknown = JSON.parse(line.slice("REHEARSAL_RESULT ".length));
  if (!parsed || typeof parsed !== "object" || (parsed as { schemaVersion?: unknown }).schemaVersion !== REHEARSAL_SCHEMA) {
    throw new Error("CHILD_RESULT_SCHEMA_INVALID");
  }
  return parsed as ChildRehearsalResult;
}

export function validateIndependentResults(results: readonly ChildRehearsalResult[]): void {
  if (results.length !== 2) throw new Error("DOUBLE_REHEARSAL_REQUIRES_TWO_RESULTS");
  const first = results[0];
  const second = results[1];
  if (!first || !second) throw new Error("DOUBLE_REHEARSAL_RESULT_MISSING");
  if (first.runId === second.runId) throw new Error("REHEARSAL_IDENTITIES_REUSED");
  if (first.runtime.instanceId === second.runtime.instanceId) throw new Error("RUNTIME_IDENTITIES_REUSED");
  if (first.status === "completed" && second.status === "completed") {
    if (first.runtime.port <= 0 || second.runtime.port <= 0 || first.runtime.port === second.runtime.port) throw new Error("EPHEMERAL_PORT_NOT_FRESH");
    if (!first.runtime.stateCreated || !second.runtime.stateCreated) throw new Error("STATE_ARTIFACT_MISSING");
    if (!first.runtime.receiptDatabaseCreated || !second.runtime.receiptDatabaseCreated) throw new Error("RECEIPT_DATABASE_MISSING");
    if (first.runtime.keyFilesCreated < 1 || second.runtime.keyFilesCreated < 1) throw new Error("IDENTITY_KEY_ARTIFACT_MISSING");
    if (first.runtime.statePath === second.runtime.statePath || first.runtime.receiptDatabasePath === second.runtime.receiptDatabasePath || first.runtime.keyDirectory === second.runtime.keyDirectory) throw new Error("RUNTIME_PATHS_REUSED");
  }
  for (const result of results) {
    if (result.externalEvidence.docker !== "not-run" || result.externalEvidence.browser !== "not-run") {
      throw new Error("EXTERNAL_EVIDENCE_REINTERPRETED");
    }
  }
}

async function runtimeSmoke(root: string, runtimeRoot: string, runId: string, evidence: CommandEvidence[]): Promise<ChildRehearsalResult["runtime"]> {
  const stateDirectory = join(runtimeRoot, "state");
  const receiptDirectory = join(runtimeRoot, "receipts");
  const keyDirectory = join(runtimeRoot, "keys");
  mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(receiptDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(keyDirectory, { recursive: true, mode: 0o700 });
  const statePath = join(stateDirectory, `control-${runId}.json`);
  const databasePath = join(receiptDirectory, `receipts-${runId}.sqlite`);

  const init = runCommand("isolated CLI init", process.execPath, ["--import", "tsx", "src/cli.ts", "init", "--state", statePath], root, evidence);
  const initResult: unknown = JSON.parse(init);
  if (!initResult || typeof initResult !== "object" || (initResult as { initialized?: unknown }).initialized !== true) throw new Error("ISOLATED_INIT_NOT_CONFIRMED");
  const scan = runCommand("isolated CLI scan", process.execPath, ["--import", "tsx", "src/cli.ts", "scan", "--state", statePath], root, evidence);
  const scanResult: unknown = JSON.parse(scan);
  if (!scanResult || typeof scanResult !== "object" || (scanResult as { scope?: unknown }).scope !== "local-control-plane") throw new Error("ISOLATED_SCAN_NOT_CONFIRMED");
  const evidenceOutput = runCommand("isolated evidence export", process.execPath, ["--import", "tsx", "src/cli.ts", "evidence", "bundle", "--database", databasePath, "--key-directory", keyDirectory], root, evidence);
  const evidenceResult: unknown = JSON.parse(evidenceOutput);
  if (!evidenceResult || typeof evidenceResult !== "object" || (evidenceResult as { formatVersion?: unknown }).formatVersion !== "invock/evidence-bundle/v1") throw new Error("ISOLATED_EVIDENCE_NOT_CONFIRMED");
  const doctorOutput = runCommand("isolated CLI doctor", process.execPath, ["--import", "tsx", "src/cli.ts", "doctor", "--database", databasePath, "--key-directory", keyDirectory], root, evidence);
  const doctorResult: unknown = JSON.parse(doctorOutput);
  if (!doctorResult || typeof doctorResult !== "object" || (doctorResult as { ready?: unknown }).ready !== true) throw new Error("ISOLATED_DOCTOR_NOT_READY");

  const store = new InvockStore(databasePath, { keyDirectory });
  const instanceId = store.instanceId;
  const api = await startApi(store, { host: "127.0.0.1", port: 0, token: `release-${runId}` });
  try {
    const health = await fetch(`${api.url}/api/v1/health`);
    const ready = await fetch(`${api.url}/api/v1/ready`, { headers: { authorization: `Bearer release-${runId}` } });
    if (health.status !== 200 || ready.status !== 200) throw new Error(`ISOLATED_API_NOT_READY:${health.status}/${ready.status}`);
    const parsedPort = Number(new URL(api.url).port);
    if (!Number.isInteger(parsedPort) || parsedPort <= 0) throw new Error("EPHEMERAL_PORT_NOT_BOUND");
    return {
      port: parsedPort,
      instanceId,
      statePath,
      receiptDatabasePath: databasePath,
      keyDirectory,
      stateCreated: existsSync(statePath),
      receiptDatabaseCreated: existsSync(databasePath),
      keyFilesCreated: readdirSync(keyDirectory).length,
    };
  } finally {
    await api.close();
    store.close();
  }
}

async function childMain(args: readonly string[]): Promise<void> {
  const root = resolve(process.cwd());
  const storeDirectory = resolve(requiredOption("--store-dir", args));
  const runtimeRoot = resolve(requiredOption("--runtime-root", args));
  const runId = option("--run-id", args) ?? randomUUID();
  const evidence: CommandEvidence[] = [];
  const blockers: string[] = [];
  if (!existsSync(join(root, "node_modules", "tsx"))) throw new Error("FROZEN_INSTALL_DID_NOT_PROVISION_TSX");
  const checked = (label: string, command: string, commandArgs: readonly string[]): string => {
    try {
      return runCommand(label, command, commandArgs, root, evidence);
    } catch (error) {
      blockers.push(`${label}:${error instanceof Error ? error.message.split("\n", 1)[0] : String(error)}`);
      return "";
    }
  };
  checked("test suite", "pnpm", ["test"]);
  checked("typecheck", "pnpm", ["typecheck"]);
  checked("build", "pnpm", ["build"]);
  checked("certification", "pnpm", ["certify"]);
  checked("demo certification", "pnpm", ["demo:certify"]);
  checked("judge certification", "pnpm", ["judge:certify"]);
  let runtime: ChildRehearsalResult["runtime"] = { port: 0, instanceId: `unavailable-${runId}`, statePath: "", receiptDatabasePath: "", keyDirectory: "", stateCreated: false, receiptDatabaseCreated: false, keyFilesCreated: 0 };
  try {
    runtime = await runtimeSmoke(root, runtimeRoot, runId, evidence);
  } catch (error) {
    blockers.push(`runtime smoke:${error instanceof Error ? error.message.split("\n", 1)[0] : String(error)}`);
  }
  const result: ChildRehearsalResult = {
    schemaVersion: REHEARSAL_SCHEMA,
    runId,
    status: blockers.length === 0 ? "completed" : "blocked",
    blockers,
    localChecks: evidence,
    runtime,
    externalEvidence: { docker: "not-run", browser: "not-run" },
  };
  console.log(`REHEARSAL_RESULT ${JSON.stringify(result)}`);
}

function usage(): void {
  console.log(`Usage: pnpm release:rehearsal\n\nRuns two independent clean-state release rehearsals. Docker and browser evidence are reported as not-run.`);
}

async function parentMain(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    return 0;
  }
  if (args.includes(CHILD_FLAG)) {
    await childMain(args);
    return 0;
  }
  const source = resolve(process.cwd());
  if (!existsSync(join(source, "package.json")) || !existsSync(join(source, "pnpm-lock.yaml"))) throw new Error("RUN_FROM_INVOCK_REPOSITORY_ROOT");
  const parentDirectory = mkdtempSync(join(tmpdir(), "invock-double-release-"));
  const sandboxes: RehearsalSandbox[] = [];
  const results: ChildRehearsalResult[] = [];
  let failure: unknown;
  const cleanupErrors: Error[] = [];
  try {
    for (const ordinal of [1, 2]) {
      const sandbox = createSandbox(parentDirectory, source, ordinal);
      sandboxes.push(sandbox);
      const runtimeRoot = join(sandbox.projectCopy, `.release-runtime-${ordinal}-${randomUUID()}`);
      mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
      const installEvidence: CommandEvidence[] = [];
      const runId = randomUUID();
      try {
        runCommand("isolated Git index", "git", ["init", "--quiet"], sandbox.projectCopy, installEvidence);
        runCommand("index project copy", "git", ["add", "--all"], sandbox.projectCopy, installEvidence);
        runCommand("frozen install", "pnpm", ["install", "--frozen-lockfile", "--store-dir", sandbox.storeDirectory], sandbox.projectCopy, installEvidence);
        const output = runCommand("release rehearsal child", "pnpm", ["exec", "tsx", "scripts/release-rehearsal.ts", CHILD_FLAG, "--store-dir", sandbox.storeDirectory, "--runtime-root", runtimeRoot, "--run-id", runId], sandbox.projectCopy, installEvidence);
        const parsed = parseResult(output);
        results.push({ ...parsed, localChecks: installEvidence.concat(parsed.localChecks) });
      } catch (error) {
        results.push({
          schemaVersion: REHEARSAL_SCHEMA,
          runId,
          status: "blocked",
          blockers: [`bootstrap:${error instanceof Error ? error.message.split("\n", 1)[0] : String(error)}`],
          localChecks: installEvidence,
          runtime: { port: 0, instanceId: `unavailable-${runId}`, statePath: "", receiptDatabasePath: "", keyDirectory: "", stateCreated: false, receiptDatabaseCreated: false, keyFilesCreated: 0 },
          externalEvidence: { docker: "not-run", browser: "not-run" },
        });
      }
    }
    validateIndependentResults(results);
  } catch (error) {
    failure = error;
  } finally {
    for (const sandbox of sandboxes.reverse()) {
      try { removeStrict(sandbox.projectCopy); } catch (error) { cleanupErrors.push(error instanceof Error ? error : new Error(String(error))); }
      try { removeStrict(sandbox.storeDirectory); } catch (error) { cleanupErrors.push(error instanceof Error ? error : new Error(String(error))); }
    }
    try { removeStrict(parentDirectory); } catch (error) { cleanupErrors.push(error instanceof Error ? error : new Error(String(error))); }
  }
  if (failure) {
    if (cleanupErrors.length > 0) throw new AggregateError([failure, ...cleanupErrors], "DOUBLE_REHEARSAL_FAILED_AND_CLEANUP_FAILED");
    throw failure;
  }
  if (cleanupErrors.length > 0) throw new AggregateError(cleanupErrors, "DOUBLE_REHEARSAL_CLEANUP_FAILED");
  const first = results[0];
  const second = results[1];
  if (!first || !second) throw new Error("DOUBLE_REHEARSAL_RESULT_MISSING");
  const blockers = results.flatMap(result => result.blockers.map(blocker => `${result.runId}:${blocker}`));
  const report: DoubleRehearsalResult = {
    schemaVersion: REHEARSAL_SCHEMA,
    status: blockers.length === 0 ? "completed" : "blocked",
    blockers,
    rehearsals: [first, second],
    independent: {
      projectCopies: sandboxes.length === 2 && new Set(sandboxes.map(sandbox => sandbox.projectCopy)).size === 2,
      pnpmStores: sandboxes.length === 2 && new Set(sandboxes.map(sandbox => sandbox.storeDirectory)).size === 2,
      runtimeIdentities: first.runtime.instanceId !== second.runtime.instanceId,
      receiptDatabases: first.runtime.receiptDatabaseCreated && second.runtime.receiptDatabaseCreated && first.runtime.receiptDatabasePath !== second.runtime.receiptDatabasePath,
      ephemeralPorts: first.runtime.port > 0 && second.runtime.port > 0 && first.runtime.port !== second.runtime.port,
    },
    cleanup: "completed",
    externalEvidence: { docker: "not-run", browser: "not-run" },
  };
  console.log("INVOCK DOUBLE RELEASE REHEARSAL");
  console.log(JSON.stringify(report, null, 2));
  return report.status === "completed" ? 0 : 1;
}

const invokedDirectly = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedDirectly) {
  try {
    process.exitCode = await parentMain();
  } catch (error) {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  }
}
