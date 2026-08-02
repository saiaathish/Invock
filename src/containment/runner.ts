import { access, lstat, readFile, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { unavailableTelemetry, type ContainmentMount, type ContainmentProfile, type ContainmentRequest, type ContainmentResult, type ContainmentTelemetry, type ResourceMeasurement, type TelemetryUnavailableReason } from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024;
const DEFAULT_MAX_ARGV_BYTES = 8 * 1024;
const DEFAULT_MAX_PIDS = 64;
const DEFAULT_MEMORY_LIMIT_MB = 64;
const DEFAULT_CPU_LIMIT = 1;
const MAX_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_ARGV_BYTES = 1024 * 1024;
const MAX_PIDS = 4_096;
const MAX_MEMORY_LIMIT_MB = 4_096;
const MAX_CPU_LIMIT = 16;

const NETWORK_COMMANDS = new Set(["curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "ftp", "telnet", "socat"]);
const SHELL_COMMANDS = new Set(["ash", "bash", "cmd", "csh", "dash", "fish", "ksh", "powershell", "pwsh", "sh", "tcsh", "zsh"]);
const SECRET_KEY = /(authorization|cookie|credential|key|password|secret|token)/iu;
const DANGEROUS_ENV_KEY = /^(?:node_options|node_path|ld_preload|dyld_.*)$/iu;
const SHELL_SYNTAX = /[;&|`$(){}<>\n\r]/u;
const IMAGE_NAME = /^[a-z0-9][a-z0-9._/-]*(?::[a-z0-9._-]+)?$/u;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/u;
let containerSequence = 0;

type SandboxCapability = ContainmentResult["capabilities"]["sandbox"];

interface EnforcementCapabilities {
  sandbox: SandboxCapability;
  network: ContainmentResult["capabilities"]["network"];
  readOnlyRoot: boolean;
  nonRoot: boolean;
  noNewPrivileges: boolean;
}

interface CanonicalRequest {
  root: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  profile: RequiredProfile;
}

interface RequiredProfile {
  fixtureRoot: string;
  allowedCommands: string[];
  timeoutMs: number;
  maxOutputBytes: number;
  maxArgvBytes: number;
  sandbox: "required" | "none";
  network: "none" | "experimental-allowlist";
  readOnlyRoot: boolean;
  nonRoot: boolean;
  noNewPrivileges: boolean;
  maxPids: number;
  memoryLimitMb: number;
  cpuSeconds: number;
  image?: string;
  imageDigest?: string;
  mounts: CanonicalMount[];
}

interface CanonicalMount {
  source: string;
  target: string;
}

function capabilities(sandbox: SandboxCapability, enforced: boolean): EnforcementCapabilities {
  return {
    sandbox,
    network: enforced ? "denied" : "unknown",
    readOnlyRoot: enforced,
    nonRoot: enforced,
    noNewPrivileges: enforced,
  };
}

function emptyResult(status: ContainmentResult["status"], started: number, reasonCodes: string[], enforcement: EnforcementCapabilities): ContainmentResult {
  return { status, stdout: "", stderr: "", durationMs: Date.now() - started, reasonCodes, cleanup: "not_run", telemetry: unavailableTelemetry("process_not_spawned"), capabilities: enforcement };
}

interface ProcResourceSample {
  cpuMs?: number;
  memoryBytes?: number;
}

function unavailable(reason: TelemetryUnavailableReason): ResourceMeasurement<number> {
  return { status: "unavailable", reason };
}

async function readLinuxResourceSample(pid: number): Promise<{ sample?: ProcResourceSample; reason?: TelemetryUnavailableReason }> {
  if (process.platform !== "linux") return { reason: "not_supported" };
  try {
    const [schedstat, status] = await Promise.all([
      readFile(`/proc/${pid}/schedstat`, "utf8"),
      readFile(`/proc/${pid}/status`, "utf8"),
    ]);
    const cpuNanoseconds = Number.parseInt(schedstat.trim().split(/\s+/u)[0] ?? "", 10);
    const memoryMatch = /^VmHWM:\s+(\d+)\s+kB$/mu.exec(status) ?? /^VmRSS:\s+(\d+)\s+kB$/mu.exec(status);
    const memoryKilobytes = memoryMatch ? Number.parseInt(memoryMatch[1] ?? "", 10) : Number.NaN;
    const sample: ProcResourceSample = {};
    if (Number.isSafeInteger(cpuNanoseconds) && cpuNanoseconds >= 0) sample.cpuMs = Math.floor(cpuNanoseconds / 1_000_000);
    if (Number.isSafeInteger(memoryKilobytes) && memoryKilobytes >= 0) sample.memoryBytes = memoryKilobytes * 1024;
    return Object.keys(sample).length > 0 ? { sample } : { reason: "process_ended_before_sample" };
  } catch (error) {
    return { reason: error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "EACCES" ? "permission_denied" : "process_ended_before_sample" };
  }
}

function mergeObserved<T extends number>(first: ResourceMeasurement<T>, second: ResourceMeasurement<T> | undefined): ResourceMeasurement<T> {
  if (first.status === "observed") return first;
  return second?.status === "observed" ? second : first;
}

async function collectTelemetry(pid: number | undefined, runtimeExposesResources: boolean, firstSample?: { sample?: ProcResourceSample; reason?: TelemetryUnavailableReason }): Promise<ContainmentTelemetry> {
  if (!runtimeExposesResources) return unavailableTelemetry("runtime_not_exposed");
  if (pid === undefined || !Number.isSafeInteger(pid) || pid <= 0) return unavailableTelemetry("process_not_spawned");
  const second = await readLinuxResourceSample(pid);
  const cpuMs = firstSample?.sample?.cpuMs ?? second.sample?.cpuMs;
  const memoryBytes = firstSample?.sample?.memoryBytes ?? second.sample?.memoryBytes;
  return {
    pid: { status: "observed", value: pid },
    cpuMs: cpuMs === undefined ? unavailable(firstSample?.reason ?? second.reason ?? "process_ended_before_sample") : { status: "observed", value: cpuMs },
    memoryBytes: memoryBytes === undefined ? unavailable(firstSample?.reason ?? second.reason ?? "process_ended_before_sample") : { status: "observed", value: memoryBytes },
  };
}

function boundedBytes(argv: string[]): number {
  return Buffer.byteLength(JSON.stringify(argv), "utf8");
}

function redact(value: string): string {
  return value
    .replace(/((?:authorization|cookie|credential|api[_-]?key|access[_-]?key|private[_-]?key|password|secret|token)\s*["']?\s*[:=]\s*)(?:(bearer)\s+)?[^\s,"'}\]]+/giu, (_match, prefix: string, scheme?: string) => `${prefix}${scheme ? `${scheme} ` : ""}[REDACTED]`)
    .replace(/(bearer\s+)[^\s,;]+/giu, "$1[REDACTED]")
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu, "[REDACTED]")
    .replace(/\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b/gu, "[REDACTED]")
    .replace(/\bFAKE_(?:SECRET|TOKEN|PASSWORD)_[A-Z0-9_-]+\b/giu, "[REDACTED]");
}

function validBound(value: number | undefined, fallback: number, maximum: number): number | undefined {
  const resolved = value ?? fallback;
  return Number.isFinite(resolved) && resolved > 0 && resolved <= maximum ? resolved : undefined;
}

function canonicalRelativePath(value: string): string | undefined {
  if (value.length === 0 || value.includes("\0") || value.includes("\\") || isAbsolute(value) || /^[A-Za-z]:/u.test(value) || SHELL_SYNTAX.test(value)) return undefined;
  const parts = value.split("/");
  if (parts.some(part => part.length === 0 || part === "." || part === "..")) return undefined;
  return parts.join("/");
}

function shellOrNetworkCommand(command: string): string | undefined {
  const base = command.split("/").pop()?.toLowerCase() ?? command.toLowerCase();
  if (SHELL_COMMANDS.has(base)) return "SHELL_COMMAND_DENIED";
  if (NETWORK_COMMANDS.has(base)) return "NETWORK_DENIED";
  return undefined;
}

function validateImage(profile: ContainmentProfile): string | undefined {
  if (profile.imageDigest !== undefined && !profile.image) return "IMAGE_WITHOUT_NAME";
  if (!profile.image) return undefined;
  if (!IMAGE_NAME.test(profile.image) || profile.image.includes("@")) return "IMAGE_NAME_INVALID";
  if (!profile.imageDigest || !IMAGE_DIGEST.test(profile.imageDigest)) return "IMAGE_NOT_DIGEST_PINNED";
  return undefined;
}

function validateProfile(profile: ContainmentProfile): { profile?: RequiredProfile; reason?: string } {
  const timeoutMs = validBound(profile.timeoutMs, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const maxOutputBytes = validBound(profile.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES);
  const maxArgvBytes = validBound(profile.maxArgvBytes, DEFAULT_MAX_ARGV_BYTES, MAX_ARGV_BYTES);
  const maxPids = validBound(profile.maxPids, DEFAULT_MAX_PIDS, MAX_PIDS);
  const memoryLimitMb = validBound(profile.memoryLimitMb, DEFAULT_MEMORY_LIMIT_MB, MAX_MEMORY_LIMIT_MB);
  const cpuSeconds = validBound(profile.cpuSeconds, DEFAULT_CPU_LIMIT, MAX_CPU_LIMIT);
  const imageError = validateImage(profile);
  if (!timeoutMs || !maxOutputBytes || !maxArgvBytes || !maxPids || !memoryLimitMb || !cpuSeconds) return { reason: "PROFILE_BOUNDS_INVALID" };
  if (imageError) return { reason: imageError };
  if (!Array.isArray(profile.allowedCommands) || profile.allowedCommands.length === 0) return { reason: "COMMAND_ALLOWLIST_EMPTY" };
  if (profile.allowedCommands.some(command => typeof command !== "string")) return { reason: "COMMAND_PATH_INVALID" };
  const allowedCommands = profile.allowedCommands.map(canonicalRelativePath);
  if (allowedCommands.some(command => command === undefined)) return { reason: "COMMAND_PATH_INVALID" };
  if (profile.mounts !== undefined && (!Array.isArray(profile.mounts) || profile.mounts.some((mount: ContainmentMount) => !mount || typeof mount.source !== "string" || typeof mount.target !== "string" || mount.readOnly === false))) return { reason: "MOUNTS_MUST_BE_READ_ONLY" };
  const sandbox = profile.sandbox ?? "required";
  const network = profile.network ?? "none";
  if (network === "experimental-allowlist") return { reason: "EXPERIMENTAL_NETWORK_UNSUPPORTED" };
  const readOnlyRoot = profile.readOnlyRoot ?? true;
  const nonRoot = profile.nonRoot ?? true;
  const noNewPrivileges = profile.noNewPrivileges ?? true;
  if (sandbox === "required" && (!readOnlyRoot || !nonRoot || !noNewPrivileges)) return { reason: "SECURE_DEFAULT_REQUIRED" };
  return {
    profile: {
      fixtureRoot: profile.fixtureRoot,
      allowedCommands: allowedCommands as string[],
      timeoutMs,
      maxOutputBytes,
      maxArgvBytes,
      sandbox,
      network,
      readOnlyRoot,
      nonRoot,
      noNewPrivileges,
      maxPids,
      memoryLimitMb,
      cpuSeconds,
      ...(profile.image ? { image: profile.image } : {}),
      ...(profile.imageDigest ? { imageDigest: profile.imageDigest } : {}),
      mounts: profile.mounts?.map(mount => ({ source: mount.source, target: mount.target })) ?? [],
    },
  };
}

async function canonicalize(request: ContainmentRequest, profile: RequiredProfile): Promise<{ request?: CanonicalRequest; reason?: string }> {
  if (typeof request.command !== "string") return { reason: "COMMAND_PATH_INVALID" };
  const command = canonicalRelativePath(request.command);
  if (!command) return { reason: "COMMAND_PATH_INVALID" };
  const commandPolicy = shellOrNetworkCommand(command);
  if (commandPolicy) return { reason: commandPolicy };
  const args = request.argv ?? [];
  if (!Array.isArray(args) || args.some(arg => typeof arg !== "string" || arg.includes("\0") || arg.includes("\\") || SHELL_SYNTAX.test(arg))) return { reason: "ARGV_SHELL_SYNTAX_DENIED" };
  if (boundedBytes([command, ...args]) > profile.maxArgvBytes) return { reason: "ARGV_BOUND_EXCEEDED" };
  if (args.some(arg => isAbsolute(arg) || /^[A-Za-z]:/u.test(arg) || arg.split("/").some(part => part === ".."))) return { reason: "ARGV_PATH_INVALID" };
  if (args.some(arg => NETWORK_COMMANDS.has(arg.toLowerCase()))) return { reason: "NETWORK_DENIED" };
  const env = request.env ?? {};
  if (Object.entries(env).some(([key, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(key) || typeof value !== "string" || SECRET_KEY.test(key) || DANGEROUS_ENV_KEY.test(key))) return { reason: "SECRET_ENV_DENIED" };
  if (!profile.allowedCommands.includes(command)) return { reason: "COMMAND_NOT_ALLOWLISTED" };

  let root: string;
  try {
    const rootStat = await lstat(profile.fixtureRoot);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) return { reason: "FIXTURE_SYMLINK_OR_NOT_DIRECTORY" };
    root = await realpath(profile.fixtureRoot);
    let current = root;
    for (const part of command.split("/")) {
      current = join(current, part);
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) return { reason: "FIXTURE_SYMLINK" };
    }
    const executable = await realpath(join(root, command));
    const rel = relative(root, executable);
    if (rel === "" || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return { reason: "FIXTURE_ESCAPE" };
    await access(executable, constants.R_OK);
  } catch {
    return { reason: "FIXTURE_NOT_FOUND" };
  }
  const mounts: CanonicalMount[] = [];
  const mountTargets = new Set<string>();
  for (const mount of profile.mounts ?? []) {
    const target = mount.target;
    if (!target.startsWith("/fixture/") || target.includes("\\") || target.includes("\0") || target.includes(",") || SHELL_SYNTAX.test(target) || target.split("/").slice(1).some(part => part === ".." || part === "." || part.length === 0) || mountTargets.has(target)) return { reason: "MOUNT_TARGET_INVALID" };
    const source = isAbsolute(mount.source) ? mount.source : resolve(root, mount.source);
    try {
      const sourceStat = await lstat(source);
      if (sourceStat.isSymbolicLink()) return { reason: "MOUNT_SYMLINK" };
      const canonicalSource = await realpath(source);
      const sourceRel = relative(root, canonicalSource);
      if (sourceRel.startsWith(`..${sep}`) || isAbsolute(sourceRel)) return { reason: "MOUNT_SOURCE_ESCAPE" };
      mountTargets.add(target);
      mounts.push({ source: canonicalSource, target });
    } catch {
      return { reason: "MOUNT_SOURCE_NOT_FOUND" };
    }
  }
  return { request: { root, command, args, env, profile: { ...profile, mounts } } };
}

async function commandAvailable(command: string, args: string[], timeoutMs = 5_000): Promise<boolean> {
  return new Promise(resolve => {
    const child = spawn(command, args, { stdio: "ignore", shell: false, windowsHide: true });
    let settled = false;
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch {} finish(false); }, timeoutMs);
    timer.unref();
    const finish = (available: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(available);
    };
    child.once("error", () => finish(false));
    child.once("close", code => finish(code === 0));
  });
}

async function dockerAvailable(): Promise<boolean> {
  return await commandAvailable("docker", ["version", "--format", "{{.Server.Version}}"]);
}

async function dockerImageAvailable(imageDigest: string): Promise<boolean> {
  return await commandAvailable("docker", ["image", "inspect", imageDigest]);
}

/** Build the complete Docker invocation. The fixture is the only host mount. */
export function buildDockerRunArgs(profile: ContainmentProfile, fixtureRoot: string, command: string, argv: string[] = [], env: Record<string, string> = {}, containerName = `invock-containment-${process.pid}-${Date.now()}-${containerSequence++}`): string[] {
  if (!profile.image || !profile.imageDigest || !IMAGE_DIGEST.test(profile.imageDigest)) throw new Error("Docker containment requires a digest-pinned image");
  const maxPids = profile.maxPids ?? DEFAULT_MAX_PIDS;
  const memoryLimitMb = profile.memoryLimitMb ?? DEFAULT_MEMORY_LIMIT_MB;
  const cpuSeconds = profile.cpuSeconds ?? DEFAULT_CPU_LIMIT;
  return [
    "run", "--rm", "--pull=never", "--network", "none", "--read-only",
    "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532",
    "--pids-limit", String(maxPids), "--memory", `${memoryLimitMb}m`, "--cpus", String(cpuSeconds),
    "--mount", `type=bind,src=${fixtureRoot},dst=/fixture,readonly`,
    ...((profile.mounts ?? []).flatMap(mount => ["--mount", `type=bind,src=${mount.source},dst=${mount.target},readonly`])),
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m", "--workdir", "/fixture",
    "--name", containerName,
    ...Object.entries(env).flatMap(([key, value]) => ["--env", `${key}=${value}`]),
    profile.imageDigest,
    "/fixture/" + command,
    ...argv,
  ];
}

async function cleanupDockerContainer(containerName: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("docker", ["rm", "--force", containerName], { stdio: "ignore", shell: false, windowsHide: true });
    const timer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
      reject(new Error("DOCKER_CLEANUP_TIMEOUT"));
    }, 2_000);
    timer.unref();
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("close", code => { clearTimeout(timer); if (code === 0 || code === 1) resolve(); else reject(new Error(`DOCKER_CLEANUP_FAILED_${code ?? "SIGNAL"}`)); });
  });
}

function terminate(child: ChildProcess): NodeJS.Timeout | undefined {
  if (child.pid === undefined) return undefined;
  try { process.kill(-child.pid, "SIGTERM"); } catch { try { child.kill("SIGTERM"); } catch { /* already gone */ } }
  const killTimer = setTimeout(() => {
    try { process.kill(-child.pid!, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
  }, 250);
  killTimer.unref();
  return killTimer;
}

async function execute(child: ChildProcess, profile: RequiredProfile, enforcement: EnforcementCapabilities, started: number, cleanup?: () => Promise<void>, runtimeExposesResources = true): Promise<ContainmentResult> {
  let stdout = "";
  let stderr = "";
  let outputExceeded = false;
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  let timer: NodeJS.Timeout | undefined;
  let result: ContainmentResult = emptyResult("failed", started, ["RUNTIME_SPAWN_FAILED"], enforcement);
  const firstSample = child.pid === undefined || !runtimeExposesResources ? undefined : await readLinuxResourceSample(child.pid);
  const append = (target: "stdout" | "stderr", chunk: Buffer): void => {
    if (outputExceeded) return;
    const next = Buffer.byteLength(stdout, "utf8") + Buffer.byteLength(stderr, "utf8") + chunk.byteLength;
    if (next > profile.maxOutputBytes) {
      outputExceeded = true;
      killTimer = terminate(child);
      return;
    }
    if (target === "stdout") stdout += chunk.toString("utf8"); else stderr += chunk.toString("utf8");
  };
  child.stdout?.on("data", chunk => append("stdout", Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
  child.stderr?.on("data", chunk => append("stderr", Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
  timer = setTimeout(() => {
    timedOut = true;
    killTimer = terminate(child);
  }, profile.timeoutMs);
  timer.unref();
  try {
    const closed = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    const output = { stdout: redact(stdout), stderr: redact(stderr) };
    if (timedOut) result = { ...emptyResult("timed_out", started, ["TIMEOUT"], enforcement), ...output, ...(closed.signal ? { signal: closed.signal } : {}) };
    else if (outputExceeded) result = { ...emptyResult("denied", started, ["OUTPUT_BOUND_EXCEEDED"], enforcement), ...output };
    else result = {
      ...emptyResult(closed.code === 0 ? "completed" : "failed", started, closed.code === 0 ? [] : ["CHILD_EXIT_NONZERO"], enforcement),
      ...output,
      ...(closed.code === null ? {} : { exitCode: closed.code }),
      ...(closed.signal ? { signal: closed.signal } : {}),
    };
  } catch {
    result = { ...emptyResult("failed", started, ["RUNTIME_SPAWN_FAILED"], enforcement), stdout: redact(stdout), stderr: redact(stderr) };
  } finally {
    if (timer) clearTimeout(timer);
    if (killTimer) clearTimeout(killTimer);
    if (!child.killed && child.exitCode === null) terminate(child);
    if (!cleanup) result.cleanup = "completed";
    else {
      try { await cleanup(); result.cleanup = "completed"; }
      catch (error) { result.cleanup = "failed"; result.reasonCodes = [...new Set([...result.reasonCodes, "CONTAINER_CLEANUP_FAILED"])]; result.stderr = `${result.stderr}${result.stderr.length > 0 ? "\\n" : ""}${error instanceof Error ? error.message : String(error)}`; }
    }
  }
  return { ...result, telemetry: await collectTelemetry(child.pid, runtimeExposesResources, firstSample) };
}

function processEnvironment(env: Record<string, string>): Record<string, string> {
  const safeEnv: Record<string, string> = { PATH: process.env.PATH ?? "", ...env };
  safeEnv.NODE_OPTIONS = "";
  return safeEnv;
}

async function runDocker(request: CanonicalRequest, enforcement: EnforcementCapabilities, started: number): Promise<ContainmentResult> {
  if (!(await dockerImageAvailable(request.profile.imageDigest!))) return emptyResult("unsupported", started, ["DOCKER_IMAGE_UNAVAILABLE"], { ...enforcement, sandbox: "unavailable", network: "unknown", readOnlyRoot: false, nonRoot: false, noNewPrivileges: false });
  const containerName = `invock-containment-${process.pid}-${Date.now()}-${containerSequence++}`;
  const child = spawn("docker", buildDockerRunArgs(request.profile, request.root, request.command, request.args, request.env, containerName), {
    cwd: request.root, shell: false, detached: true, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  return execute(child, request.profile, enforcement, started, () => cleanupDockerContainer(containerName), false);
}

/** Execute one canonical, allow-listed fixture under an enforceable local profile. */
export async function runContained(request: ContainmentRequest): Promise<ContainmentResult> {
  const started = Date.now();
  if (!request || typeof request !== "object" || !request.profile || typeof request.profile !== "object") return emptyResult("denied", started, ["PROFILE_INVALID"], capabilities("not_requested", false));
  const parsed = validateProfile(request.profile);
  if (!parsed.profile) return emptyResult("denied", started, [parsed.reason ?? "PROFILE_INVALID"], capabilities("not_requested", false));
  const canonical = await canonicalize(request, parsed.profile);
  if (!canonical.request) return emptyResult("denied", started, [canonical.reason ?? "REQUEST_INVALID"], capabilities("not_requested", false));
  const profile = canonical.request.profile;
  if (profile.sandbox === "none") {
    if (profile.mounts.length > 0) return emptyResult("unsupported", started, ["MOUNTS_REQUIRE_ENFORCED_RUNTIME"], capabilities("not_requested", false));
    const child = spawn(process.execPath, [join(canonical.request.root, canonical.request.command), ...canonical.request.args], {
      cwd: canonical.request.root, shell: false, detached: true, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: processEnvironment(canonical.request.env),
    });
    return execute(child, profile, capabilities("not_requested", false), started);
  }
  if (profile.mounts.length > 0 && !profile.image) return emptyResult("unsupported", started, ["MOUNTS_UNSUPPORTED_ON_MACOS_SANDBOX"], { sandbox: "unavailable", network: "unknown", readOnlyRoot: false, nonRoot: false, noNewPrivileges: false });
  if (profile.image) {
    if (!(await dockerAvailable())) return emptyResult("unsupported", started, ["DOCKER_RUNTIME_UNAVAILABLE"], capabilities("unavailable", false));
    return runDocker(canonical.request, capabilities("available", true), started);
  }
  return emptyResult("unsupported", started, ["REQUIRED_CONTAINMENT_RUNTIME_UNAVAILABLE", "ISOLATION_NOT_CLAIMED"], capabilities("unavailable", false));
}

export type { ContainmentProfile, ContainmentRequest, ContainmentResult } from "./types.js";
