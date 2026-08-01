import { access, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { spawn } from "node:child_process";
import { isAbsolute, join, relative, sep } from "node:path";
import type { ContainmentRequest, ContainmentResult } from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024;
const DEFAULT_MAX_ARGV_BYTES = 8 * 1024;
const NETWORK_COMMANDS = new Set(["curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "ftp", "telnet", "socat"]);
const SECRET = /(authorization|cookie|token|password|secret|api[_-]?key)\s*([=:])\s*[^\s,;]+/giu;

function redact(value: string): string {
  return value.replaceAll(SECRET, "$1$2[REDACTED]");
}

function result(status: ContainmentResult["status"], started: number, reasonCodes: string[], capability: ContainmentResult["capabilities"]["sandbox"]): ContainmentResult {
  return { status, stdout: "", stderr: "", durationMs: Date.now() - started, reasonCodes, capabilities: { sandbox: capability, network: "denied" } };
}

function boundedBytes(argv: string[]): number {
  return Buffer.byteLength(JSON.stringify(argv), "utf8");
}

async function sandboxAvailable(): Promise<boolean> {
  if (process.platform !== "darwin") return false;
  try { await access("/usr/bin/sandbox-exec", constants.X_OK); return true; } catch { return false; }
}

/** Execute one allow-listed script beneath fixtureRoot. No shell or public network is used. */
export async function runContained(request: ContainmentRequest): Promise<ContainmentResult> {
  const started = Date.now();
  const profile = request.profile;
  const sandbox = profile.sandbox === "required" ? (await sandboxAvailable() ? "available" : "unavailable") : "not_requested";
  // Detection alone is not containment. Until a restrictive, tested policy is
  // applied to the child, fail closed even when the host exposes sandbox-exec.
  if (profile.sandbox === "required") return result("unsupported", started, [sandbox === "available" ? "SANDBOX_POLICY_UNAVAILABLE" : "SANDBOX_UNAVAILABLE", "ISOLATION_NOT_CLAIMED"], sandbox);

  const args = request.argv ?? [];
  const maxArgvBytes = profile.maxArgvBytes ?? DEFAULT_MAX_ARGV_BYTES;
  if (boundedBytes([request.command, ...args]) > maxArgvBytes) return result("denied", started, ["ARGV_BOUND_EXCEEDED"], sandbox);
  if (request.env !== undefined && Object.keys(request.env).some(key => /(token|secret|password|key|credential)/iu.test(key))) return result("denied", started, ["SECRET_ENV_DENIED"], sandbox);
  const base = request.command.replaceAll("\\", "/").split("/").pop() ?? request.command;
  if (NETWORK_COMMANDS.has(base.toLowerCase()) || args.some(arg => NETWORK_COMMANDS.has(arg.toLowerCase()))) return result("denied", started, ["NETWORK_DENIED"], sandbox);
  if (!profile.allowedCommands.includes(request.command) || isAbsolute(request.command) || request.command.includes("..")) return result("denied", started, ["COMMAND_NOT_ALLOWLISTED"], sandbox);

  let root: string;
  let executable: string;
  try {
    root = await realpath(profile.fixtureRoot);
    executable = await realpath(join(root, request.command));
    const rel = relative(root, executable);
    if (rel === "" || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return result("denied", started, ["FIXTURE_ESCAPE"], sandbox);
    await access(executable, constants.R_OK);
  } catch { return result("denied", started, ["FIXTURE_NOT_FOUND"], sandbox); }

  const childArgs = [executable, ...args];
  const child = spawn(process.execPath, childArgs, {
    cwd: root,
    shell: false,
    detached: true,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: process.env.PATH ?? "", NODE_OPTIONS: "", ...(request.env ?? {}) },
  });
  let stdout = "";
  let stderr = "";
  let outputExceeded = false;
  const maxOutputBytes = profile.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const append = (target: "stdout" | "stderr", chunk: Buffer): void => {
    const next = Buffer.byteLength(stdout, "utf8") + Buffer.byteLength(stderr, "utf8") + chunk.byteLength;
    if (next > maxOutputBytes) { outputExceeded = true; return; }
    if (target === "stdout") stdout += chunk.toString("utf8"); else stderr += chunk.toString("utf8");
  };
  child.stdout.on("data", chunk => append("stdout", Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
  child.stderr.on("data", chunk => append("stderr", Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
  let timedOut = false;
  let timer = setTimeout(() => { timedOut = true; terminate(child); }, profile.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  timer.unref();
  const closed = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once("close", (code, signal) => resolve({ code, signal })));
  clearTimeout(timer);
  if (timedOut) return { ...result("timed_out", started, ["TIMEOUT"], sandbox), stdout: redact(stdout), stderr: redact(stderr), ...(closed.signal === null ? {} : { signal: closed.signal }) };
  if (outputExceeded) return { ...result("denied", started, ["OUTPUT_BOUND_EXCEEDED"], sandbox), stdout: redact(stdout.slice(0, maxOutputBytes)), stderr: redact(stderr) };
  return { ...result(closed.code === 0 ? "completed" : "failed", started, closed.code === 0 ? [] : ["CHILD_EXIT_NONZERO"], sandbox), stdout: redact(stdout), stderr: redact(stderr), ...(closed.code === null ? {} : { exitCode: closed.code }), ...(closed.signal === null ? {} : { signal: closed.signal }) };
}

function terminate(child: ReturnType<typeof spawn>): void {
  if (child.pid === undefined) return;
  try { process.kill(-child.pid, "SIGTERM"); } catch { try { child.kill("SIGTERM"); } catch { /* already gone */ } }
  const killTimer = setTimeout(() => { try { process.kill(-child.pid!, "SIGKILL"); } catch { /* already gone */ } }, 250);
  killTimer.unref();
}

export type { ContainmentProfile, ContainmentRequest, ContainmentResult } from "./types.js";
