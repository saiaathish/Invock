import { spawnSync } from "node:child_process";

interface CommandResult { stdout: string; stderr: string; status: number | null; timedOut: boolean; }

function timedOut(error: Error | undefined): boolean {
  return Boolean(error && "code" in error && error.code === "ETIMEDOUT");
}

function run(command: string, args: string[]): string {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 180_000, killSignal: "SIGKILL", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed${timedOut(result.error) ? ": COMMAND_TIMEOUT" : ""}\n${result.stderr || result.stdout}`);
  return result.stdout;
}

function runDockerProbe(): CommandResult {
  const result = spawnSync("pnpm", ["docker-containment-test"], { encoding: "utf8", timeout: 180_000, killSignal: "SIGKILL", stdio: ["ignore", "pipe", "pipe"] });
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "", status: result.status, timedOut: timedOut(result.error) };
}

function deterministicDockerOutput(stdout: string): string {
  try {
    const value: unknown = JSON.parse(stdout);
    // Image digests identify each freshly-built image and may vary with the
    // container runtime's build metadata; duration is also intentionally
    // volatile. Compare the containment behavior, while retaining both
    // fields in the emitted probe evidence.
    return JSON.stringify(value, (key, nested) => key === "durationMs" || key === "imageDigest" ? undefined : nested);
  } catch {
    throw new Error("DOCKER_CERTIFICATION_MALFORMED_OUTPUT");
  }
}

run("pnpm", ["test"]);
run("pnpm", ["typecheck"]);
run("pnpm", ["build"]);
const certifyA = run("pnpm", ["certify"]);
const certifyB = run("pnpm", ["certify"]);
if (certifyA !== certifyB) throw new Error("BASE_CERTIFICATION_NONDETERMINISTIC");
const dockerA = runDockerProbe();
const dockerB = runDockerProbe();
if (dockerA.timedOut || dockerB.timedOut) throw new Error("DOCKER_CONTAINMENT_TIMEOUT");
if (dockerA.status === 2 && dockerB.status === 2 && dockerA.stdout.includes('"status":"unsupported"') && dockerB.stdout.includes('"status":"unsupported"')) {
  console.log("INVOCK EXPANDED CERTIFICATION: UNSUPPORTED\nDocker containment certification was not run because the Docker runtime is unavailable.");
  process.exitCode = 2;
} else {
  if (dockerA.status !== 0 || dockerB.status !== 0 || !dockerA.stdout.includes('"status":"pass"') || !dockerB.stdout.includes('"status":"pass"')) throw new Error("DOCKER_CONTAINMENT_NOT_PROVEN");
  if (deterministicDockerOutput(dockerA.stdout) !== deterministicDockerOutput(dockerB.stdout)) throw new Error("DOCKER_CERTIFICATION_NONDETERMINISTIC");
  run("pnpm", ["arena"]);
  run("pnpm", ["mutation-review"]);
  console.log("INVOCK EXPANDED CERTIFICATION: PASS\nFull suite, build, deterministic double certification, Docker attack probe, Arena, and mutation review passed twice where applicable.");
}
