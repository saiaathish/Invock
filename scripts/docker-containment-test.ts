import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runContained, type ContainmentResult } from "../src/containment/runner.js";

const VERSION_TIMEOUT_MS = 5_000;
const BUILD_TIMEOUT_MS = 120_000;
const ATTACK_TIMEOUT_MS = 10_000;
const MAX_OUTPUT = 4_096;

function timedOut(error: Error | undefined): boolean {
  return Boolean(error && "code" in error && error.code === "ETIMEDOUT");
}

function output(value: string | Buffer | null | undefined): string {
  const text = value?.toString() ?? "";
  return text.length > MAX_OUTPUT ? `${text.slice(0, MAX_OUTPUT)}...[truncated]` : text;
}

function cleanupContainer(name: string): "completed" | "failed" {
  const cleanup = spawnSync("docker", ["rm", "--force", name], { encoding: "utf8", timeout: 5_000, killSignal: "SIGKILL", stdio: ["ignore", "pipe", "pipe"] });
  return cleanup.status === 0 || cleanup.status === 1 ? "completed" : "failed";
}

function imageDigest(): string | undefined {
  const result = spawnSync("docker", ["image", "inspect", "invock-containment:local", "--format", "{{.Id}}"], { encoding: "utf8", timeout: VERSION_TIMEOUT_MS, killSignal: "SIGKILL" });
  const digest = result.stdout?.trim();
  return result.status === 0 && digest && /^sha256:[0-9a-f]{64}$/u.test(digest) ? digest : undefined;
}

function parseObservation(result: ContainmentResult): { hostRead: boolean; writeDenied: boolean; networkDenied: boolean } | undefined {
  try {
    const value: unknown = JSON.parse(result.stdout);
    if (value === null || typeof value !== "object") return undefined;
    const record = value as Record<string, unknown>;
    if (typeof record.hostRead !== "boolean" || typeof record.writeDenied !== "boolean" || typeof record.networkDenied !== "boolean") return undefined;
    return { hostRead: record.hostRead, writeDenied: record.writeDenied, networkDenied: record.networkDenied };
  } catch {
    return undefined;
  }
}

function productProbePassed(result: ContainmentResult): boolean {
  const observation = parseObservation(result);
  return result.status === "completed"
    && result.cleanup === "completed"
    && result.capabilities.sandbox === "available"
    && result.capabilities.network === "denied"
    && result.capabilities.readOnlyRoot
    && result.capabilities.nonRoot
    && result.capabilities.noNewPrivileges
    && observation?.hostRead === false
    && observation.writeDenied
    && observation.networkDenied;
}

async function runProductProbe(digest: string): Promise<ContainmentResult> {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "invock-docker-product-fixture-"));
  const hostProbeDirectory = mkdtempSync(join(tmpdir(), "invock-docker-host-probe-"));
  const hostProbe = join(hostProbeDirectory, "host-only.txt");
  try {
    copyFileSync(fileURLToPath(new URL("../fixtures/containment/adversarial.js", import.meta.url)), join(fixtureRoot, "adversarial.js"));
    writeFileSync(hostProbe, "host-only-containment-probe\n", { mode: 0o600 });
    return await runContained({
      profile: {
        fixtureRoot,
        allowedCommands: ["adversarial.js"],
        sandbox: "required",
        network: "none",
        readOnlyRoot: true,
        nonRoot: true,
        noNewPrivileges: true,
        timeoutMs: 5_000,
        maxOutputBytes: 16 * 1024,
        maxPids: 32,
        memoryLimitMb: 64,
        cpuSeconds: 1,
        image: "invock-containment:local",
        imageDigest: digest,
      },
      command: "adversarial.js",
      env: { INVOCK_HOST_READ_PROBE: hostProbe, INVOCK_WRITE_TARGET: "/fixture/.invock-write-probe" },
    });
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
    rmSync(hostProbeDirectory, { recursive: true, force: true });
  }
}

async function main(): Promise<number> {
  const probe = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8", timeout: VERSION_TIMEOUT_MS, killSignal: "SIGKILL" });
  if (probe.status !== 0) {
    console.log(JSON.stringify({ status: "unsupported", reason: "DOCKER_RUNTIME_UNAVAILABLE", detail: timedOut(probe.error) ? "version probe timed out" : output(probe.stderr) }));
    return 2;
  }

  const build = spawnSync("docker", ["build", "--tag", "invock-containment:local", "--file", "docker/containment.Dockerfile", "."], { encoding: "utf8", timeout: BUILD_TIMEOUT_MS, killSignal: "SIGKILL" });
  if (build.status !== 0) {
    console.log(JSON.stringify({ status: "fail", reason: timedOut(build.error) ? "DOCKER_IMAGE_BUILD_TIMEOUT" : "DOCKER_IMAGE_BUILD_FAILED", stdout: output(build.stdout), stderr: output(build.stderr) }));
    return 1;
  }
  const digest = imageDigest();
  if (!digest) {
    console.log(JSON.stringify({ status: "unsupported", reason: "DOCKER_IMAGE_DIGEST_UNAVAILABLE" }));
    return 2;
  }

  const attack = "const fs=require('node:fs'); let writeDenied=false; try{fs.writeFileSync('/etc/invock-attack','x')}catch{writeDenied=true} const controller=new AbortController(); setTimeout(()=>controller.abort(),300); fetch('http://example.com',{signal:controller.signal}).then(()=>process.exit(1)).catch(()=>process.exit(writeDenied?0:1));";
  const containerName = `invock-containment-certify-${process.pid}-${Date.now()}`;
  const result = spawnSync("docker", ["run", "--rm", "--name", containerName, "--network", "none", "--read-only", "--memory", "64m", "--cpus", "0.5", "--pids-limit", "64", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "invock-containment:local", "-e", attack], { encoding: "utf8", timeout: ATTACK_TIMEOUT_MS, killSignal: "SIGKILL" });
  const cleanup = timedOut(result.error) ? cleanupContainer(containerName) : "completed";
  const directPassed = result.status === 0;
  const product = directPassed ? await runProductProbe(digest) : undefined;
  const passed = directPassed && product !== undefined && productProbePassed(product);
  const unsupported = !directPassed && timedOut(result.error) ? false : product?.status === "unsupported";
  const reason = timedOut(result.error)
    ? "DOCKER_CONTAINMENT_TIMEOUT"
    : cleanup === "failed"
      ? "DOCKER_CLEANUP_FAILED"
      : product && !productProbePassed(product)
        ? product.reasonCodes[0] ?? "DOCKER_PRODUCT_CONTAINMENT_ASSERTION_FAILED"
        : undefined;
  console.log(JSON.stringify({ status: passed ? "pass" : unsupported ? "unsupported" : "fail", reason, imageDigest: digest, direct: { exitCode: result.status, stdout: output(result.stdout), stderr: output(result.stderr), cleanup }, productRunner: product }));
  return passed ? 0 : unsupported ? 2 : 1;
}

main().then(code => { process.exitCode = code; }).catch(error => { console.error(error instanceof Error ? error.stack : String(error)); process.exitCode = 1; });
