import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runContained, type ContainmentResult } from "./runner.js";

const LOCAL_CERTIFICATION_IMAGE = "invock-containment:local";
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/u;
const DOCKER_INSPECT_TIMEOUT_MS = 5_000;

export interface ContainmentCertification {
  schemaVersion: "invock/containment-certification/v1";
  status: "pass" | "degraded" | "unsupported" | "fail";
  runtime: { platform: string; arch: string; node: string };
  checks: {
    execution: boolean;
    hostReadDenied: boolean;
    writeDenied: boolean;
    networkDenied: boolean;
    readOnlyRoot: boolean;
    nonRoot: boolean;
    noNewPrivileges: boolean;
    cleanup: boolean;
  };
  result: ContainmentResult;
  limitations: string[];
}

function observation(result: ContainmentResult): { hostRead: boolean; writeDenied: boolean; networkDenied: boolean } | undefined {
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

/** Discover only a locally cached image; never pulls or treats a tag as proof. */
async function localImageDigest(image: string): Promise<string | undefined> {
  return await new Promise(resolveDigest => {
    const child = spawn("docker", ["image", "inspect", image, "--format", "{{.Id}}"], {
      stdio: ["ignore", "pipe", "ignore"],
      shell: false,
      windowsHide: true,
    });
    let stdout = "";
    let settled = false;
    const finish = (digest: string | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveDigest(digest);
    };
    const timer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
      finish(undefined);
    }, DOCKER_INSPECT_TIMEOUT_MS);
    timer.unref();
    child.stdout?.on("data", chunk => {
      if (stdout.length < 256) stdout += chunk.toString("utf8").slice(0, 256 - stdout.length);
    });
    child.once("error", () => finish(undefined));
    child.once("close", code => {
      const digest = stdout.trim();
      finish(code === 0 && IMAGE_DIGEST.test(digest) ? digest : undefined);
    });
  });
}

export async function certifyContainment(fixtureRoot = resolve(process.cwd(), "fixtures/containment")): Promise<ContainmentCertification> {
  const writeTarget = join(fixtureRoot, `.containment-write-probe-${process.pid}-${Date.now()}`);
  const hostProbeDirectory = await mkdtemp(join(tmpdir(), "invock-containment-host-probe-"));
  const hostReadProbe = join(hostProbeDirectory, "host-only.txt");
  await writeFile(hostReadProbe, "host-only-containment-probe\n", { mode: 0o600 });
  const configuredImage = process.env.INVOCK_CONTAINMENT_IMAGE?.trim();
  const certificationImage = configuredImage || LOCAL_CERTIFICATION_IMAGE;
  const imageDigest = await localImageDigest(certificationImage);
  let result: ContainmentResult;
  try {
    result = await runContained({
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
        ...(imageDigest ? { image: certificationImage, imageDigest } : {}),
      },
      command: "adversarial.js",
      env: { INVOCK_HOST_READ_PROBE: hostReadProbe, INVOCK_WRITE_TARGET: writeTarget },
    });
  } finally {
    await rm(writeTarget, { force: true });
    await rm(hostProbeDirectory, { recursive: true, force: true });
  }

  const seen = observation(result);
  const checks = {
    execution: result.status === "completed" && seen !== undefined,
    hostReadDenied: seen?.hostRead === false,
    writeDenied: seen?.writeDenied === true,
    networkDenied: seen?.networkDenied === true,
    readOnlyRoot: result.capabilities.readOnlyRoot,
    nonRoot: result.capabilities.nonRoot,
    noNewPrivileges: result.capabilities.noNewPrivileges,
    cleanup: result.cleanup === "completed",
  };
  const adversarialChecks = checks.execution && checks.hostReadDenied && checks.writeDenied && checks.networkDenied && checks.readOnlyRoot && checks.nonRoot && checks.cleanup;
  const status = result.status === "unsupported" ? "unsupported" : !adversarialChecks ? "fail" : checks.noNewPrivileges ? "pass" : "degraded";
  const limitations = status === "degraded"
    ? ["NO_NEW_PRIVILEGES_UNAVAILABLE_ON_MACOS_SEATBELT", "DOCKER_IMAGE_NOT_AVAILABLE_FOR_DEFAULT_CERTIFICATION"]
    : status === "unsupported"
      ? ["REQUIRED_CONTAINMENT_RUNTIME_UNAVAILABLE"]
      : [];
  return {
    schemaVersion: "invock/containment-certification/v1",
    status,
    runtime: { platform: process.platform, arch: process.arch, node: process.version },
    checks,
    result,
    limitations,
  };
}
