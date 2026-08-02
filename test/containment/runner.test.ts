import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runContained, type ContainmentProfile } from "../../src/containment/index.js";
import { buildDockerRunArgs } from "../../src/containment/runner.js";

const fixtureRoot = fileURLToPath(new URL("../../fixtures/containment/", import.meta.url));
const profile = (overrides: Partial<ContainmentProfile> = {}): ContainmentProfile => ({ fixtureRoot, allowedCommands: ["emit.js"], sandbox: "none", ...overrides });

test("runner executes a local fixture without claiming unenforced isolation", async () => {
  const result = await runContained({ profile: profile(), command: "emit.js" });
  assert.equal(result.status, "completed");
  assert.equal(result.stdout, "ok\n");
  assert.equal(result.capabilities.sandbox, "not_requested");
  assert.equal(result.capabilities.network, "unknown");
  assert.equal(result.capabilities.readOnlyRoot, false);
  assert.equal(result.capabilities.nonRoot, false);
  assert.equal(result.capabilities.noNewPrivileges, false);
  assert.equal(result.cleanup, "completed");
  assert.equal(result.telemetry?.pid.status, "observed");
  if (result.telemetry?.pid.status === "observed") assert.ok(result.telemetry.pid.value > 0);
  assert.ok(result.telemetry?.cpuMs.status === "observed" || result.telemetry?.cpuMs.status === "unavailable");
  assert.ok(result.telemetry?.memoryBytes.status === "observed" || result.telemetry?.memoryBytes.status === "unavailable");
});

test("denied requests carry bounded explicit-unavailable telemetry", async () => {
  const result = await runContained({ profile: profile({ maxArgvBytes: 1 }), command: "emit.js", argv: ["too-large"] });
  assert.equal(result.status, "denied");
  assert.deepEqual(result.telemetry, {
    pid: { status: "unavailable", reason: "process_not_spawned" },
    cpuMs: { status: "unavailable", reason: "process_not_spawned" },
    memoryBytes: { status: "unavailable", reason: "process_not_spawned" },
  });
});

test("runner enforces timeout and terminates the process group", async () => {
  const result = await runContained({ profile: profile({ timeoutMs: 50 }), command: "emit.js", argv: ["sleep", "5000"] });
  assert.equal(result.status, "timed_out");
  assert.match(result.reasonCodes.join(","), /TIMEOUT/u);
});

test("runner enforces output bound", async () => {
  const result = await runContained({ profile: profile({ maxOutputBytes: 32 }), command: "emit.js", argv: ["output", "1000"] });
  assert.equal(result.status, "denied");
  assert.match(result.reasonCodes.join(","), /OUTPUT_BOUND_EXCEEDED/u);
});

test("runner denies network commands before spawning", async () => {
  const result = await runContained({ profile: profile({ allowedCommands: ["curl"] }), command: "curl", argv: ["https://example.com"] });
  assert.equal(result.status, "denied");
  assert.deepEqual(result.reasonCodes, ["NETWORK_DENIED"]);
  assert.equal(result.capabilities.network, "unknown");
});

test("required sandbox is unsupported without an enforceable runtime", async () => {
  const result = await runContained({ profile: profile({ sandbox: "required" }), command: "emit.js" });
  assert.equal(result.status, "unsupported");
  assert.equal(result.capabilities.sandbox, "unavailable");
  assert.equal(result.capabilities.network, "unknown");
  assert.equal(result.capabilities.readOnlyRoot, false);
});

test("required profiles never fall back to an untrusted macOS Seatbelt boundary", async () => {
  const result = await runContained({ profile: profile({ sandbox: "required", allowedCommands: ["adversarial.js"] }), command: "adversarial.js" });
  assert.equal(result.status, "unsupported");
  assert.equal(result.capabilities.sandbox, "unavailable");
  assert.ok(result.reasonCodes.includes("REQUIRED_CONTAINMENT_RUNTIME_UNAVAILABLE"));
});

test("required profiles do not execute a sibling-repository probe without Docker", async () => {
  const repositoryProbe = fileURLToPath(new URL("../../README.md", import.meta.url));
  const result = await runContained({
    profile: profile({ sandbox: "required", allowedCommands: ["adversarial.js"] }),
    command: "adversarial.js",
    env: { INVOCK_HOST_READ_PROBE: repositoryProbe },
  });
  assert.equal(result.status, "unsupported");
  assert.equal(result.stdout, "");
});

test("runner rejects shell, absolute, parent, and oversized argv", async () => {
  const shell = await runContained({ profile: profile({ allowedCommands: ["sh"] }), command: "sh", argv: ["-c", "echo no"] });
  assert.equal(shell.status, "denied");
  assert.ok(shell.reasonCodes.includes("SHELL_COMMAND_DENIED"));
  const absolute = await runContained({ profile: profile({ allowedCommands: ["/bin/echo"] }), command: "/bin/echo" });
  assert.equal(absolute.status, "denied");
  const escaped = await runContained({ profile: profile({ allowedCommands: ["../emit.js"] }), command: "../emit.js" });
  assert.equal(escaped.status, "denied");
  assert.ok(escaped.reasonCodes.includes("COMMAND_PATH_INVALID"));
  const argvEscape = await runContained({ profile: profile(), command: "emit.js", argv: ["../outside.txt"] });
  assert.equal(argvEscape.status, "denied");
  assert.deepEqual(argvEscape.reasonCodes, ["ARGV_PATH_INVALID"]);
  const argvAbsolute = await runContained({ profile: profile(), command: "emit.js", argv: ["/etc/passwd"] });
  assert.equal(argvAbsolute.status, "denied");
  assert.deepEqual(argvAbsolute.reasonCodes, ["ARGV_PATH_INVALID"]);
  const oversized = await runContained({ profile: profile({ maxArgvBytes: 4 }), command: "emit.js", argv: ["12345"] });
  assert.equal(oversized.status, "denied");
  assert.ok(oversized.reasonCodes.includes("ARGV_BOUND_EXCEEDED"));
});

test("runner rejects secret environment names and unpinned Docker images", async () => {
  const env = await runContained({ profile: profile({}), command: "emit.js", env: { API_TOKEN: "not-a-real-secret" } });
  assert.equal(env.status, "denied");
  assert.deepEqual(env.reasonCodes, ["SECRET_ENV_DENIED"]);
  const image = await runContained({ profile: profile({ sandbox: "required", image: "node:22-bookworm-slim" }), command: "emit.js" });
  assert.equal(image.status, "denied");
  assert.deepEqual(image.reasonCodes, ["IMAGE_NOT_DIGEST_PINNED"]);
  const malformedDigest = await runContained({ profile: profile({ sandbox: "required", image: "node:22-bookworm-slim", imageDigest: "sha256:not-a-digest" }), command: "emit.js" });
  assert.equal(malformedDigest.status, "denied");
  assert.deepEqual(malformedDigest.reasonCodes, ["IMAGE_NOT_DIGEST_PINNED"]);
});

test("Docker profile includes every secure-default invariant", () => {
  const args = buildDockerRunArgs({
    fixtureRoot,
    allowedCommands: ["emit.js"],
    sandbox: "required",
    image: "node:22-bookworm-slim",
    imageDigest: `sha256:${"a".repeat(64)}`,
  }, fixtureRoot, "emit.js", ["ok"]);
  assert.deepEqual(args.slice(0, 12), [
    "run", "--rm", "--pull=never", "--network", "none", "--read-only",
    "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532", "--pids-limit",
  ]);
  assert.ok(args.includes("--memory"));
  assert.ok(args.includes("--cpus"));
  assert.ok(args.some(value => value.startsWith("type=bind,src=") && value.endsWith(",dst=/fixture,readonly")));
  assert.ok(args.includes("--tmpfs"));
  assert.ok(args.includes("--pull=never"));
  assert.equal(args.at(-2), "/fixture/emit.js");
});

test("runner rejects symlinked fixture commands and cleans temporary fixtures", async () => {
  const directory = await mkdtemp(join(tmpdir(), "invock-containment-"));
  try {
    await writeFile(join(directory, "outside.js"), "process.stdout.write('outside\\n')\n");
    await symlink(join(directory, "outside.js"), join(directory, "link.js"));
    const result = await runContained({ profile: { fixtureRoot: directory, allowedCommands: ["link.js"], sandbox: "none" }, command: "link.js" });
    assert.equal(result.status, "denied");
    assert.deepEqual(result.reasonCodes, ["FIXTURE_SYMLINK"]);
    const mountEscape = await runContained({ profile: { fixtureRoot: directory, allowedCommands: ["outside.js"], sandbox: "none", mounts: [{ source: "/etc/hosts", target: "/fixture/escape" }] }, command: "outside.js" });
    assert.equal(mountEscape.status, "denied");
    assert.deepEqual(mountEscape.reasonCodes, ["MOUNT_SOURCE_ESCAPE"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("runner rejects symlinked and writable mounts before execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "invock-containment-"));
  try {
    await symlink(directory, join(directory, "mount-link"));
    const symlinkMount = await runContained({ profile: profile({ mounts: [{ source: join(directory, "mount-link"), target: "/fixture/input" }] }), command: "emit.js" });
    assert.equal(symlinkMount.status, "denied");
    assert.deepEqual(symlinkMount.reasonCodes, ["MOUNT_SYMLINK"]);
    const writableMount = await runContained({ profile: profile({ mounts: [{ source: directory, target: "/fixture/input", readOnly: false }] }), command: "emit.js" });
    assert.equal(writableMount.status, "denied");
    assert.deepEqual(writableMount.reasonCodes, ["MOUNTS_MUST_BE_READ_ONLY"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("runner redacts sensitive output and leaves no temporary fixture", async () => {
  const directory = await mkdtemp(join(tmpdir(), "invock-containment-"));
  try {
    await mkdir(join(directory, "nested"));
    await writeFile(join(directory, "secret.js"), "process.stdout.write('token=real-value authorization: Bearer real-token\\n')\n");
    const result = await runContained({ profile: { fixtureRoot: directory, allowedCommands: ["secret.js"], sandbox: "none" }, command: "secret.js" });
    assert.equal(result.status, "completed");
    assert.equal(result.stdout, "token=[REDACTED] authorization: Bearer [REDACTED]\n");
    assert.equal(await readFile(join(directory, "secret.js"), "utf8"), "process.stdout.write('token=real-value authorization: Bearer real-token\\n')\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
