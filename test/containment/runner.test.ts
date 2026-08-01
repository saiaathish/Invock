import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runContained, type ContainmentProfile } from "../../src/containment/index.js";

const fixtureRoot = fileURLToPath(new URL("../../fixtures/containment/", import.meta.url));
const profile = (overrides: Partial<ContainmentProfile> = {}): ContainmentProfile => ({ fixtureRoot, allowedCommands: ["emit.js"], ...overrides });

test("runner executes an allow-listed local fixture", async () => {
  const result = await runContained({ profile: profile(), command: "emit.js" });
  assert.equal(result.status, "completed");
  assert.equal(result.stdout, "ok\n");
  assert.equal(result.capabilities.network, "denied");
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
});

test("runner fails closed when required sandbox is unavailable", async () => {
  const result = await runContained({ profile: profile({ sandbox: "required" }), command: "emit.js" });
  if (process.platform !== "darwin" || !existsSync("/usr/bin/sandbox-exec")) {
    assert.equal(result.status, "unsupported");
    assert.match(result.reasonCodes.join(","), /SANDBOX_UNAVAILABLE/u);
  }
});

test("runner rejects fixture escape and oversized argv", async () => {
  const escaped = await runContained({ profile: profile({ allowedCommands: ["../emit.js"] }), command: "../emit.js" });
  assert.equal(escaped.status, "denied");
  const oversized = await runContained({ profile: profile({ maxArgvBytes: 4 }), command: "emit.js", argv: ["12345"] });
  assert.equal(oversized.status, "denied");
});
