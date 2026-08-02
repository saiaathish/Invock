import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { persistContainmentRun, readContainmentRun, verifyContainmentRun } from "../../src/containment/lifecycle.js";
import { unavailableTelemetry } from "../../src/containment/types.js";
import { digestJson } from "../../src/core/canonical.js";

test("containment run records are versioned, inspectable, and isolated by run id", async () => {
  const directory = await mkdtemp(join(tmpdir(), "invock-containment-records-"));
  try {
    const record = {
      schemaVersion: "invock/containment-run/v2" as const,
      runId: "containment_test",
      createdAt: new Date(0).toISOString(),
      requestDigest: digestJson({ request: "containment-test" }),
      command: "emit.js",
      result: {
        status: "completed" as const,
        stdout: "ok\n",
        stderr: "",
        durationMs: 1,
        reasonCodes: [],
        telemetry: unavailableTelemetry("legacy_record"),
        capabilities: { sandbox: "not_requested" as const, network: "unknown" as const, readOnlyRoot: false, nonRoot: false, noNewPrivileges: false },
      },
    };
    const path = await persistContainmentRun(directory, record);
    assert.equal(path, join(directory, "containment_test.json"));
    const persisted = await readContainmentRun(directory, "containment_test");
    assert.equal(persisted.schemaVersion, "invock/containment-run/v2");
    assert.deepEqual({ ...persisted, integrity: undefined }, { ...record, integrity: undefined });
    assert.equal(verifyContainmentRun(persisted, persisted.integrity.publicKeyPem), true);
    await writeFile(path, JSON.stringify({ ...persisted, result: { ...persisted.result, stdout: "tampered\n" } }));
    await assert.rejects(() => readContainmentRun(directory, "containment_test"), /INTEGRITY/u);
    await assert.rejects(() => readContainmentRun(directory, "missing"), /ENOENT/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("containment record validation rejects oversized telemetry and keeps unavailable states explicit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "invock-containment-telemetry-"));
  try {
    const record = {
      schemaVersion: "invock/containment-run/v2" as const,
      runId: "telemetry_bounds",
      createdAt: new Date(0).toISOString(),
      requestDigest: digestJson({ request: "telemetry" }),
      command: "emit.js",
      result: {
        status: "unsupported" as const,
        stdout: "",
        stderr: "",
        durationMs: 0,
        reasonCodes: ["RUNTIME_UNAVAILABLE"],
        telemetry: {
          pid: { status: "observed" as const, value: 2_147_483_648 },
          cpuMs: { status: "unavailable" as const, reason: "not_supported" as const },
          memoryBytes: { status: "unavailable" as const, reason: "not_supported" as const },
        },
        capabilities: { sandbox: "unavailable" as const, network: "unknown" as const, readOnlyRoot: false, nonRoot: false, noNewPrivileges: false },
      },
    };
    await assert.rejects(() => persistContainmentRun(directory, record), /CONTAINMENT_RUN_INVALID/u);
    const unavailable = { ...record, runId: "telemetry_unavailable", result: { ...record.result, telemetry: unavailableTelemetry("not_supported") } };
    const path = await persistContainmentRun(directory, unavailable);
    const persisted = await readContainmentRun(directory, "telemetry_unavailable");
    assert.equal(path.endsWith("telemetry_unavailable.json"), true);
    assert.deepEqual(persisted.result.telemetry, unavailableTelemetry("not_supported"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
