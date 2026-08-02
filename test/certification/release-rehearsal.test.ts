import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { validateIndependentResults, type ChildRehearsalResult } from "../../scripts/release-rehearsal.js";

const root = resolve(import.meta.dirname, "../..");

function result(runId: string, instanceId: string, port: number): ChildRehearsalResult {
  return {
    schemaVersion: "invock/release-rehearsal/v1",
    runId,
    status: "completed",
    blockers: [],
    localChecks: [],
    runtime: { port, instanceId, statePath: `/${runId}/state.json`, receiptDatabasePath: `/${runId}/receipts.sqlite`, keyDirectory: `/${runId}/keys`, stateCreated: true, receiptDatabaseCreated: true, keyFilesCreated: 1 },
    externalEvidence: { docker: "not-run", browser: "not-run" },
  };
}

test("release rehearsal is registered and exposes its bounded clean-state contract", () => {
  const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as { scripts?: Record<string, string> };
  assert.equal(packageJson.scripts?.["release:rehearsal"], "node --import tsx scripts/release-rehearsal.ts");
  const source = readFileSync(resolve(root, "scripts/release-rehearsal.ts"), "utf8");
  assert.match(source, /mkdtempSync/u);
  assert.match(source, /cpSync/u);
  assert.match(source, /--frozen-lockfile/u);
  assert.match(source, /--store-dir/u);
  assert.match(source, /port: 0/u);
  assert.match(source, /force: false/u);
  assert.match(source, /externalEvidence: \{ docker: "not-run", browser: "not-run" \}/u);
  assert.doesNotMatch(source, /\|\| true/u);
  assert.equal(spawnSync(process.execPath, ["--import", "tsx", "scripts/release-rehearsal.ts", "--help"], { cwd: root, encoding: "utf8" }).status, 0);
});

test("independent-result validation rejects reused runtime identity", () => {
  assert.doesNotThrow(() => validateIndependentResults([result("run-a", "identity-a", 41001), result("run-b", "identity-b", 41002)]));
  assert.throws(() => validateIndependentResults([result("run-a", "same", 41001), result("run-b", "same", 41002)]), /RUNTIME_IDENTITIES_REUSED/u);
  assert.throws(() => validateIndependentResults([result("run-a", "identity-a", 0), result("run-b", "identity-b", 41002)]), /EPHEMERAL_PORT_NOT_FRESH/u);
});

test("independent-result validation refuses external evidence relabeling", () => {
  const invalid = { ...result("run-b", "identity-b", 41002), externalEvidence: { docker: "pass", browser: "not-run" } } as unknown as ChildRehearsalResult;
  assert.throws(() => validateIndependentResults([result("run-a", "identity-a", 41001), invalid]), /EXTERNAL_EVIDENCE_REINTERPRETED/u);
});
