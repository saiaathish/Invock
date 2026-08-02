import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function cli(directory: string, ...args: string[]): string { return execFileSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], { cwd: process.cwd(), env: { ...process.env, NO_COLOR: "1" }, encoding: "utf8" }); }

test("CLI help and local lifecycle commands work in a disposable directory", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-cli-test-"));
  try {
    const state = join(directory, "state.json"); const database = join(directory, "receipts.sqlite"); const keys = join(directory, "keys");
    assert.match(cli(directory, "--help"), /invock init/u);
    const initialized = JSON.parse(cli(directory, "init", "--state", state)) as { initialized: boolean };
    assert.equal(initialized.initialized, true);
    const scanned = JSON.parse(cli(directory, "scan", "--state", state)) as { scope: string; unsupportedIntegrations: string[] };
    assert.equal(scanned.scope, "local-control-plane"); assert.ok(scanned.unsupportedIntegrations.length > 0);
    const exported = JSON.parse(cli(directory, "receipts", "export", "--format", "json", "--database", database, "--key-directory", keys)) as { formatVersion: string; receipts: unknown[] };
    assert.equal(exported.formatVersion, "invock/evidence-bundle/v1"); assert.deepEqual(exported.receipts, []);
    const bundled = cli(directory, "evidence", "bundle", "--format", "markdown", "--database", database, "--key-directory", keys);
    assert.match(bundled, /Invock evidence bundle/u);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI serve wires SDK authorization to the canonical fail-closed gate", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-cli-api-test-"));
  const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", "serve", "--database", join(directory, "receipts.sqlite"), "--key-directory", join(directory, "keys")], { cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, NO_COLOR: "1" } });
  let stderr = "";
  const ready = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("CLI server did not start")), 5_000);
    child.stderr?.on("data", chunk => {
      stderr += chunk.toString();
      if (stderr.includes("Invock dashboard token:")) { clearTimeout(timer); resolve(); }
    });
    child.once("error", error => { clearTimeout(timer); reject(error); });
  });
  try {
    await ready;
    const url = /^Invock dashboard: (http:\/\/[^\s]+)$/mu.exec(stderr)?.[1];
    const token = /^Invock dashboard token: ([^\s]+)$/mu.exec(stderr)?.[1];
    assert.ok(url && token);
    const response = await fetch(`${url}/api/v1/authorize`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ agent: "cli-test", tool: "read_file", arguments: { path: "/workspace/README.md" } }) });
    assert.equal(response.status, 200);
    const decision = await response.json() as { verdict: string; reasonCodes: string[] };
    assert.equal(decision.verdict, "BLOCK");
    assert.ok(decision.reasonCodes.includes("STRICT_AUTHORITY_REQUIRED"));
  } finally {
    child.kill("SIGTERM");
    await new Promise<void>(resolve => { if (child.exitCode !== null || child.signalCode !== null) resolve(); else child.once("close", () => resolve()); });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI strict-authority mode blocks policy-only API calls", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-cli-strict-test-"));
  const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", "serve", "--strict-authority", "--database", join(directory, "receipts.sqlite"), "--key-directory", join(directory, "keys")], { cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, NO_COLOR: "1" } });
  let stderr = "";
  const ready = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("strict CLI server did not start")), 5_000);
    child.stderr?.on("data", chunk => {
      stderr += chunk.toString();
      if (stderr.includes("Invock dashboard token:")) { clearTimeout(timer); resolve(); }
    });
    child.once("error", error => { clearTimeout(timer); reject(error); });
  });
  try {
    await ready;
    const url = /^Invock dashboard: (http:\/\/[^\s]+)$/mu.exec(stderr)?.[1];
    const token = /^Invock dashboard token: ([^\s]+)$/mu.exec(stderr)?.[1];
    const sessionId = /^Invock API session: ([^\s]+)$/mu.exec(stderr)?.[1];
    assert.ok(url && token && sessionId);
    const response = await fetch(`${url}/api/v1/authorize`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ agent: "cli-test", projectId: "project-1", sessionId, tool: "read_file", arguments: { path: "/workspace/README.md" } }) });
    assert.equal(response.status, 200);
    const decision = await response.json() as { verdict: string; reasonCodes: string[] };
    assert.equal(decision.verdict, "BLOCK");
    assert.deepEqual(decision.reasonCodes, ["STRICT_AUTHORITY_REQUIRED"]);
  } finally {
    child.kill("SIGTERM");
    await new Promise<void>(resolve => { if (child.exitCode !== null || child.signalCode !== null) resolve(); else child.once("close", () => resolve()); });
    rmSync(directory, { recursive: true, force: true });
  }
});
