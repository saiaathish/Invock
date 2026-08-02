import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "../..");

test("certification derives the secret-scan result and does not claim untested gates", () => {
  const source = readFileSync(join(root, "scripts/certify.ts"), "utf8");
  assert.match(source, /scanForSecrets\(\)/u);
  assert.match(source, /SECRET_SCAN_FAILED/u);
  assert.match(source, /SECRET_SCAN_INCOMPLETE/u);
  assert.match(source, /Frozen install state: NOT_TESTED/u);
  assert.match(source, /claims: NOT_TESTED/u);
  assert.doesNotMatch(source, /Secret scan: PASS`/u);
});

test("Docker certification reports an unavailable runtime without throwing", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-certification-docker-"));
  try {
    const docker = join(directory, "docker");
    writeFileSync(docker, "#!/bin/sh\nexit 127\n", { mode: 0o755 });
    chmodSync(docker, 0o755);
    const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/docker-containment-test.ts"], {
      cwd: root,
      env: { ...process.env, PATH: `${directory}:${process.env.PATH ?? ""}` },
      encoding: "utf8",
      timeout: 15_000,
    });
    assert.equal(result.status, 2);
    assert.deepEqual(JSON.parse(result.stdout), { status: "unsupported", reason: "DOCKER_RUNTIME_UNAVAILABLE", detail: "" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Docker and final certification commands have hard time bounds", () => {
  const docker = readFileSync(join(root, "scripts/docker-containment-test.ts"), "utf8");
  const expanded = readFileSync(join(root, "scripts/expanded-certify.ts"), "utf8");
  const final = readFileSync(join(root, "scripts/final-certify.ts"), "utf8");
  assert.match(docker, /timeout: VERSION_TIMEOUT_MS/u);
  assert.match(docker, /timeout: BUILD_TIMEOUT_MS/u);
  assert.match(docker, /timeout: ATTACK_TIMEOUT_MS/u);
  assert.match(expanded, /timeout: 180_000/u);
  assert.match(final, /timeout: 180_000/u);
});

test("the authoritative gate invokes a supported protocol command and derives secret-scan status", () => {
  const packageJson = readFileSync(join(root, "package.json"), "utf8");
  const final = readFileSync(join(root, "scripts/final-certify.ts"), "utf8");
  assert.match(packageJson, /"protocol-certify"\s*:/u);
  assert.match(final, /Supported protocol certification command/u);
  assert.match(final, /name: "Secret scan"/u);
  assert.match(final, /Secret scan: PASS/u);
});

test("certification process cleanup rejects asynchronous child execution", () => {
  const final = readFileSync(join(root, "scripts/final-certify.ts"), "utf8");
  assert.match(final, /asynchronousProcessPattern/u);
  assert.match(final, /spawn\|exec\|fork\|execFile/u);
});
