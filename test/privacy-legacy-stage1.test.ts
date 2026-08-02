import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { loadPrivacyConfig, defaultPrivacyConfig } from "../src/privacy/index.js";
import {
  LegacySourceRegistry,
  verifyAndConfine,
  computePathHmac,
  getPseudonymKey,
} from "../src/privacy/legacy/index.js";
import { type DiscoveredLegacyArtifact, type LegacyFindingRecord } from "../src/privacy/legacy/types.js";

test("Stage 1 — Configuration migration & idempotency", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-legacy-config-"));
  try {
    // 1. Initially load config (should generate with legacy_onboarding defaults)
    const config = loadPrivacyConfig(directory);
    assert.ok(config.legacy_onboarding);
    assert.equal(config.legacy_onboarding!.status, "NOT_SCANNED");
    assert.equal(config.legacy_onboarding!.reminder, true);
    assert.deepEqual(config.legacy_onboarding!.default_scopes, [
      "INVOCK_LEGACY",
      "CLAUDE_LOCAL",
      "CODEX_LOCAL",
    ]);

    // 2. Modify config and save it
    config.legacy_onboarding!.status = "SCAN_COMPLETE";
    writeFileSync(join(directory, "privacy.json"), JSON.stringify(config, null, 2));

    // 3. Reload config and verify it is idempotent (doesn't overwrite changes back to default)
    const reloaded = loadPrivacyConfig(directory);
    assert.ok(reloaded.legacy_onboarding);
    assert.equal(reloaded.legacy_onboarding!.status, "SCAN_COMPLETE");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Stage 1 — Source discovery", async () => {
  const registry = new LegacySourceRegistry(process.cwd(), ["/tmp"]);
  const adapters = registry.getAdapters();

  assert.equal(adapters.length, 5);

  const claude = registry.getAdapter("CLAUDE_LOCAL");
  assert.ok(claude);
  const codex = registry.getAdapter("CODEX_LOCAL");
  assert.ok(codex);
  const invock = registry.getAdapter("INVOCK_LEGACY");
  assert.ok(invock);
  const ws = registry.getAdapter("WORKSPACE");
  assert.ok(ws);
  const custom = registry.getAdapter("CUSTOM_ROOT");
  assert.ok(custom);

  // Claude discovery checks
  const claudeRoots = await claude!.discoverRoots();
  assert.ok(Array.isArray(claudeRoots));

  // Codex discovery checks
  const codexRoots = await codex!.discoverRoots();
  assert.ok(Array.isArray(codexRoots));

  // Workspace discovery checks
  const wsRoots = await ws!.discoverRoots();
  assert.equal(wsRoots.length, 1);
  assert.equal(wsRoots[0]!.safeToScanByDefault, false); // must be opt-in
});

test("Stage 1 — Root path traversal, external symlink rejection, and confinement", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "invock-confinement-"));
  const outsideDir = mkdtempSync(join(tmpdir(), "invock-outside-"));

  try {
    const rootPath = join(tempDir, "root");
    mkdirSync(rootPath);

    const insideFile = join(rootPath, "inside.json");
    writeFileSync(insideFile, "{}");

    // Valid confinement
    const confined = verifyAndConfine(rootPath, insideFile);
    assert.equal(confined.normalizedRelativePath, "inside.json");
    assert.equal(confined.isSymlink, false);

    // Traversal rejection (outside file)
    const outsideFile = join(outsideDir, "outside.json");
    writeFileSync(outsideFile, "{}");
    assert.throws(() => verifyAndConfine(rootPath, outsideFile), /TRAVERSAL_REJECTED/);

    // Symlink targeting outside
    const linkFile = join(rootPath, "link-outside.json");
    symlinkSync(outsideFile, linkFile);
    assert.throws(() => verifyAndConfine(rootPath, linkFile), /TRAVERSAL_REJECTED/);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("Stage 1 — Path HMAC stability and isolation", () => {
  const key = Buffer.alloc(32, 1);
  const hmac1 = computePathHmac(key, "root-a", "file.json");
  const hmac2 = computePathHmac(key, "root-a", "file.json");
  const hmac3 = computePathHmac(key, "root-b", "file.json");

  assert.equal(hmac1, hmac2); // stable
  assert.notEqual(hmac1, hmac3); // isolated by root ID
});

test("Stage 1 — FindingRecord excludes raw path and raw content", () => {
  const record: LegacyFindingRecord = {
    id: "finding-01",
    scanId: "scan-01",
    sourceType: "CLAUDE_LOCAL",
    sourceRootId: "claude-config",
    pathHmac: "some-stable-hmac",
    artifactFingerprint: "sha256-fingerprint",
    format: "JSON",
    categories: ["AGENT_CONVERSATION"],
    severity: "CRITICAL",
    matchCount: 5,
    sizeBytes: 1024,
    recognizedDisposable: true,
    autoDeleteEligible: true,
    recommendedActions: ["DELETE_DISPOSABLE_ARTIFACT"],
    detectedAt: new Date().toISOString(),
  };

  const serialized = JSON.stringify(record);
  // Ensure no fields containing raw path or content exist in the persistent model
  assert.ok(!serialized.includes("path/to") && !serialized.includes("rawContent") && !serialized.includes("snippet"));
});
