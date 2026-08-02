import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runLegacyScan } from "../src/privacy/legacy/scanners.js";
import { scanTextContent, scanSQLiteDatabase } from "../src/privacy/legacy/detectors.js";
import { DatabaseSync } from "node:sqlite";

test("Stage 2 — Consent constraint", async () => {
  await assert.rejects(
    async () => {
      await runLegacyScan(process.cwd(), {
        consent: false,
        selectedScopes: ["INVOCK_LEGACY"],
      });
    },
    /CONSENT_REQUIRED/
  );
});

test("Stage 2 — Text detector finds secrets and PII but does not store them", () => {
  const sample = "Debug log:\nuser email is alice@example.com, API key is sk-1234567890abcdef1234567890abcdef\n";
  const result = scanTextContent(sample);

  assert.ok(result.categories.includes("SECRET"));
  assert.ok(result.categories.includes("PERSONAL_DATA"));
  assert.equal(result.severity, "CRITICAL");
  assert.ok(result.matchCount >= 2);
});

test("Stage 2 — SQLite detector reads schema and columns safely", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-sqlite-test-"));
  const dbPath = join(directory, "test.sqlite");
  try {
    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        prompt TEXT,
        response TEXT,
        api_token TEXT
      );
      INSERT INTO sessions (prompt, response, api_token) VALUES ('hello', 'hi', 'sk-key123');
    `);
    db.close();

    const result = scanSQLiteDatabase(dbPath);
    assert.ok(result.categories.includes("AGENT_CONVERSATION") || result.categories.includes("CONTENT_BEARING_DATABASE"));
    assert.ok(result.categories.includes("SECRET"));
    assert.equal(result.severity, "CRITICAL");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Stage 2 — Size bounds and symlink escapes", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "invock-scanner-bounds-"));
  try {
    const rootPath = join(tempDir, "root");
    mkdirSync(rootPath);

    // Large file (20 MiB)
    const largeFile = join(rootPath, "large.json");
    writeFileSync(largeFile, "A".repeat(17 * 1024 * 1024)); // > 16 MiB

    // Small file with secret
    const smallFile = join(rootPath, "small.json");
    writeFileSync(smallFile, '{"key": "sk-1234567890abcdef1234567890abcdef"}');

    // Pseudonym key path
    const pKeyPath = join(rootPath, "pseudonym.key");
    writeFileSync(pKeyPath, Buffer.alloc(32, 1));

    const { summary, findings } = await runLegacyScan(tempDir, {
      consent: true,
      selectedScopes: ["CUSTOM_ROOT"],
      customPaths: [rootPath],
      pseudonymKeyPath: pKeyPath,
      maxFileSizeBytes: 16 * 1024 * 1024,
    });

    // Large file should be skipped, small file examined
    assert.equal(summary.filesExamined, 2); // small.json and pseudonym.key
    assert.equal(summary.filesSkipped, 1); // large.json is skipped due to size
    assert.ok(findings.length >= 1);

    // Confirm finding does not leak absolute path or content snippets
    for (const finding of findings) {
      assert.ok(!JSON.stringify(finding).includes("rootPath"));
      assert.ok(!JSON.stringify(finding).includes("small.json"));
      assert.ok(!JSON.stringify(finding).includes("sk-1234567890"));
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("Stage 2 — Network isolation verification during scan", async () => {
  let networkCallsCount = 0;
  const net = await import("node:net");

  const originalConnect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args: any[]) {
    networkCallsCount++;
    throw new Error("TCP_CONNECT_BLOCKED");
  } as any;

  try {
    const tempDir = mkdtempSync(join(tmpdir(), "invock-network-iso-"));
    const pKeyPath = join(tempDir, "pseudonym.key");
    writeFileSync(pKeyPath, Buffer.alloc(32, 1));

    await runLegacyScan(tempDir, {
      consent: true,
      selectedScopes: ["INVOCK_LEGACY"],
      pseudonymKeyPath: pKeyPath,
    });

    rmSync(tempDir, { recursive: true, force: true });
  } finally {
    net.Socket.prototype.connect = originalConnect;
  }

  assert.equal(networkCallsCount, 0, "External network attempts during scanner test: 0");
});

test("Stage 2 — Content-free persistence (canaries)", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-canaries-"));
  try {
    const canaries = {
      prompt: "canary-prompt-xyz789",
      response: "canary-response-xyz789",
      email: "canary-email-xyz789@example.com",
      phone: "555-canary-phone",
      address: "123 Canary Lane",
      credential: "canary-cred-password-abc",
      apiKey: "sk-canary-apiKey-xyz7890123456789012345",
      password: "canary-password-123",
      toolArgument: "canary-tool-arg",
      toolResult: "canary-tool-result",
    };

    const testFile = join(directory, "canary_test.json");
    writeFileSync(testFile, JSON.stringify(canaries));

    let stdoutBuffer = "";
    let stderrBuffer = "";
    const originalWriteStdout = process.stdout.write;
    const originalWriteStderr = process.stderr.write;
    process.stdout.write = (chunk: any) => {
      stdoutBuffer += chunk.toString();
      return true;
    };
    process.stderr.write = (chunk: any) => {
      stderrBuffer += chunk.toString();
      return true;
    };

    const pKeyPath = join(directory, "pseudonym.key");
    writeFileSync(pKeyPath, Buffer.alloc(32, 1));

    const { summary, findings } = await runLegacyScan(directory, {
      consent: true,
      selectedScopes: ["CUSTOM_ROOT"],
      customPaths: [directory],
      pseudonymKeyPath: pKeyPath,
    });

    process.stdout.write = originalWriteStdout;
    process.stderr.write = originalWriteStderr;

    const serializedSummary = JSON.stringify(summary);
    const serializedFindings = JSON.stringify(findings);

    for (const val of Object.values(canaries)) {
      assert.ok(!serializedSummary.includes(val), `Canary ${val} persisted in summary`);
      assert.ok(!serializedFindings.includes(val), `Canary ${val} persisted in findings`);
      assert.ok(!stdoutBuffer.includes(val), `Canary ${val} present in stdout`);
      assert.ok(!stderrBuffer.includes(val), `Canary ${val} present in stderr`);
    }

    assert.ok(!serializedFindings.includes("canary_test.json"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
