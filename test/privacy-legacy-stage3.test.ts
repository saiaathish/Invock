import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runLegacyScan } from "../src/privacy/legacy/scanners.js";
import { signPlan, verifyPlan } from "../src/privacy/legacy/plan.js";
import { applyRemediationPlan, validateIgnoreReason } from "../src/privacy/legacy/remediation.js";
import { runLegacyVerification } from "../src/privacy/legacy/verification.js";
import { generateSigningMaterial } from "../src/storage/receipts.js";

test("Stage 3 — Plan signing, verification, and tamper rejection", () => {
  const signing = generateSigningMaterial();
  const unsignedPlan = {
    id: "plan-123",
    scanId: "scan-123",
    scanDigest: "digest-123",
    createdAt: new Date().toISOString(),
    items: [
      {
        findingId: "finding-1",
        sourceType: "INVOCK_LEGACY" as const,
        sourceRootId: "root-1",
        pathHmac: "hmac-1",
        expectedArtifactFingerprint: "fp-1",
        action: "DELETE_DISPOSABLE_ARTIFACT" as const,
        reasonCode: "DISPOSABLE",
        userConfirmed: true,
      },
    ],
    selectedDeleteCount: 1,
    manualActionCount: 0,
    providerActionCount: 0,
    ignoredCount: 0,
  };

  const signed = signPlan(unsignedPlan, signing.privateKeyPem, signing.signingKeyId);
  assert.ok(signed.signature);
  assert.equal(verifyPlan(signed, signing.publicKeyPem), true);

  // Tamper check
  const tampered = { ...signed, scanDigest: "different-digest" };
  assert.equal(verifyPlan(tampered, signing.publicKeyPem), false);
});

test("Stage 3 — Safe cleanup execution, workspace preservation, and dry run", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "invock-stage3-cleanup-"));

  const originalHome = process.env.HOME;
  process.env.HOME = tempDir;

  try {
    const claudeDir = join(tempDir, ".claude");
    mkdirSync(claudeDir);
    const disposableSession = join(claudeDir, "session.log");
    writeFileSync(disposableSession, 'sk-1234567890abcdef1234567890abcdef');

    const workspacePath = join(tempDir, "workspace");
    mkdirSync(workspacePath);
    const dotEnv = join(workspacePath, ".env");
    writeFileSync(dotEnv, 'DB_PASSWORD="sk-1234567890abcdef1234567890abcdef"');

    const sourceFile = join(workspacePath, "index.ts");
    writeFileSync(sourceFile, "console.log('hello');");

    const privacyDir = join(tempDir, ".invock");
    mkdirSync(privacyDir, { recursive: true });
    const pKeyPath = join(privacyDir, "privacy-pseudonym.key");
    writeFileSync(pKeyPath, Buffer.alloc(32, 1).toString("base64url"));

    const { summary, findings } = await runLegacyScan(tempDir, {
      consent: true,
      selectedScopes: ["CLAUDE_LOCAL", "WORKSPACE"],
      customPaths: [],
      pseudonymKeyPath: pKeyPath,
    });

    assert.ok(findings.length > 0);

    const logFinding = findings.find(f => f.format === "LOG" || f.recommendedActions.includes("DELETE_DISPOSABLE_ARTIFACT"));
    assert.ok(logFinding);

    // Workspace files (.env) should never be recommended for auto-delete
    const envFinding = findings.find(f => f.categories.includes("SECRET") && f.sourceType === "WORKSPACE");
    if (envFinding) {
      assert.ok(!envFinding.autoDeleteEligible);
      assert.ok(envFinding.recommendedActions.includes("ROTATE_SECRET_REQUIRED"));
    }

    // Build plan
    const signing = generateSigningMaterial();
    const unsignedPlan = {
      id: "plan-1",
      scanId: summary.scanId,
      scanDigest: summary.scanDigest,
      createdAt: new Date().toISOString(),
      items: findings.map(f => ({
        findingId: f.id,
        sourceType: f.sourceType,
        sourceRootId: f.sourceRootId,
        pathHmac: f.pathHmac,
        expectedArtifactFingerprint: f.artifactFingerprint,
        action: f.autoDeleteEligible ? ("DELETE_DISPOSABLE_ARTIFACT" as const) : ("ROTATE_SECRET_REQUIRED" as const),
        reasonCode: "TEST",
        userConfirmed: true,
      })),
      selectedDeleteCount: findings.filter(f => f.autoDeleteEligible).length,
      manualActionCount: findings.filter(f => !f.autoDeleteEligible).length,
      providerActionCount: 0,
      ignoredCount: 0,
    };

    const plan = signPlan(unsignedPlan, signing.privateKeyPem, signing.signingKeyId);

    // Dry Run Verification (B5)
    const dryRunResult = await applyRemediationPlan(tempDir, plan, findings, signing.privateKeyPem, signing.signingKeyId, {
      dryRun: true,
    });
    assert.ok(dryRunResult.receipt);
    assert.equal(existsSync(disposableSession), true); // Dry run must make ZERO changes

    // Apply (Real Deletion)
    const realResult = await applyRemediationPlan(tempDir, plan, findings, signing.privateKeyPem, signing.signingKeyId, {
      dryRun: false,
    });

    assert.equal(existsSync(disposableSession), false); // Eligible artifact should be deleted
    assert.equal(existsSync(dotEnv), true); // Workspace .env file must NOT be deleted
    assert.equal(existsSync(sourceFile), true); // Source code must NOT be deleted

    // Receipt verification (B13)
    assert.ok(realResult.receipt.signature);
    assert.ok(!JSON.stringify(realResult.receipt).includes("session.log")); // content-free

    // Verify cleanup result (B14)
    const deletedHmacs = plan.items.filter(i => i.action === "DELETE_DISPOSABLE_ARTIFACT").map(i => i.pathHmac);
    const contract = { id: "default-local-zdr", version: 1, mode: "LOCAL_ZDR" as const, metadataTtlSeconds: 2592000, createdAt: new Date().toISOString(), notBefore: new Date().toISOString(), digest: "abc", keyId: signing.signingKeyId, publicKeyPem: signing.publicKeyPem, signature: "sig" };
    writeFileSync(join(privacyDir, "privacy.json"), JSON.stringify({ mode: "LOCAL_ZDR", contractId: "default-local-zdr", metadataTtlSeconds: 2592000, contract, processors: [], pseudonymKeyPath: pKeyPath }));

    const verifyState = await runLegacyVerification(tempDir, ["WORKSPACE"], deletedHmacs);
    assert.ok(["VERIFIED_CLEAN_FOR_SELECTED_SCOPE", "PARTIALLY_REMEDIATED"].includes(verifyState));
  } finally {
    process.env.HOME = originalHome;
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("Stage 3 — Ignore reason validation", () => {
  assert.equal(validateIgnoreReason(""), false); // too short
  assert.equal(validateIgnoreReason("a".repeat(201)), false); // too long
  assert.equal(validateIgnoreReason("Intended debug file for mock tests"), true);
  assert.equal(validateIgnoreReason("Contains bearer 1234567890"), false); // leaks token/secret pattern
});
