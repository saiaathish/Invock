import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  PROVIDER_GUIDANCE,
  getProviderGuidance,
  validateEvidenceReference,
  loadProviderHistoryRecords,
  updateProviderState
} from "../src/privacy/legacy/provider-history.js";
import {
  resolveEnforcementStart,
  createProtectionBoundary,
  signProtectionBoundary,
  verifyProtectionBoundary
} from "../src/privacy/legacy/boundary.js";
import { generateSigningMaterial } from "../src/storage/receipts.js";

test("Stage 4 — Provider history guidance and evidence validation", () => {
  const claude = getProviderGuidance("CLAUDE");
  assert.equal(claude.providerId, "CLAUDE");
  assert.equal(claude.automatedDeletionImplemented, false);
  const source = claude.officialSources[0];
  assert.ok(source);
  assert.ok(source.url.includes("anthropic.com"));

  const codex = getProviderGuidance("CODEX");
  assert.equal(codex.providerId, "CODEX");
  assert.equal(codex.automatedDeletionImplemented, false);

  const unknown = getProviderGuidance("unknown-provider");
  assert.equal(unknown.providerId, "UNKNOWN");

  // Evidence reference validation
  assert.equal(validateEvidenceReference("support-ticket-123"), true);
  assert.equal(validateEvidenceReference("A".repeat(600)), false); // too long
  assert.equal(validateEvidenceReference("sk-proj-123456789012345678901234"), false); // API key
  assert.equal(validateEvidenceReference("Bearer 12345"), false); // token
});

test("Stage 4 — Provider state persistence and mapping", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "invock-stage4-provider-"));
  try {
    const records = loadProviderHistoryRecords(tempDir);
    assert.equal(records.length, 2); // Default CLAUDE and CODEX

    const updated = updateProviderState(tempDir, "CLAUDE", "PROVIDER_CONFIRMED", "confirmation-id-123");
    assert.equal(updated.state, "PROVIDER_CONFIRMED");
    assert.equal(updated.evidenceReference, "confirmation-id-123");
    assert.ok(updated.evidenceDigest);

    // Reload check
    const recordsReloaded = loadProviderHistoryRecords(tempDir);
    const claudeRecord = recordsReloaded.find(r => r.providerId === "CLAUDE");
    assert.ok(claudeRecord);
    assert.equal(claudeRecord.state, "PROVIDER_CONFIRMED");
    assert.ok(claudeRecord.evidenceDigest);

    // Invalid evidence error
    assert.throws(() => {
      updateProviderState(tempDir, "CLAUDE", "PROVIDER_CONFIRMED", "Bearer token-123");
    });
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("Stage 4 — Earliest protection start timestamp resolver", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "invock-stage4-timestamp-"));
  const signing = generateSigningMaterial();
  try {
    // 1. Not provable first
    const evidence1 = await resolveEnforcementStart(tempDir, signing.publicKeyPem);
    assert.equal(evidence1.sourceType, "NOT_PROVABLE");
    assert.equal(evidence1.verified, false);

    // 2. Add valid contract
    const configPath = join(tempDir, "privacy.json");
    const contractUnsigned = {
      id: "contract-123",
      version: 1,
      mode: "LOCAL_ZDR" as const,
      metadataTtlSeconds: 2592000,
      createdAt: new Date(Date.now() - 5000).toISOString(),
      notBefore: new Date(Date.now() - 5000).toISOString()
    };
    const { digestJson } = await import("../src/core/canonical.js");
    const digest = digestJson(contractUnsigned);
    const { sign } = await import("node:crypto");
    const signature = sign(
      null,
      Buffer.from(`invock-privacy-contract-v1\0${digest}`, "utf8"),
      signing.privateKeyPem
    ).toString("base64url");

    const config = {
      mode: "LOCAL_ZDR",
      contractId: "contract-123",
      metadataTtlSeconds: 2592000,
      pseudonymizationScope: "session",
      contract: {
        ...contractUnsigned,
        digest,
        publicKeyPem: signing.publicKeyPem,
        signature
      },
      processors: [],
      pseudonymKeyPath: join(tempDir, "privacy-pseudonym.key")
    };
    writeFileSync(configPath, JSON.stringify(config, null, 2));

    const evidence2 = await resolveEnforcementStart(tempDir, signing.publicKeyPem);
    assert.equal(evidence2.sourceType, "SIGNED_ACTIVATION_EVENT");
    assert.equal(evidence2.verified, true);
    assert.equal(evidence2.startedAt, contractUnsigned.createdAt);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("Stage 4 — Protection boundary creation, signing, and verification", () => {
  const signing = generateSigningMaterial();
  const providerHistory = [
    {
      providerId: "CLAUDE",
      productId: "Claude",
      state: "PROVIDER_CONFIRMED" as const,
      evidenceReference: "ref-123",
      evidenceDigest: "digest-123"
    }
  ];
  const evidence = {
    startedAt: new Date(Date.now() - 10000).toISOString(),
    sourceType: "SIGNED_ACTIVATION_EVENT" as const,
    sourceId: "contract-123",
    sourceDigest: "digest-123",
    verified: true,
    reasonCodes: []
  };

  const unsigned = createProtectionBoundary(
    "install-123",
    "LOCAL_ZDR",
    "VERIFIED_CLEAN_FOR_SELECTED_SCOPE",
    ["CLAUDE_LOCAL"],
    { total: 5, resolved: 5, unresolved: 0 },
    providerHistory,
    evidence,
    "zdr-cert-digest-123",
    { scanDigest: "scan-digest-123" }
  );

  assert.equal(unsigned.verdict, "COMPLETE_FOR_SELECTED_LOCAL_SCOPE");

  const signed = signProtectionBoundary(unsigned, signing.privateKeyPem, signing.signingKeyId);
  assert.ok(signed.signature);
  assert.equal(verifyProtectionBoundary(signed, signing.publicKeyPem), true);

  // Tampering with verdict
  const tampered1 = { ...signed, verdict: "COMPLETE_FOR_SELECTED_LOCAL_SCOPE" as const, localFindingsUnresolved: 2 };
  assert.equal(verifyProtectionBoundary(tampered1, signing.publicKeyPem), false);

  // Tampering with signature
  const tampered2 = { ...signed, activePrivacyMode: "END_TO_END_ZDR" as const };
  assert.equal(verifyProtectionBoundary(tampered2, signing.publicKeyPem), false);
});
