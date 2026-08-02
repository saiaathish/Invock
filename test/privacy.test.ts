import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { defaultPrivacyConfig, evaluatePrivacy, loadPrivacyConfig, pseudonymize, setPrivacyMode, validateMode, verifyPrivacyContract, type ProcessorRetentionProfile } from "../src/privacy/index.js";

test("privacy mode validation rejects every non-mode value", () => { for (const value of ["STANDARD", "OFF", "DISABLED", "LOCAL_ONLY", "ENCRYPTED_RETENTION"]) assert.throws(() => validateMode(value), /PRIVACY_MODE_UNSUPPORTED/); });

test("privacy defaults to LOCAL_ZDR and validates its contract", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-zdr-"));
  try { const config = loadPrivacyConfig(directory); assert.equal(config.mode, "LOCAL_ZDR"); assert.equal(verifyPrivacyContract(config), true); assert.equal(evaluatePrivacy(config).verdict, "ALLOW"); } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("END_TO_END_ZDR fails closed for undeclared processors", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-zdr-"));
  try { const config = setPrivacyMode(directory, "END_TO_END_ZDR"); const result = evaluatePrivacy(config, ["missing"]); assert.equal(result.verdict, "BLOCK"); assert.ok(result.reasonCodes.includes("PROCESSOR_PROFILE_MISSING")); } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("END_TO_END_ZDR accepts only compliant, evidenced processors", () => {
  const profile: ProcessorRetentionProfile = { id: "synthetic-provider", version: 1, processorType: "MODEL_PROVIDER", retentionClass: "VERIFIED_ZDR", receivesCustomerContent: true, customerContentPersisted: false, contentLoggingEnabled: false, contentUsedForTraining: false, humanReviewPossible: false, requiredRequestSettings: {}, forbiddenFeatures: [], evidence: { type: "SIGNED_MANIFEST", verifiedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() }, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), digest: "synthetic-profile-digest", keyId: "synthetic-key", signature: "synthetic-signature" };
  const config = { ...defaultPrivacyConfig(mkdtempSync(join(tmpdir(), "invock-zdr-"))), mode: "END_TO_END_ZDR" as const, processors: [profile] }; const result = evaluatePrivacy(config, [profile.id]); assert.equal(result.verdict, "ALLOW"); assert.ok(result.reasonCodes.includes("END_TO_END_ZDR_SATISFIED"));
});

test("pseudonymization is stable and content-free", () => { const directory = mkdtempSync(join(tmpdir(), "invock-zdr-")); try { const key = join(directory, "key"); assert.equal(pseudonymize("synthetic", key), pseudonymize("synthetic", key)); assert.notEqual(pseudonymize("synthetic", key), "synthetic"); } finally { rmSync(directory, { recursive: true, force: true }); } });
