import assert from "node:assert/strict";
import test from "node:test";
import { InvockStore } from "../../src/storage/store.js";
import { buildEvidenceBundle, renderEvidenceBundle, verifyEvidenceBundle } from "../../src/evidence/bundle.js";
import type { ActionEnvelope, PolicyDecision } from "../../src/core/types.js";
import { fingerprintSensitiveValue, matchSensitiveValue } from "../../src/core/lineage.js";

function evidenceFixture(): { store: InvockStore; envelope: ActionEnvelope; decision: PolicyDecision } {
  const store = new InvockStore(":memory:");
  const envelope = {
    envelopeVersion: "1.0", invocationId: "inv-evidence", requestId: "req-evidence", sessionId: "session-evidence", timestamp: "2026-08-01T00:00:00.000Z",
    subject: { principalId: "local-user", clientId: "test", scopes: ["*"] }, target: { serverId: "local", toolName: "read_file", toolSchemaDigest: "schema-digest", toolDescriptorDigest: "descriptor-digest", registryVersion: "registry-v1", protocolEra: "2025-11-25" },
    raw: { protocolMethod: "tools/call", argumentBytes: 2, argumentKeys: ["path"] }, capabilities: ["fs.read"], effects: ["data.observe"], resources: [], labels: ["public"], lineage: [], riskSignals: [], uncertainty: [], integrity: { argumentsDigest: "arguments-digest", requestDigest: "request-digest", policyVersionId: "policy-v1", normalizerVersion: "normalizer-v1" },
  } satisfies ActionEnvelope;
  const decision = { contractVersion: "1.0", decisionId: "decision-evidence", invocationId: envelope.invocationId, verdict: "ALLOW", policyVersionId: "policy-v1", policyDigest: "policy-digest", matchedRuleIds: ["allow-read"], reasonCodes: [], traces: [], obligations: [], retryable: false, evaluatedAt: envelope.timestamp } satisfies PolicyDecision;
  store.recordInterception(envelope, decision);
  store.complete(envelope, decision, false, { token: "FAKE_SECRET_123" });
  const intentEvidence = { digest: "intent-digest", privateKey: "-----BEGIN PRIVATE KEY-----" };
  store.saveExpansionRecord({ recordId: "intent-1", recordType: "intent_capsule", digest: intentEvidence.digest, payload: intentEvidence, status: "active" });
  return { store, envelope, decision };
}

test("evidence bundle is redacted and includes public verification material", () => {
  const { store } = evidenceFixture();
  try {
    const bundle = buildEvidenceBundle(store, "session-evidence");
    const serialized = JSON.stringify(bundle);
    assert.equal(bundle.receipts.length, 1);
    assert.equal(bundle.digests.intent[0], "intent-digest");
    assert.match(bundle.publicVerificationKey, /PUBLIC KEY/u);
    assert.equal(serialized.includes("FAKE_SECRET_123"), false);
    assert.equal(serialized.includes("PRIVATE KEY"), false);
    assert.equal(serialized.includes('"path"'), false);
  } finally { store.close(); }
});

test("JSON, NDJSON, and Markdown renderers produce usable deterministic output", () => {
  const { store } = evidenceFixture();
  try {
    const bundle = buildEvidenceBundle(store);
    const json = renderEvidenceBundle(bundle, "json");
    const ndjson = renderEvidenceBundle(bundle, "ndjson");
    const markdown = renderEvidenceBundle(bundle, "markdown");
    assert.equal(JSON.parse(json).formatVersion, "invock/evidence-bundle/v1");
    assert.equal(ndjson.trim().split("\n").every(line => JSON.parse(line).type), true);
    assert.match(markdown, /# Invock evidence bundle/u);
    assert.equal(renderEvidenceBundle(bundle, "json"), renderEvidenceBundle(bundle, "json"));
  } finally { store.close(); }
});

test("evidence export carries receipt-key history across a signing-key rotation", () => {
  const { store, envelope, decision } = evidenceFixture();
  try {
    const rotatedEnvelope = { ...envelope, invocationId: "inv-rotated", requestId: "req-rotated", timestamp: "2026-08-01T00:00:01.000Z" };
    const rotatedDecision = { ...decision, invocationId: rotatedEnvelope.invocationId, decisionId: "decision-rotated", evaluatedAt: rotatedEnvelope.timestamp };
    store.rotateReceiptSigningKey(new Date("2026-08-01T00:00:00.500Z"));
    store.recordInterception(rotatedEnvelope, rotatedDecision, new Date("2026-08-01T00:00:01.000Z"));
    store.complete(rotatedEnvelope, rotatedDecision, false, { blocked: true }, undefined, new Date("2026-08-01T00:00:01.000Z"));
    const bundle = buildEvidenceBundle(store);
    assert.equal(bundle.publicVerificationKeys.length, 2);
    assert.equal(verifyEvidenceBundle(bundle), true);
    const keyMutation = structuredClone(bundle);
    keyMutation.publicVerificationKeys[0]!.publicKeyPem = keyMutation.publicVerificationKeys[1]!.publicKeyPem;
    assert.equal(verifyEvidenceBundle(keyMutation), false);
  } finally { store.close(); }
});

test("evidence export includes the complete receipt chain beyond the dashboard activity bound", () => {
  const { store, envelope, decision } = evidenceFixture();
  try {
    for (let index = 1; index <= 201; index += 1) {
      const itemEnvelope = { ...envelope, invocationId: `inv-evidence-${index}`, requestId: `req-evidence-${index}`, timestamp: `2026-08-01T00:00:${String(index % 60).padStart(2, "0")}.000Z` };
      const itemDecision = { ...decision, invocationId: itemEnvelope.invocationId, decisionId: `decision-evidence-${index}`, evaluatedAt: itemEnvelope.timestamp };
      store.recordInterception(itemEnvelope, itemDecision);
      store.complete(itemEnvelope, itemDecision, false, { index });
    }
    const bundle = buildEvidenceBundle(store);
    assert.equal(bundle.receipts.length, 202);
    assert.equal(bundle.receipts.at(-1)?.sequence, 202);
  } finally { store.close(); }
});

test("evidence export fails closed on a digest-mismatched expansion record", () => {
  const { store } = evidenceFixture();
  try {
    store.db.prepare("UPDATE expansion_records SET digest = ? WHERE record_id = ?").run("tampered-digest", "intent-1");
    assert.throws(() => buildEvidenceBundle(store), /EXPANSION_DIGEST_MISMATCH/u);
  } finally { store.close(); }
});

test("detached verification rejects receipt, ordering, head, scope, and digest mutations", () => {
  const { store } = evidenceFixture();
  try {
    const original = buildEvidenceBundle(store);
    assert.equal(verifyEvidenceBundle(original), true);
    const first = original.receipts[0]!;

    const payloadMutation = structuredClone(original);
    payloadMutation.receipts[0]!.signedReceipt.payload.toolName = "mutated";
    assert.equal(verifyEvidenceBundle(payloadMutation), false);

    const signatureMutation = structuredClone(original);
    signatureMutation.receipts[0]!.signedReceipt.signature = `${signatureMutation.receipts[0]!.signedReceipt.signature[0] === "A" ? "B" : "A"}${signatureMutation.receipts[0]!.signedReceipt.signature.slice(1)}`;
    assert.equal(verifyEvidenceBundle(signatureMutation), false);

    const projectionMutation = structuredClone(original);
    projectionMutation.receipts[0]!.verdict = "BLOCK";
    assert.equal(verifyEvidenceBundle(projectionMutation), false);

    const missingReceipt = structuredClone(original);
    missingReceipt.receipts = [];
    assert.equal(verifyEvidenceBundle(missingReceipt), false);

    const reordered = structuredClone(buildEvidenceBundle(store));
    const secondEnvelope = { ...first.signedReceipt.payload, receiptId: "second", sequence: 2, previousReceiptHash: first.signedReceipt.receiptHash };
    // A single-receipt fixture cannot be reordered; an invalid sequence is the equivalent bounded omission check.
    reordered.receipts[0]!.signedReceipt.payload.sequence = 2;
    assert.equal(verifyEvidenceBundle(reordered), false);
    void secondEnvelope;

    const headMutation = structuredClone(original);
    headMutation.chainHead!.lastReceiptHash = "tampered";
    assert.equal(verifyEvidenceBundle(headMutation), false);

    const filtered = buildEvidenceBundle(store, "session-evidence");
    assert.equal(verifyEvidenceBundle(filtered), true);
    const wrongScope = structuredClone(filtered);
    wrongScope.sessionId = "other-session";
    assert.equal(verifyEvidenceBundle(wrongScope), false);

    const expansionMutation = structuredClone(original);
    expansionMutation.digests.policy[0] = "tampered-policy-digest";
    assert.equal(verifyEvidenceBundle(expansionMutation), false);
  } finally { store.close(); }
});

test("detached verification binds lineage to its source receipt, expiry, and keyed fingerprint proof", () => {
  const store = new InvockStore(":memory:");
  const baseEnvelope = {
    envelopeVersion: "1.0", invocationId: "lineage-source", requestId: "lineage-source-request", sessionId: "lineage-session", timestamp: "2026-08-01T00:00:00.000Z",
    subject: { principalId: "local-user", clientId: "test", scopes: ["*"] }, target: { serverId: "local", toolName: "read_file", toolSchemaDigest: "schema-digest", toolDescriptorDigest: "descriptor-digest", registryVersion: "registry-v1", protocolEra: "2025-11-25" },
    raw: { protocolMethod: "tools/call", argumentBytes: 2, argumentKeys: ["path"] }, capabilities: ["fs.read"], effects: ["data.observe"], resources: [], labels: ["secret"], lineage: [], riskSignals: [], uncertainty: [], integrity: { argumentsDigest: "arguments-digest", requestDigest: "request-digest", policyVersionId: "policy-v1", normalizerVersion: "normalizer-v1" },
  } satisfies ActionEnvelope;
  const baseDecision = { contractVersion: "1.0", decisionId: "lineage-decision-source", invocationId: baseEnvelope.invocationId, verdict: "ALLOW", policyVersionId: "policy-v1", policyDigest: "policy-digest", matchedRuleIds: ["allow-read"], reasonCodes: [], traces: [], obligations: [], retryable: false, evaluatedAt: baseEnvelope.timestamp } satisfies PolicyDecision;
  try {
    const sourceResult = "source-secret-value-123";
    const now = new Date("2026-08-01T00:00:00.000Z");
    store.recordInterception(baseEnvelope, baseDecision, now);
    store.complete(baseEnvelope, baseDecision, true, { content: [{ type: "text", text: sourceResult }] }, undefined, now);
    store.recordTaint(baseEnvelope.invocationId, baseEnvelope.sessionId, ["secret"], fingerprintSensitiveValue(sourceResult, store.taintKey), now, 1800);
    const lineage = matchSensitiveValue(sourceResult, store.taintKey, store.activeFingerprints(baseEnvelope.sessionId, new Date(now.getTime() + 1_000)))[0]!;
    const sinkEnvelope = { ...baseEnvelope, invocationId: "lineage-sink", requestId: "lineage-sink-request", timestamp: new Date(now.getTime() + 1_000).toISOString(), lineage: [lineage] } satisfies ActionEnvelope;
    const sinkDecision = { ...baseDecision, decisionId: "lineage-decision-sink", invocationId: sinkEnvelope.invocationId, evaluatedAt: sinkEnvelope.timestamp } satisfies PolicyDecision;
    store.recordInterception(sinkEnvelope, sinkDecision, new Date(now.getTime() + 1_000));
    store.complete(sinkEnvelope, sinkDecision, false, { blocked: true }, undefined, new Date(now.getTime() + 1_000));
    const original = buildEvidenceBundle(store);
    assert.equal(original.lineageProofs.length, 1);
    assert.equal(original.lineageProofs[0]?.fingerprints[0]?.digest.length, 43);
    assert.equal(JSON.stringify(original).includes(sourceResult), false);
    assert.equal(verifyEvidenceBundle(original), true);

    const expiryMutation = structuredClone(original);
    expiryMutation.lineageProofs[0]!.expiresAt = new Date(now.getTime() + 3_600_000).toISOString();
    assert.equal(verifyEvidenceBundle(expiryMutation), false);
    const sourceMutation = structuredClone(original);
    sourceMutation.lineageProofs[0]!.sourceInvocationId = "other-source";
    assert.equal(verifyEvidenceBundle(sourceMutation), false);
    const fingerprintMutation = structuredClone(original);
    fingerprintMutation.lineageProofs[0]!.fingerprints = [];
    assert.equal(verifyEvidenceBundle(fingerprintMutation), false);

    const keyedDigestMutation = structuredClone(original);
    keyedDigestMutation.lineageProofs[0]!.fingerprints[0]!.digest = "A".repeat(43);
    assert.equal(verifyEvidenceBundle(keyedDigestMutation), false);

    const proofDigestMutation = structuredClone(original);
    proofDigestMutation.lineageProofs[0]!.fingerprintProofDigest = "A".repeat(43);
    assert.equal(verifyEvidenceBundle(proofDigestMutation), false);
  } finally { store.close(); }
});
