import assert from "node:assert/strict";
import test from "node:test";
import { digestJson } from "../../src/core/canonical.js";
import { createIdentityEvidenceBinding, IdentityAuthority } from "../../src/identity/index.js";
import { assertReceiptMetadata } from "../../src/storage/receipts.js";
import { InvockStore } from "../../src/storage/store.js";
import type { ActionEnvelope, PolicyDecision } from "../../src/core/types.js";

const now = new Date("2026-08-01T00:00:00.000Z");

function fixture(): { store: InvockStore; envelope: ActionEnvelope; decision: PolicyDecision } {
  const store = new InvockStore(":memory:");
  const envelope = {
    envelopeVersion: "1.0", invocationId: "inv-identity-binding", requestId: "req-identity-binding", sessionId: "session-identity-binding", timestamp: now.toISOString(),
    subject: { principalId: "agent-1", clientId: "test", scopes: [] }, target: { serverId: "local", toolName: "read", toolSchemaDigest: digestJson("schema"), toolDescriptorDigest: digestJson("descriptor"), registryVersion: "registry-v1", protocolEra: "2025-11-25" },
    raw: { protocolMethod: "tools/call", argumentBytes: 2, argumentKeys: ["path"] }, capabilities: ["fs.read"], effects: ["data.observe"], resources: [], labels: ["public"], lineage: [], riskSignals: [], uncertainty: [], integrity: { argumentsDigest: digestJson({ path: "safe.txt" }), requestDigest: digestJson("request"), policyVersionId: "policy-v1", normalizerVersion: "normalizer-v1" },
  } satisfies ActionEnvelope;
  const decision = { contractVersion: "1.0", decisionId: "decision-identity-binding", invocationId: envelope.invocationId, verdict: "ALLOW", policyVersionId: "policy-v1", policyDigest: digestJson("policy"), matchedRuleIds: ["allow-read"], reasonCodes: [], traces: [], obligations: [], retryable: false, evaluatedAt: now.toISOString() } satisfies PolicyDecision;
  store.recordInterception(envelope, decision, now);
  return { store, envelope, decision };
}

test("identity/session binding is canonical and survives into signed receipt evidence", () => {
  const authority = new IdentityAuthority();
  const enrollment = authority.enroll({ organizationId: "org-1", projectId: "project-1", displayName: "worker", runtimeType: "node" }, now);
  const session = authority.openSession(enrollment.identity.id, "project-1", 60, now);
  const binding = authority.evidenceBinding(enrollment.identity, session, now);
  assert.deepEqual(binding, createIdentityEvidenceBinding(enrollment.identity, session));
  assert.equal(Object.isFrozen(binding), true);
  assert.throws(() => (session as { projectId: string }).projectId = "other", TypeError);

  const { store, envelope, decision } = fixture();
  try {
    const metadata = {
      intentCapsuleDigest: digestJson("capsule"), capabilityLeaseChainDigest: digestJson(["lease"]), effectiveAuthorityDigest: digestJson("authority"),
      identityDigest: binding.identityDigest, sessionDigest: binding.sessionDigest, projectDigest: binding.projectDigest, agentDigest: binding.agentDigest, identityBindingDigest: binding.bindingDigest,
    };
    assert.doesNotThrow(() => assertReceiptMetadata(metadata));
    const receipt = store.complete(envelope, decision, false, { blocked: true }, undefined, now, metadata);
    assert.equal(receipt.payload.identityDigest, binding.identityDigest);
    assert.equal(receipt.payload.sessionDigest, binding.sessionDigest);
    assert.equal(receipt.payload.projectDigest, binding.projectDigest);
    assert.equal(receipt.payload.agentDigest, binding.agentDigest);
    assert.equal(receipt.payload.identityBindingDigest, binding.bindingDigest);
    assert.equal(store.verifyChain(), true);
    assert.equal(JSON.stringify(receipt).includes("PRIVATE KEY"), false);
  } finally { store.close(); }
});

test("changed or omitted identity and authority metadata is rejected before commit", () => {
  const authority = new IdentityAuthority();
  const enrollment = authority.enroll({ organizationId: "org-2", projectId: "project-2", displayName: "worker", runtimeType: "python" }, now);
  const session = authority.openSession(enrollment.identity.id, "project-2", 60, now);
  const binding = authority.evidenceBinding(enrollment.identity, session, now);
  assert.throws(() => assertReceiptMetadata({ identityDigest: binding.identityDigest, sessionDigest: binding.sessionDigest, projectDigest: digestJson({ projectId: "other" }), agentDigest: binding.agentDigest, identityBindingDigest: binding.bindingDigest }), /binding digest mismatch/u);
  assert.throws(() => assertReceiptMetadata({ identityDigest: binding.identityDigest }), /INCOMPLETE_IDENTITY_BINDING/u);
  assert.throws(() => assertReceiptMetadata({ intentCapsuleDigest: digestJson("capsule"), effectiveAuthorityDigest: digestJson("authority") }), /INCOMPLETE_AUTHORITY_BINDING/u);

  const { store, envelope, decision } = fixture();
  try {
    assert.throws(() => store.complete(envelope, decision, false, { blocked: true }, undefined, now, { intentCapsuleDigest: digestJson("capsule") }), /INCOMPLETE_AUTHORITY_BINDING/u);
    assert.equal(store.verifyChain(), true);
  } finally { store.close(); }
});
