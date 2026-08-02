import assert from "node:assert/strict";
import test from "node:test";
import { digestJson, canonicalize } from "../../src/core/canonical.js";
import { compilePolicy, evaluatePolicy, parsePolicyYaml } from "../../src/core/policy.js";
import { evaluateMonotonicAuthority, issueCapabilityLease } from "../../src/authority/index.js";
import { generateSigningMaterial, makeReceiptPayload, signReceipt, verifyReceipt } from "../../src/storage/receipts.js";
import { testAuthority, TEST_NOW } from "../../fixtures/testing/invock.js";
import type { ActionEnvelope, PolicyDecision } from "../../src/core/types.js";

function seeded(seed: number) {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
}

function reorderedObject(seed: number): Record<string, unknown> {
  const next = seeded(seed);
  const entries: Array<[string, unknown]> = [
    ["alpha", next() % 17],
    ["nested", { zeta: next() % 31, beta: [next() % 7, "stable"] }],
    ["unicode", `value-${next() % 101}-é`],
    ["empty", null],
  ];
  entries.sort((a, b) => (next() % 2 === 0 ? a[0].localeCompare(b[0]) : b[0].localeCompare(a[0])));
  return Object.fromEntries(entries);
}

function envelope(index: number): ActionEnvelope {
  return {
    envelopeVersion: "1.0", invocationId: `inv-property-${index}`, requestId: String(index), sessionId: "property-session", timestamp: TEST_NOW.toISOString(),
    subject: { principalId: "property-principal", clientId: "property-client", scopes: [] },
    target: { serverId: "property-server", toolName: "read", toolSchemaDigest: "schema", toolDescriptorDigest: "descriptor", registryVersion: "registry", protocolEra: "test" },
    raw: { protocolMethod: "tools/call", argumentBytes: 2, argumentKeys: [] }, capabilities: ["fs.read"], effects: ["data.observe"], resources: [], labels: ["public"], lineage: [], riskSignals: [], uncertainty: [],
    integrity: { argumentsDigest: digestJson({}), requestDigest: digestJson({ index }), policyVersionId: "policy", normalizerVersion: "1.0" },
  };
}

function decision(index: number): PolicyDecision {
  return { contractVersion: "1.0", decisionId: `decision-${index}`, invocationId: `inv-property-${index}`, verdict: "ALLOW", policyVersionId: "policy", policyDigest: "policy-digest", matchedRuleIds: [], reasonCodes: [], traces: [], obligations: [], retryable: false, evaluatedAt: TEST_NOW.toISOString() };
}

test("property: canonicalization and digest remain stable for equivalent reordered objects", () => {
  const cases = 64;
  for (let index = 0; index < cases; index += 1) {
    const first = reorderedObject(index + 1);
    const second = Object.fromEntries(Object.entries(first).reverse());
    assert.equal(canonicalize(first), canonicalize(second));
    assert.equal(digestJson(first), digestJson(second));
  }
  console.log(`property canonicalization cases: ${cases}`);
});

test("property: authority evaluation never expands and child leases cannot amplify a parent", () => {
  const cases = 32;
  for (let index = 1; index <= cases; index += 1) {
    const { capsule, lease: parent } = testAuthority(index + 1);
    const request = { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] };
    assert.equal(evaluateMonotonicAuthority(capsule, [parent], request, TEST_NOW).allowed, true);
    const child = issueCapabilityLease({
      issuer: parent.subject, subject: "worker", parentLeaseId: parent.leaseId, capabilities: ["fs.read"],
      constraints: parent.constraints, remainingCalls: index, issuedAt: TEST_NOW.toISOString(), expiresAt: "2027-11-01T00:00:00.000Z",
    }, capsule, parent, TEST_NOW);
    assert.equal(evaluateMonotonicAuthority(capsule, [parent, child], request, TEST_NOW).allowed, true);
    assert.throws(() => issueCapabilityLease({
      issuer: parent.subject, subject: "worker", parentLeaseId: parent.leaseId, capabilities: ["fs.read"], constraints: parent.constraints,
      remainingCalls: parent.remainingCalls + 1, issuedAt: TEST_NOW.toISOString(), expiresAt: parent.expiresAt,
    }, capsule, parent, TEST_NOW));
  }
  console.log(`property authority monotonicity cases: ${cases}`);
});

test("property: policy defaults deny unknown observed authority rather than generating broader authority", () => {
  const cases = 16;
  const compiled = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: unknown-authority }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules: [{ id: baseline, decision: ALLOW, reasonCodes: [], when: { any: [] } }]
`));
  for (let index = 0; index < cases; index += 1) {
    const observed = envelope(index);
    observed.capabilities = ["unknown"];
    observed.effects = ["unknown"];
    const result = evaluatePolicy(compiled, observed, TEST_NOW);
    assert.equal(result.verdict, "BLOCK");
    assert.ok(result.reasonCodes.includes("DEFAULT_BLOCK"));
  }
  console.log(`property policy authority-boundary cases: ${cases}`);
});

test("property: every signed receipt payload mutation is rejected by signature and digest verification", () => {
  const signing = generateSigningMaterial();
  const cases = 24;
  for (let index = 0; index < cases; index += 1) {
    const payload = makeReceiptPayload({ instanceId: "property-instance", sequence: index + 1, envelope: envelope(index), decision: decision(index), upstreamForwarded: false, previousReceiptHash: null, now: TEST_NOW });
    const receipt = signReceipt(payload, signing);
    assert.equal(verifyReceipt(receipt, signing.publicKeyPem, null), true);
    const mutated = { ...receipt, payload: { ...receipt.payload, toolName: `mutated-${index}` } };
    assert.equal(verifyReceipt(mutated, signing.publicKeyPem, null), false);
    assert.equal(verifyReceipt({ ...receipt, signature: `${receipt.signature}x` }, signing.publicKeyPem, null), false);
    assert.equal(verifyReceipt({ ...receipt, hashAlgorithm: "MD5" as "SHA-256" }, signing.publicKeyPem, null), false);
    assert.equal(verifyReceipt({ ...receipt, signingKeyId: "forged-key" }, signing.publicKeyPem, null), false);
    assert.equal(verifyReceipt({ ...receipt, canonicalization: "forged" as "RFC8785-JCS" }, signing.publicKeyPem, null), false);
  }
  console.log(`property receipt mutation cases: ${cases}`);
});
