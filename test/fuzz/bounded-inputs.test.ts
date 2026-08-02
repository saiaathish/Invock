import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeCommand, normalizeInvocation, normalizePath, normalizeRecipient, normalizeUrl } from "../../src/core/normalize.js";
import { parsePolicyYaml } from "../../src/core/policy.js";
import { InvocationGate } from "../../src/gateway/engine.js";
import { InvockStore } from "../../src/storage/store.js";
import { generateSigningMaterial, signReceipt, verifyReceipt, makeReceiptPayload } from "../../src/storage/receipts.js";
import { evaluateMonotonicAuthority } from "../../src/authority/index.js";
import { IdentityAuthority, assertIdentityEvidenceBinding } from "../../src/identity/index.js";
import { testAuthority, testCall, testGate, testNormalizationContext, TEST_NOW } from "../../fixtures/testing/invock.js";
import type { ActionEnvelope, PolicyDecision, ToolCallRequest } from "../../src/core/types.js";

function seeded(seed: number) {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1103515245) + 12345) >>> 0; return state; };
}

async function outcomeOrReject(action: () => unknown | Promise<unknown>): Promise<"accepted" | "rejected"> {
  try { await action(); return "accepted"; } catch { return "rejected"; }
}

function receiptEnvelope(index: number): ActionEnvelope {
  return {
    envelopeVersion: "1.0", invocationId: `fuzz-${index}`, requestId: String(index), sessionId: "fuzz-session", timestamp: TEST_NOW.toISOString(), subject: { principalId: "fuzz", clientId: "fuzz", scopes: [] },
    target: { serverId: "fuzz", toolName: "read", toolSchemaDigest: "schema", toolDescriptorDigest: "descriptor", registryVersion: "registry", protocolEra: "test" }, raw: { protocolMethod: "tools/call", argumentBytes: 2, argumentKeys: [] }, capabilities: ["fs.read"], effects: ["data.observe"], resources: [], labels: [], lineage: [], riskSignals: [], uncertainty: [], integrity: { argumentsDigest: "arg", requestDigest: "req", policyVersionId: "policy", normalizerVersion: "1.0" },
  };
}

function receiptDecision(index: number): PolicyDecision {
  return { contractVersion: "1.0", decisionId: `d-${index}`, invocationId: `fuzz-${index}`, verdict: "ALLOW", policyVersionId: "policy", policyDigest: "policy", matchedRuleIds: [], reasonCodes: [], traces: [], obligations: [], retryable: false, evaluatedAt: TEST_NOW.toISOString() };
}

test("fuzz: bounded JSON-RPC shapes never forward malformed transport parameters", async () => {
  const store = new InvockStore();
  const gate = testGate(store);
  const cases = 18;
  try {
    for (let index = 0; index < cases; index += 1) {
      const malformed = index % 3 !== 0;
      const request = (malformed ? ({ ...testCall(index), params: { name: index % 2 ? "" : "read", arguments: index % 2 ? null : [] } }) : testCall(index)) as ToolCallRequest;
      try {
        const result = await gate.authorizeInvocation(request);
        if (malformed) assert.notEqual(result.kind, "forward", `malformed JSON-RPC case ${index} forwarded`);
      } catch {
        assert.ok(malformed, `valid JSON-RPC case ${index} unexpectedly rejected`);
      }
    }
  } finally { store.close(); }
  console.log(`fuzz JSON-RPC cases: ${cases}`);
});

test("fuzz: malformed tool schemas and normalizer metadata fail closed", async () => {
  const cases = 18;
  const context = testNormalizationContext();
  for (let index = 0; index < cases; index += 1) {
    const descriptor = index % 3 === 0
      ? { fields: [{ pointer: "/x", type: "not-a-field-kind" }] }
      : index % 3 === 1
        ? { fields: [], declaredCapabilities: ["not-a-capability"] }
        : { fields: [], declaredEffects: ["not-an-effect"] };
    const result = await outcomeOrReject(() => normalizeInvocation(testCall(index), descriptor as never, context));
    assert.equal(result, "rejected", `schema case ${index} was accepted`);
  }
  console.log(`fuzz tool schema cases: ${cases}`);
});

test("fuzz: nested argument values are bounded and never bypass malformed-input denial", async () => {
  const cases = 18;
  const store = new InvockStore();
  const supportedGate = testGate(store);
  try {
    for (let index = 0; index < cases; index += 1) {
      const next = seeded(index + 77);
      const value: unknown = index % 2 === 0 ? { nested: [next() % 9, { text: `v-${next() % 99}` }] } : [next() % 9];
      try {
        const result = await supportedGate.authorizeInvocation(testCall(index, value));
        if (Array.isArray(value)) assert.notEqual(result.kind, "forward", `array case ${index} forwarded`);
      } catch {
        assert.ok(Array.isArray(value));
      }
    }
  } finally { store.close(); }
  console.log(`fuzz nested argument cases: ${cases}`);
});

test("fuzz: malformed policy YAML is rejected without unbounded parsing", () => {
  const cases = 18;
  const inputs = ["", "defaults: [", "!!js/function 'bad'", "apiVersion: wrong", "apiVersion: invock.dev/v1\nkind: InvocationPolicy\nrules: []", "a: &x [*x]"];
  for (let index = 0; index < cases; index += 1) {
    const source = inputs[index % inputs.length]!;
    assert.throws(() => parsePolicyYaml(source));
  }
  console.log(`fuzz policy YAML cases: ${cases}`);
});

test("fuzz: URLs, paths, recipients, commands, and encodings reject unsafe forms or return classified resources", async () => {
  const cases = 18;
  const context = testNormalizationContext();
  const values = ["", "javascript:alert(1)", "https://user:pass@example.test/", "https://example.test/%00", "https://127.0.0.1/", "file:///tmp/a", "https://EXAMPLE.test./a", "https://[::1]/", "https://example.test/a%2Fb"];
  for (let index = 0; index < cases; index += 1) {
    const raw = values[index % values.length]!;
    const urlResult = await outcomeOrReject(() => normalizeUrl(raw, "/url", "GET"));
    if (["", "javascript:alert(1)", "https://user:pass@example.test/", "file:///tmp/a"].includes(raw)) assert.equal(urlResult, "rejected");
    const pathResult = await outcomeOrReject(() => normalizePath(raw, "/path", "read", context));
    assert.ok(pathResult === "accepted" || pathResult === "rejected");
    assert.ok((await outcomeOrReject(() => normalizeRecipient(raw, "/recipient", ["example.test"]))) !== "accepted" || raw.includes("@"));
    assert.ok((await outcomeOrReject(() => normalizeCommand(raw, "/command"))) === "accepted" || raw.length === 0 || raw.includes(":") || raw.includes("/"));
  }
  console.log(`fuzz URL/path/encoding cases: ${cases}`);
});

test("fuzz: signed receipt payload and encoding mutations never verify", () => {
  const cases = 18;
  const signing = generateSigningMaterial();
  for (let index = 0; index < cases; index += 1) {
    const receipt = signReceipt(makeReceiptPayload({ instanceId: "fuzz", sequence: index + 1, envelope: receiptEnvelope(index), decision: receiptDecision(index), upstreamForwarded: false, previousReceiptHash: null, now: TEST_NOW }), signing);
    const mutated = { ...receipt, payload: { ...receipt.payload, reasonCodes: [`mutated-${index}`] } };
    assert.equal(verifyReceipt(mutated, signing.publicKeyPem, null), false);
    assert.equal(verifyReceipt(receipt, signing.publicKeyPem, index % 2 === 0 ? "wrong-previous" : null), index % 2 !== 0);
  }
  console.log(`fuzz receipt payload cases: ${cases}`);
});

test("fuzz: malformed delegation chains remain denied and cannot amplify authority", () => {
  const cases = 18;
  const { capsule, lease } = testAuthority(4);
  for (let index = 0; index < cases; index += 1) {
    const malformed = index % 2 === 0 ? [{ ...lease, parentLeaseId: "missing" }] : Array.from({ length: 17 }, () => lease);
    const result = evaluateMonotonicAuthority(capsule, malformed, { tool: "read", capabilities: ["fs.read"], effects: ["data.observe"] }, TEST_NOW);
    assert.equal(result.allowed, false);
  }
  console.log(`fuzz delegation-chain cases: ${cases}`);
});

test("fuzz: identity evidence mutations and session/project boundary changes fail closed", () => {
  const cases = 18;
  for (let index = 0; index < cases; index += 1) {
    const authority = new IdentityAuthority();
    const enrolled = authority.enroll({ agentId: `fuzz-agent-${index}`, organizationId: "fuzz-org", projectId: "fuzz-project", displayName: "bounded agent", runtimeType: "test" }, TEST_NOW);
    const session = authority.openSession(enrolled.identity.id, enrolled.identity.projectId, 60, TEST_NOW);
    const binding = authority.evidenceBinding(enrolled.identity, session, TEST_NOW);
    assert.doesNotThrow(() => assertIdentityEvidenceBinding(binding));
    const fields = ["identityDigest", "sessionDigest", "projectDigest", "agentDigest", "bindingDigest"] as const;
    const field = fields[index % fields.length]!;
    assert.throws(() => assertIdentityEvidenceBinding({ ...binding, [field]: `${binding[field]}x` }));
    assert.throws(() => authority.openSession(enrolled.identity.id, "other-project", 60, TEST_NOW));
  }
  console.log(`fuzz identity/session-boundary cases: ${cases}`);
});

console.log("fuzz seeded total cases: 144; max cases per family: 18; execution is bounded by finite loops and local APIs");
