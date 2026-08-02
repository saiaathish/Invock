import { compilePolicy, parsePolicyYaml } from "../../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../../src/gateway/engine.js";
import { InvockStore } from "../../src/storage/store.js";
import { activateIntentCapsule, createIntentCapsule, issueCapabilityLease, type CapabilityLease, type IntentCapsule } from "../../src/authority/index.js";

export const TEST_NOW = new Date("2027-01-01T00:00:00.000Z");

export const readDescriptor = {
  fields: [],
  declaredCapabilities: ["fs.read" as const],
  declaredEffects: ["data.observe" as const],
};

export function testPolicy() {
  return compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: adversarial-tests }
defaults:
  decision: ALLOW
  unknownCapability: BLOCK
  unknownEffect: BLOCK
  unresolvedPath: BLOCK
rules:
  - id: baseline
    decision: ALLOW
    reasonCodes: [TEST_BASELINE]
    when: { any: [] }
`));
}

export function testCall(id: number | string = 1, argumentsValue: unknown = {}) {
  return { jsonrpc: "2.0" as const, id, method: "tools/call" as const, params: { name: "read", arguments: argumentsValue } };
}

export function testGate(store: InvockStore, sessionId = "session-a", cwd = process.cwd()) {
  return new InvocationGate(testPolicy(), new StaticDescriptorRegistry({ read: readDescriptor }), store, {
    cwd,
    projectRoot: cwd,
    organizationDomains: [],
    sessionId,
    principal: { principalId: "principal-test", clientId: "client-test", agentId: "agent-test", scopes: ["tools:call"] },
    now: () => TEST_NOW,
  }, { allowUnboundForTests: true });
}

export function testNormalizationContext(cwd = process.cwd()) {
  const policy = testPolicy();
  return {
    cwd,
    projectRoot: cwd,
    organizationDomains: [],
    policyVersionId: policy.policyVersionId,
    schemaDigest: "schema-test",
    descriptorDigest: "descriptor-test",
    sessionId: "fuzz-session",
    principal: { principalId: "fuzz-principal", clientId: "fuzz-client", scopes: [] },
    lineage: [],
    now: () => TEST_NOW,
  };
}

export function testAuthority(calls = 4): { capsule: IntentCapsule; lease: CapabilityLease } {
  const capsule = activateIntentCapsule(createIntentCapsule({
    version: 1,
    purpose: "bounded adversarial verification",
    allowedTools: ["read"],
    allowedCapabilities: ["fs.read"],
    allowedEffects: ["data.observe"],
    resourceConstraints: { paths: [], domains: [], recipients: [] },
    dataConstraints: { allowedLabels: ["public"], forbiddenLabels: ["secret"] },
    budgets: { calls, bytes: 4096 },
    expiresAt: "2028-01-01T00:00:00.000Z",
  }, TEST_NOW), TEST_NOW);
  const lease = issueCapabilityLease({
    issuer: "capsule",
    subject: "agent-test",
    capabilities: ["fs.read"],
    constraints: { tools: ["read"], effects: ["data.observe"], resources: { paths: [], domains: [], recipients: [] }, data: { allowedLabels: ["public"], forbiddenLabels: ["secret"] } },
    remainingCalls: calls,
    issuedAt: TEST_NOW.toISOString(),
    expiresAt: "2027-12-01T00:00:00.000Z",
  }, capsule, undefined, TEST_NOW);
  return { capsule, lease };
}
