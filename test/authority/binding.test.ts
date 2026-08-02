import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { compilePolicy, parsePolicyYaml } from "../../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../../src/gateway/engine.js";
import { activateBoundIntentCapsule, createAuthorityBinding, createHumanActivation, createIntentCapsule, issueCapabilityLease, type IntentCapsule } from "../../src/authority/index.js";
import { IdentityAuthority } from "../../src/identity/index.js";
import { InvockStore } from "../../src/storage/store.js";

const now = new Date("2027-01-01T00:00:00.000Z");
const descriptor = { fields: [{ pointer: "/path", type: "path" as const, access: "read" as const }], inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } };
const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: bound-authority }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: allow-read
    decision: ALLOW
    reasonCodes: []
    when: { uncertainty: { empty: true } }
`));

function makeBoundAuthority(directory: string): { gate: InvocationGate; store: InvockStore; capsule: IntentCapsule; binding: ReturnType<typeof createAuthorityBinding>; lease: ReturnType<typeof issueCapabilityLease>; trustedApproverKeys: Map<string, string>; identityAuthority: IdentityAuthority; identityContext: { identity: ReturnType<IdentityAuthority["enroll"]>["identity"]; session: ReturnType<IdentityAuthority["openSession"]> }; identityBinding: ReturnType<IdentityAuthority["evidenceBinding"]> } {
  const registry = new StaticDescriptorRegistry({ read: descriptor });
  const identityAuthority = new IdentityAuthority();
  const enrolled = identityAuthority.enroll({ organizationId: "org-1", projectId: "project-1", displayName: "agent-1", runtimeType: "test", agentId: "agent-1" }, now);
  const attested = identityAuthority.attest(enrolled.identity.id, { build: "bound-authority-test" }, now);
  const session = identityAuthority.openSession(attested.identity.id, attested.identity.projectId, 3600, now);
  const binding = createAuthorityBinding({ agentId: attested.identity.id, sessionId: session.id, projectId: attested.identity.projectId, policyVersionId: policy.policyVersionId, policyDigest: policy.policyDigest, registryVersion: registry.registryVersion("read"), toolSchemaDigest: registry.schemaDigest("read") });
  const proposed = createIntentCapsule({ version: 1, purpose: "read only the project file", allowedTools: ["read"], allowedCapabilities: ["fs.read"], allowedEffects: ["data.observe"], resourceConstraints: { paths: [join(directory, "safe.txt")], domains: [], recipients: [] }, dataConstraints: { allowedLabels: ["public", "internal"], forbiddenLabels: ["secret"] }, budgets: { calls: 1 }, expiresAt: "2028-01-01T00:00:00.000Z", authorityBinding: binding }, now);
  const keys = generateKeyPairSync("ed25519", { privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
  const trustedApproverKeys = new Map([["human-1", keys.publicKey]]);
  const activation = createHumanActivation({ capsuleId: proposed.capsuleId, version: proposed.version, proposedDigest: proposed.digest, binding, approverId: "human-1", approvedAt: now.toISOString(), statementDigest: proposed.digest, privateKeyPem: keys.privateKey });
  const capsule = activateBoundIntentCapsule(proposed, activation, now, trustedApproverKeys);
  const lease = issueCapabilityLease({ issuer: "capsule", subject: binding.agentId, capabilities: ["fs.read"], constraints: { tools: ["read"], effects: ["data.observe"], resources: { paths: [join(directory, "safe.txt")], domains: [], recipients: [] }, data: { allowedLabels: ["public", "internal"], forbiddenLabels: ["secret"] } }, remainingCalls: 1, issuedAt: now.toISOString(), expiresAt: "2027-12-01T00:00:00.000Z", authorityBinding: binding }, capsule, undefined, now, trustedApproverKeys);
  const store = new InvockStore(":memory:");
  const identityBinding = identityAuthority.evidenceBinding(attested.identity, session, now);
  const gate = new InvocationGate(policy, registry, store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: session.id, principal: { principalId: binding.agentId, agentId: binding.agentId, clientId: "test", scopes: ["*"] }, now: () => now }, { trustedApproverKeys, requireContainment: false });
  return { gate, store, capsule, binding, lease, trustedApproverKeys, identityAuthority, identityContext: { identity: attested.identity, session }, identityBinding };
}

test("signed human activation and runtime context binding reach the receipt", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-bound-authority-"));
  const { gate, store, capsule, binding, lease, identityAuthority, identityContext, identityBinding } = makeBoundAuthority(directory);
  try {
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { projectId: binding.projectId, identityAuthority, identityContext, identityBinding, authority: { binding, capsule, leases: [lease], request: { tool: "read", capabilities: [], effects: [] } } });
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") throw new Error("expected forward");
    const receipt = gate.finish(outcome, { content: [{ type: "text", text: "ok" }] }, now);
    assert.equal(outcome.receiptMetadata?.authorityBindingDigest, binding.bindingDigest);
    assert.equal(capsule.humanActivation?.approverId, "human-1");
    assert.ok(receipt);
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a bound capsule fails closed when the runtime binding is omitted or diverges", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-bound-authority-deny-"));
  const { gate, store, capsule, binding, lease, identityAuthority, identityContext, identityBinding } = makeBoundAuthority(directory);
  try {
    const request = { jsonrpc: "2.0" as const, id: 1, method: "tools/call" as const, params: { name: "read", arguments: { path: "safe.txt" } } };
    const missing = await gate.authorizeInvocation(request, { projectId: binding.projectId, identityAuthority, identityContext, identityBinding, authority: { capsule, leases: [lease], request: { tool: "read", capabilities: [], effects: [] } } });
    assert.equal(missing.kind, "respond");
    if (missing.kind === "respond") assert.ok((missing.response.result.structuredContent?.reasonCodes as string[]).includes("AUTHORITY_BINDING_REQUIRED"));
    const diverged = await gate.authorizeInvocation(request, { projectId: "other-project", identityAuthority, identityContext, identityBinding, authority: { binding, capsule, leases: [lease], request: { tool: "read", capabilities: [], effects: [] } } });
    assert.equal(diverged.kind, "respond");
    if (diverged.kind === "respond") assert.ok((diverged.response.result.structuredContent?.reasonCodes as string[]).length > 0);
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the default invocation gate blocks requests without authority", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-authority-required-"));
  const { gate, store } = makeBoundAuthority(directory);
  try {
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } });
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.ok((outcome.response.result.structuredContent?.reasonCodes as string[]).includes("STRICT_AUTHORITY_REQUIRED"));
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("bound authority without verified identity evidence fails closed", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-bound-authority-identity-required-"));
  const { gate, store, capsule, binding, lease } = makeBoundAuthority(directory);
  try {
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { projectId: binding.projectId, authority: { binding, capsule, leases: [lease], request: { tool: "read", capabilities: [], effects: [] } } });
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.ok((outcome.response.result.structuredContent?.reasonCodes as string[]).includes("IDENTITY_BINDING_INVALID"));
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("persisted lease budgets cannot be replayed without a consume callback", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-authority-lease-replay-"));
  const { gate, store, capsule, binding, lease, identityAuthority, identityContext, identityBinding } = makeBoundAuthority(directory);
  const runtime = { projectId: binding.projectId, identityAuthority, identityContext, identityBinding, authority: { binding, capsule, leases: [lease], request: { tool: "read", capabilities: [], effects: [] } } };
  try {
    const first = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, runtime);
    assert.equal(first.kind, "forward");
    const replay = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, runtime);
    assert.equal(replay.kind, "respond");
    if (replay.kind === "respond") assert.ok((replay.response.result.structuredContent?.reasonCodes as string[]).some(code => ["AUTHORITY_LEASE_NOT_ACTIVE", "LEASE_STATE_STALE"].includes(code)));
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("authoritative capsule and lease revocation invalidate previously issued snapshots", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-authority-revocation-"));
  const { gate, store, capsule, binding, lease, trustedApproverKeys, identityAuthority, identityContext, identityBinding } = makeBoundAuthority(directory);
  const request = { jsonrpc: "2.0" as const, id: 1, method: "tools/call" as const, params: { name: "read", arguments: { path: "safe.txt" } } };
  const runtime = { projectId: binding.projectId, identityAuthority, identityContext, identityBinding, authority: { binding, capsule, leases: [lease], request: { tool: "read", capabilities: [], effects: [] } } };
  try {
    store.authorizeAuthorityState(capsule, [lease], binding.sessionId, now, trustedApproverKeys);
    store.revokeAuthorityLease(lease.leaseId, binding.sessionId, now);
    const leaseDenied = await gate.authorizeInvocation(request, runtime);
    assert.equal(leaseDenied.kind, "respond");
    if (leaseDenied.kind === "respond") assert.ok((leaseDenied.response.result.structuredContent?.reasonCodes as string[]).includes("AUTHORITY_LEASE_NOT_ACTIVE"));

    const second = makeBoundAuthority(directory);
    second.store.authorizeAuthorityState(second.capsule, [second.lease], second.binding.sessionId, now, second.trustedApproverKeys);
    second.store.revokeAuthorityCapsule(second.capsule.capsuleId, now, second.trustedApproverKeys);
    const capsuleDenied = await second.gate.authorizeInvocation(request, { projectId: second.binding.projectId, identityAuthority: second.identityAuthority, identityContext: second.identityContext, identityBinding: second.identityBinding, authority: { binding: second.binding, capsule: second.capsule, leases: [second.lease], request: { tool: "read", capabilities: [], effects: [] } } });
    assert.equal(capsuleDenied.kind, "respond");
    if (capsuleDenied.kind === "respond") {
      const reasonCodes = capsuleDenied.response.result.structuredContent?.reasonCodes as string[];
      assert.ok(reasonCodes.includes("AUTHORITY_CAPSULE_REVOKED"));
    }
    second.store.close();
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
