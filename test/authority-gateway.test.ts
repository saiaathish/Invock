import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { activateIntentCapsule, createIntentCapsule, issueCapabilityLease } from "../src/authority/index.js";
import { InvockStore } from "../src/storage/store.js";

test("gateway binds effective authority metadata to the persisted receipt and consumes the lease", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-authority-gateway-"));
  const target = join(directory, "safe.txt");
  const now = new Date("2027-01-01T00:00:00.000Z");
  const store = new InvockStore(join(directory, "store.sqlite"));
  try {
    const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: authority-test }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: allow-read
    decision: ALLOW
    reasonCodes: []
    when: { uncertainty: { empty: true } }
`));
    const descriptor = { fields: [{ pointer: "/path", type: "path" as const, access: "read" as const }], inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } };
    const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: descriptor }), store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: "authority-session", principal: { principalId: "test", agentId: "worker", clientId: "test", scopes: [] }, now: () => now }, { requireContainment: false });
    const capsule = activateIntentCapsule(createIntentCapsule({ version: 1, purpose: "read safe file", allowedTools: ["read"], allowedCapabilities: ["fs.read"], allowedEffects: ["data.observe"], resourceConstraints: { paths: [target], domains: [], recipients: [] }, dataConstraints: { allowedLabels: ["public", "internal"], forbiddenLabels: ["secret"] }, budgets: { calls: 1 }, expiresAt: "2028-01-01T00:00:00.000Z" }, now), now);
    const lease = issueCapabilityLease({ issuer: "capsule", subject: "worker", capabilities: ["fs.read"], constraints: { tools: ["read"], effects: ["data.observe"], resources: { paths: [target], domains: [], recipients: [] }, data: { allowedLabels: ["public", "internal"], forbiddenLabels: ["secret"] } }, remainingCalls: 1, issuedAt: now.toISOString(), expiresAt: "2027-12-01T00:00:00.000Z" }, capsule, undefined, now);
    let consumed: readonly typeof lease[] | undefined;
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { protocolEra: "2025-11-25", authority: { sessionId: "authority-session", capsule, leases: [lease], request: { tool: "wrong-tool", capabilities: [], effects: [] }, consume: leases => { consumed = leases as readonly typeof lease[]; } } });
    assert.equal(outcome.kind, "forward");
    assert.equal(consumed?.[0]?.remainingCalls, 0);
    if (outcome.kind !== "forward") throw new Error("expected forward");
    const receiptId = gate.finish(outcome, { content: [{ type: "text", text: "ok" }] }, now);
    const receipt = store.getReceipt(receiptId);
    assert.equal(receipt?.payload.intentCapsuleDigest, capsule.digest);
    assert.equal(receipt?.payload.capabilityLeaseChainDigest, receipt?.payload.capabilityLeaseChainDigest);
    assert.equal(typeof receipt?.payload.effectiveAuthorityDigest, "string");
    assert.equal(receipt?.payload.protocolProfileId, "2025-11-25");
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("gateway rejects authority reused across sessions", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-authority-session-"));
  const store = new InvockStore(join(directory, "store.sqlite"));
  try {
    const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: authority-session-test }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: allow
    decision: ALLOW
    reasonCodes: []
    when: { uncertainty: { empty: true } }
`));
    const descriptor = { fields: [{ pointer: "/path", type: "path" as const, access: "read" as const }], inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } };
    const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: descriptor }), store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: "session-b", principal: { principalId: "test", clientId: "test", scopes: [] } });
    const now = new Date("2027-01-01T00:00:00.000Z");
    const target = join(directory, "safe.txt");
    const capsule = activateIntentCapsule(createIntentCapsule({ version: 1, purpose: "session-bound", allowedTools: ["read"], allowedCapabilities: ["fs.read"], allowedEffects: ["data.observe"], resourceConstraints: { paths: [target], domains: [], recipients: [] }, dataConstraints: { allowedLabels: ["public"], forbiddenLabels: ["secret"] }, budgets: { calls: 1 }, expiresAt: "2028-01-01T00:00:00.000Z" }, now), now);
    const lease = issueCapabilityLease({ issuer: "capsule", subject: "worker", capabilities: ["fs.read"], constraints: { tools: ["read"], effects: ["data.observe"], resources: { paths: [target], domains: [], recipients: [] }, data: { allowedLabels: ["public"], forbiddenLabels: ["secret"] } }, remainingCalls: 1, issuedAt: now.toISOString(), expiresAt: "2027-12-01T00:00:00.000Z" }, capsule, undefined, now);
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { authority: { sessionId: "session-a", capsule, leases: [lease], request: { tool: "read", capabilities: ["fs.read"], effects: ["data.observe"] } } });
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.match(String(outcome.response.result.structuredContent?.reasonCodes), /NORMALIZATION_FAILED|EFFECTIVE_AUTHORITY_DENIED/);
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});
