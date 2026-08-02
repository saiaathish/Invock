import test from "node:test";
import assert from "node:assert/strict";
import { digestJson } from "../../src/core/canonical.js";
import { activateIntentCapsule, consumeCapabilityLease, createIntentCapsule, evaluateMonotonicAuthority, issueCapabilityLease, revokeCapabilityLease, revokeIntentCapsule, type CapabilityLease, type IntentCapsule } from "../../src/authority/index.js";
import { InvockStore } from "../../src/storage/store.js";

const input = (overrides: Record<string, unknown> = {}) => ({ version: 1, purpose: "test", allowedTools: ["read"], allowedCapabilities: ["fs.read" as const], allowedEffects: ["data.observe" as const], resourceConstraints: { paths: ["/tmp"], domains: ["example.test"], recipients: ["local"] }, dataConstraints: { allowedLabels: ["public"], forbiddenLabels: ["secret"] }, budgets: { calls: 2 }, expiresAt: "2030-01-01T00:00:00Z", ...overrides });
const leaseInput = (overrides: Record<string, unknown> = {}) => ({ issuer: "capsule", subject: "worker", capabilities: ["fs.read" as const], constraints: { tools: ["read"], effects: ["data.observe" as const], resources: { paths: ["/tmp"], domains: ["example.test"], recipients: ["local"] }, data: { allowedLabels: ["public"], forbiddenLabels: ["secret"] } }, remainingCalls: 2, issuedAt: "2027-01-01T00:00:00Z", expiresAt: "2029-01-01T00:00:00Z", ...overrides });
function active(): IntentCapsule { return activateIntentCapsule(createIntentCapsule(input(), new Date("2027-01-01T00:00:00Z")), new Date("2027-01-01T00:00:00Z")); }

test("capsule lifecycle is proposal then activation and revocation", () => { const proposed = createIntentCapsule(input(), new Date("2027-01-01T00:00:00Z")); assert.equal(proposed.status, "PROPOSED"); const activeCapsule = activateIntentCapsule(proposed, new Date("2027-01-01T00:00:00Z")); assert.equal(activeCapsule.status, "ACTIVE"); assert.equal(revokeIntentCapsule(activeCapsule).status, "REVOKED"); assert.throws(() => activateIntentCapsule(activeCapsule)); });
test("expiry and malformed input fail closed", () => { assert.throws(() => createIntentCapsule(input({ expiresAt: "2026-01-01T00:00:00Z" }), new Date("2027-01-01T00:00:00Z"))); const capsule = active(); assert.throws(() => activateIntentCapsule({ ...capsule, digest: "bad" })); });
test("lease replay and call budget are enforced", () => { const lease = issueCapabilityLease(leaseInput(), active(), undefined, new Date("2027-01-01T00:00:00Z")); const spent = consumeCapabilityLease(lease); assert.equal(spent.remainingCalls, 1); assert.throws(() => consumeCapabilityLease(spent, { calls: 2 })); const exhausted = consumeCapabilityLease(spent); assert.equal(exhausted.status, "EXPIRED"); assert.throws(() => consumeCapabilityLease(exhausted)); });
test("revocation blocks evaluation", () => { const capsule = active(); const lease = issueCapabilityLease(leaseInput(), capsule, undefined, new Date("2027-01-01T00:00:00Z")); const request = { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] }; assert.equal(evaluateMonotonicAuthority(capsule, [lease], request).allowed, true); assert.equal(evaluateMonotonicAuthority(capsule, [revokeCapabilityLease(lease)], request).allowed, false); });
test("child lease is a monotonic subset", () => { const capsule = active(); const parent = issueCapabilityLease(leaseInput({ issuer: "capsule", subject: "delegator", remainingCalls: 2 }), capsule, undefined, new Date("2027-01-01T00:00:00Z")); const child = issueCapabilityLease(leaseInput({ issuer: "delegator", subject: "worker", parentLeaseId: parent.leaseId, remainingCalls: 1 }), capsule, parent, new Date("2027-01-01T00:00:00Z")); assert.equal(child.remainingCalls, 1); assert.throws(() => issueCapabilityLease(leaseInput({ issuer: "delegator", subject: "worker", parentLeaseId: parent.leaseId, capabilities: ["fs.write"], remainingCalls: 1 }), capsule, parent, new Date("2027-01-01T00:00:00Z"))); });
test("evaluation rejects a forged child lease that expands its parent", () => {
  const capsule = active();
  const parent = issueCapabilityLease(leaseInput({ issuer: "capsule", subject: "delegator", remainingCalls: 2 }), capsule, undefined, new Date("2027-01-01T00:00:00Z"));
  const validChild = issueCapabilityLease(leaseInput({ issuer: "delegator", subject: "worker", parentLeaseId: parent.leaseId, remainingCalls: 1 }), capsule, parent, new Date("2027-01-01T00:00:00Z"));
  const expandedBody: CapabilityLease = { ...validChild, capabilities: ["fs.read", "fs.write"], digest: "" };
  const expanded: CapabilityLease = { ...expandedBody, digest: digestJson({ leaseId: expandedBody.leaseId, parentLeaseId: expandedBody.parentLeaseId, issuer: expandedBody.issuer, subject: expandedBody.subject, capabilities: expandedBody.capabilities, constraints: expandedBody.constraints, remainingCalls: expandedBody.remainingCalls, issuedAt: expandedBody.issuedAt, expiresAt: expandedBody.expiresAt, authorityBindingDigest: expandedBody.authorityBindingDigest ?? null, status: expandedBody.status }) };
  const result = evaluateMonotonicAuthority(capsule, [parent, expanded], { tool: "read", capabilities: ["fs.read"], effects: ["data.observe"] }, new Date("2027-01-01T00:00:00Z"));
  assert.equal(result.allowed, false);
  assert.ok(result.reasonCodes.includes("LEASE_AUTHORITY_AMPLIFICATION"));
});
test("evaluation enforces lease constraints and exhausted budgets", () => { const capsule = active(); const lease = issueCapabilityLease(leaseInput({ remainingCalls: 1 }), capsule, undefined, new Date("2027-01-01T00:00:00Z")); const denied = evaluateMonotonicAuthority(capsule, [lease], { tool: "write", capabilities: ["fs.read"], effects: ["data.modify"], resources: { paths: ["/other"] }, dataLabels: ["secret"] }); assert.equal(denied.allowed, false); assert.ok(denied.reasonCodes.includes("TOOL_OUTSIDE_LEASE")); assert.ok(denied.reasonCodes.includes("EFFECT_OUTSIDE_LEASE")); assert.ok(denied.reasonCodes.includes("RESOURCE_PATHS_OUTSIDE_LEASE")); assert.ok(denied.reasonCodes.includes("DATA_LABEL_OUTSIDE_LEASE")); assert.equal(evaluateMonotonicAuthority(capsule, [{ ...lease, remainingCalls: 0, status: "EXPIRED" }], { tool: "read", capabilities: ["fs.read"], effects: ["data.observe"] }).allowed, false); });
test("delegation depth fails closed", () => { const capsule = active(); const lease = issueCapabilityLease(leaseInput(), capsule, undefined, new Date("2027-01-01T00:00:00Z")); const chain = Array.from({ length: 17 }, () => lease); const result = evaluateMonotonicAuthority(capsule, chain, { tool: "read", capabilities: ["fs.read"], effects: ["data.observe"] }); assert.equal(result.allowed, false); assert.ok(result.reasonCodes.includes("DELEGATION_DEPTH_EXCEEDED")); });

test("a child-only delegation chain cannot survive parent revocation", () => {
  const now = new Date("2027-01-01T00:00:00Z");
  const capsule = active();
  const parent = issueCapabilityLease(leaseInput({ issuer: "capsule", subject: "delegator", remainingCalls: 2 }), capsule, undefined, now);
  const child = issueCapabilityLease(leaseInput({ issuer: "delegator", subject: "worker", parentLeaseId: parent.leaseId, remainingCalls: 1 }), capsule, parent, now);
  const request = { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] };
  const childOnly = evaluateMonotonicAuthority(capsule, [child], request, now);
  assert.equal(childOnly.allowed, false);
  assert.ok(childOnly.reasonCodes.includes("INVALID_LEASE_CHAIN"));

  const store = new InvockStore(":memory:");
  try {
    store.authorizeAuthorityState(capsule, [parent, child], "session-a", now);
    store.revokeAuthorityLease(parent.leaseId, "session-a", now);
    assert.throws(() => store.authorizeAuthorityState(capsule, [child], "session-a", now), /AUTHORITY_LEASE_CHAIN_INCOMPLETE|AUTHORITY_LEASE_NOT_ACTIVE/u);
  } finally { store.close(); }
});

test("duration budgets are enforced against the persisted lease start", () => {
  const start = new Date("2027-01-01T00:00:00Z");
  const capsule = activateIntentCapsule(createIntentCapsule(input({ budgets: { calls: 2, durationSeconds: 1 } }), start), start);
  const lease = issueCapabilityLease(leaseInput({ remainingCalls: 2 }), capsule, undefined, start);
  const request = { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] };
  assert.equal(evaluateMonotonicAuthority(capsule, [lease], request, new Date("2027-01-01T00:00:00.500Z")).allowed, true);
  const expired = evaluateMonotonicAuthority(capsule, [lease], request, new Date("2027-01-01T00:00:02Z"));
  assert.equal(expired.allowed, false);
  assert.ok(expired.reasonCodes.includes("DURATION_BUDGET_EXCEEDED"));
});

test("capsules and leases are deeply immutable and lifecycle-bound", () => {
  const capsule = active();
  assert.throws(() => (capsule.allowedTools as string[]).push("write"), TypeError);
  const revokedCapsule = revokeIntentCapsule(capsule);
  assert.throws(() => activateIntentCapsule({ ...revokedCapsule, status: "PROPOSED" }), /digest|revocation/u);

  const lease = issueCapabilityLease(leaseInput(), capsule, undefined, new Date("2027-01-01T00:00:00Z"));
  assert.throws(() => (lease.constraints.tools as string[]).push("write"), TypeError);
  const revokedLease = revokeCapabilityLease(lease);
  const request = { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] };
  assert.equal(evaluateMonotonicAuthority(capsule, [revokedLease], request).allowed, false);
  assert.equal(evaluateMonotonicAuthority(capsule, [{ ...revokedLease, status: "ACTIVE" }], request).allowed, false);
});
