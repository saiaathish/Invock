import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { activateIntentCapsule, createIntentCapsule, evaluateMonotonicAuthority, issueCapabilityLease } from "../src/authority/index.js";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { digestJson } from "../src/core/canonical.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { InvockStore } from "../src/storage/store.js";

test("authority kernel rejects explicit unknown capability and effect values", () => {
  const now = new Date("2027-01-01T00:00:00.000Z");
  const capsule = activateIntentCapsule(createIntentCapsule({ version: 1, purpose: "read", allowedTools: ["read"], allowedCapabilities: ["fs.read"], allowedEffects: ["data.observe"], resourceConstraints: { paths: ["/tmp"], domains: ["example.test"], recipients: ["local"] }, dataConstraints: { allowedLabels: ["public"], forbiddenLabels: ["secret"] }, budgets: { calls: 1 }, expiresAt: "2028-01-01T00:00:00.000Z" }, now), now);
  const lease = issueCapabilityLease({ issuer: "capsule", subject: "worker", capabilities: ["fs.read"], constraints: { tools: ["read"], effects: ["data.observe"], resources: { paths: ["/tmp"], domains: ["example.test"], recipients: ["local"] }, data: { allowedLabels: ["public"], forbiddenLabels: ["secret"] } }, remainingCalls: 1, issuedAt: now.toISOString(), expiresAt: "2027-12-01T00:00:00.000Z" }, capsule, undefined, now);
  const result = evaluateMonotonicAuthority(capsule, [lease], { tool: "read", capabilities: ["unknown"], effects: ["unknown"] });
  assert.equal(result.allowed, false);
  assert.ok(result.reasonCodes.includes("UNKNOWN_CAPABILITY"));
  assert.ok(result.reasonCodes.includes("UNKNOWN_EFFECT"));
});

test("policy omission of unknown capability and effect defaults fails closed", () => {
  const compiled = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: omitted-unknown-defaults }
defaults: { decision: ALLOW }
rules:
  - id: allow-observed
    decision: ALLOW
    reasonCodes: []
    when: { uncertainty: { empty: true } }
`));
  assert.equal(compiled.policy.defaults.unknownCapability, "BLOCK");
  assert.equal(compiled.policy.defaults.unknownEffect, "BLOCK");
});

test("runtime normalizer type confusion fails closed before forwarding", async () => {
  const dir = mkdtempSync(join(tmpdir(), "invock-normalizer-hardening-"));
  const store = new InvockStore(join(dir, "state.sqlite"));
  const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: fail-closed }
defaults: { decision: ALLOW }
rules:
  - id: never
    decision: ALLOW
    reasonCodes: []
    when: { any: [] }
`));
  const hostile = { fields: [{ pointer: "/url", type: "untrusted-runtime-type" }] } as never;
  const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ fetch: hostile }), store, { cwd: dir, projectRoot: dir, organizationDomains: [], sessionId: "hardening", principal: { principalId: "test", clientId: "test", scopes: [] } }, { allowUnboundForTests: true });
  try {
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "fetch", arguments: { url: "https://outside.test" } } });
    assert.notEqual(outcome.kind, "forward");
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.ok((outcome.response.result.structuredContent?.reasonCodes as string[]).includes("UNKNOWN_NORMALIZER"));
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("caller-supplied receipt identity metadata is rejected and never signed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "invock-receipt-provenance-"));
  const store = new InvockStore(":memory:");
  const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: receipt-provenance }
defaults: { decision: ALLOW }
rules:
  - id: allow
    decision: ALLOW
    reasonCodes: []
    when: { any: [] }
`));
  const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), store, { cwd: dir, projectRoot: dir, organizationDomains: [], sessionId: "provenance", principal: { principalId: "agent", clientId: "test", scopes: [] } }, { allowUnboundForTests: true });
  try {
    const fakeDigest = digestJson("caller-controlled");
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { receiptMetadata: { identityDigest: fakeDigest, sessionDigest: fakeDigest, projectDigest: fakeDigest, agentDigest: fakeDigest, identityBindingDigest: digestJson({ identityDigest: fakeDigest, sessionDigest: fakeDigest, projectDigest: fakeDigest, agentDigest: fakeDigest }) } } as never);
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") {
      const receiptId = outcome.response.result.structuredContent?.receiptId;
      assert.equal(typeof receiptId, "string");
      assert.equal(store.getReceipt(receiptId as string)?.payload.identityDigest, undefined);
    }
  } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
});
