import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { IdentityAuthority } from "../src/identity/index.js";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { InvockStore } from "../src/storage/store.js";
import { digestJson } from "../src/core/canonical.js";

function policy() {
  return compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: identity-gateway-test }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: allow-read
    decision: ALLOW
    reasonCodes: []
    when: { uncertainty: { empty: true } }
`));
}

test("identity evidence binding is carried into the signed receipt", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-identity-gateway-"));
  const store = new InvockStore(":memory:");
  try {
    writeFileSync(join(directory, "safe.txt"), "safe");
    const now = new Date("2026-01-01T00:00:00.000Z");
    const authority = new IdentityAuthority();
    const enrolled = authority.enroll({ organizationId: "org-1", projectId: "project-1", displayName: "worker", runtimeType: "node" }, now);
    const attested = authority.attest(enrolled.identity.id, { build: "identity-gateway-test" }, now);
    const session = authority.openSession(attested.identity.id, attested.identity.projectId, 60, now);
    const binding = authority.evidenceBinding(attested.identity, session, now);
    const gate = new InvocationGate(policy(), new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: session.id, principal: { principalId: attested.identity.id, clientId: "test", agentId: attested.identity.id, scopes: ["*"] }, now: () => now }, { allowUnboundForTests: true });
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { identityBinding: binding, identityAuthority: authority, identityContext: { identity: attested.identity, session }, projectId: attested.identity.projectId, sessionId: session.id });
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") throw new Error("expected forward");
    const receipt = store.getReceipt(gate.finish(outcome, { content: [{ type: "text", text: "ok" }] }, now));
    assert.equal(receipt?.payload.identityDigest, binding.identityDigest);
    assert.equal(receipt?.payload.sessionDigest, binding.sessionDigest);
    assert.equal(receipt?.payload.projectDigest, binding.projectDigest);
    assert.equal(receipt?.payload.agentDigest, binding.agentDigest);
    assert.equal(receipt?.payload.identityBindingDigest, binding.bindingDigest);
    assert.equal(receipt?.payload.attestationDigest, digestJson(attested.attestation));
    assert.equal(store.verifyChain(), true);
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("enrolled but unattested workload identity is denied at the gateway", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-identity-gateway-unattested-"));
  const store = new InvockStore(":memory:");
  try {
    writeFileSync(join(directory, "safe.txt"), "safe");
    const now = new Date("2026-01-01T00:00:00.000Z");
    const authority = new IdentityAuthority();
    const enrolled = authority.enroll({ organizationId: "org-1", projectId: "project-1", displayName: "worker", runtimeType: "node" }, now);
    const session = authority.openSession(enrolled.identity.id, enrolled.identity.projectId, 60, now);
    const binding = authority.evidenceBinding(enrolled.identity, session, now);
    const gate = new InvocationGate(policy(), new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: session.id, principal: { principalId: enrolled.identity.id, clientId: "test", agentId: enrolled.identity.id, scopes: ["*"] }, now: () => now }, { allowUnboundForTests: true });
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { identityBinding: binding, identityAuthority: authority, identityContext: { identity: enrolled.identity, session }, projectId: enrolled.identity.projectId, sessionId: session.id });
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.ok((outcome.response.result.structuredContent?.reasonCodes as string[]).includes("IDENTITY_BINDING_INVALID"));
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("tampered identity evidence binding is denied before forwarding", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-identity-gateway-tamper-"));
  const store = new InvockStore(":memory:");
  try {
    writeFileSync(join(directory, "safe.txt"), "safe");
    const now = new Date("2026-01-01T00:00:00.000Z");
    const authority = new IdentityAuthority();
    const enrolled = authority.enroll({ organizationId: "org-1", projectId: "project-1", displayName: "worker", runtimeType: "node" }, now);
    const session = authority.openSession(enrolled.identity.id, enrolled.identity.projectId, 60, now);
    const binding = authority.evidenceBinding(enrolled.identity, session, now);
    const gate = new InvocationGate(policy(), new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: session.id, principal: { principalId: enrolled.identity.id, clientId: "test", agentId: enrolled.identity.id, scopes: ["*"] }, now: () => now }, { allowUnboundForTests: true });
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { identityBinding: { ...binding, bindingDigest: "bad" }, identityAuthority: authority, identityContext: { identity: enrolled.identity, session }, projectId: enrolled.identity.projectId, sessionId: session.id });
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.match(String(outcome.response.result.structuredContent?.reasonCodes), /IDENTITY_BINDING_INVALID/u);
    assert.equal(store.listActivity()[0]?.status, "blocked");
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("self-consistent identity evidence without authoritative runtime context is denied", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-identity-gateway-unverified-"));
  const store = new InvockStore(":memory:");
  try {
    writeFileSync(join(directory, "safe.txt"), "safe");
    const now = new Date("2026-01-01T00:00:00.000Z");
    const authority = new IdentityAuthority();
    const enrolled = authority.enroll({ organizationId: "org-1", projectId: "project-1", displayName: "worker", runtimeType: "node" }, now);
    const session = authority.openSession(enrolled.identity.id, enrolled.identity.projectId, 60, now);
    const binding = authority.evidenceBinding(enrolled.identity, session, now);
    const gate = new InvocationGate(policy(), new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: session.id, principal: { principalId: enrolled.identity.id, clientId: "test", agentId: enrolled.identity.id, scopes: ["*"] }, now: () => now }, { allowUnboundForTests: true });
    const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" } } }, { identityBinding: binding, projectId: enrolled.identity.projectId, sessionId: session.id });
    assert.equal(outcome.kind, "respond");
    if (outcome.kind === "respond") assert.match(String(outcome.response.result.structuredContent?.reasonCodes), /IDENTITY_BINDING_INVALID/u);
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});
