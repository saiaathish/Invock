import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { digestJson } from "../src/core/canonical.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { startStreamableHttpGateway } from "../src/mcp/http.js";
import { negotiateEra } from "../src/mcp/protocol.js";
import { PersistentToolRegistry, ToolRegistry } from "../src/registry/registry.js";
import { InvockStore } from "../src/storage/store.js";

function fixtureGate() {
  const dir = mkdtempSync(join(tmpdir(), "invock-http-"));
  const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: http }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: block-secret
    decision: BLOCK
    reasonCodes: [PATH_PROTECTED]
    when: { resources: { paths: { labels: { any: [secret] } } } }
`));
  const store = new InvockStore(join(dir, "gateway.sqlite"));
  const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path" }] } }), store, { cwd: dir, projectRoot: realpathSync(dir), organizationDomains: [], sessionId: "http", principal: { principalId: "test", clientId: "test", scopes: [] } }, { allowUnboundForTests: true });
  return { dir, store, gate, close: () => { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("HTTP MCP gateway blocks before its upstream forwarding port", async () => {
  const fixture = fixtureGate(); let forwarded = 0;
  const http = await startStreamableHttpGateway(fixture.gate, { token: "gateway-token", forward: async message => { forwarded++; return { jsonrpc: "2.0", id: "id" in message ? message.id : null, result: { content: [{ type: "text", text: "upstream" }] } }; } });
  try {
    const response = await fetch(http.url, { method: "POST", headers: { authorization: "Bearer gateway-token", "content-type": "application/json", accept: "application/json", host: new URL(http.url).host }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read", arguments: { path: ".env" } } }) });
    const body = await response.json() as { result: { structuredContent: { verdict: string } } };
    assert.equal(response.status, 200); assert.equal(body.result.structuredContent.verdict, "BLOCK"); assert.equal(forwarded, 0);
  } finally { await http.close(); fixture.close(); }
});

test("protocol candidate flag and dangerous tool drift both fail closed", () => {
  assert.throws(() => negotiateEra("2026-07-28"));
  assert.equal(negotiateEra("2026-07-28", true).kind, "candidate-2026");
  const registry = new ToolRegistry(); const normalizer = { fields: [{ pointer: "/path", type: "path" as const }] };
  registry.discover("server", { name: "read", inputSchema: { type: "object", properties: { path: { type: "string" } } } }, normalizer);
  const updated = registry.discover("server", { name: "read", inputSchema: { type: "object", properties: { path: { type: "string" }, command: { type: "string" } }, required: ["command"] } }, normalizer);
  assert.equal(updated.drift.severity, "high"); assert.equal(updated.tool.status, "quarantined");
});

test("ordinary schema drift and malformed discovery quarantine active tools", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-registry-quarantine-"));
  const store = new InvockStore(join(directory, "registry.sqlite"));
  try {
    const registry = new PersistentToolRegistry(store, "server");
    const normalizer = { fields: [{ pointer: "/path", type: "path" as const }] };
    registry.discover({ name: "read", inputSchema: { type: "object", properties: { path: { type: "string" } } } }, normalizer);
    const drift = registry.discover({ name: "read", inputSchema: { type: "object", properties: { path: { type: "string" }, optional: { type: "string" } } } }, normalizer);
    assert.equal(drift.tool.status, "quarantined");
    assert.equal(registry.isQuarantined("read"), true);
    registry.observeToolsList({ tools: [{ name: "read", inputSchema: { type: "object" }, annotations: {} }] });
    assert.equal(registry.isQuarantined("read"), true);
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("registry persists trust inventory, validates output schema, and requires explicit release review", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-registry-trust-"));
  const store = new InvockStore(join(directory, "registry.sqlite"));
  try {
    const registry = new PersistentToolRegistry(store, "server");
    const outputSchema = { type: "object", properties: { ok: { type: "boolean" } } };
    const normalizer = { fields: [{ pointer: "/path", type: "path" as const }] };
    const descriptor = { name: "read", inputSchema: { type: "object", properties: { path: { type: "string" } } }, outputSchema, annotations: {
      "io.invock/normalizer": normalizer,
      "io.invock/trust": { sourceType: "oci", image: "registry.example/read", imageDigest: "sha256:" + "b".repeat(64), signature: { status: "verified", keyId: "key-1" }, sbomReference: "sbom:local", outputSchemaDigest: digestJson(outputSchema), dependencyEvidence: { status: "current" }, containerEvidence: { status: "current" } },
    } };
    const first = registry.discover(descriptor, normalizer);
    assert.equal(first.tool.status, "active");
    assert.equal(registry.trustInventory("read")?.signature?.status, "verified");
    assert.equal(registry.trustInventory("read")?.outputSchemaDigest, digestJson(outputSchema));

    const reopened = new PersistentToolRegistry(store, "server");
    assert.equal(reopened.trustInventory("read")?.sbomReference, "sbom:local");
    const drift = reopened.discover({ ...descriptor, outputSchema: { type: "array" } }, normalizer);
    assert.equal(drift.tool.status, "quarantined");
    assert.equal(reopened.reviewQuarantine("read", "release", "reviewer@example.test"), false);
    const updatedOutputSchema = { type: "array" };
    const updatedDescriptor = { ...descriptor, outputSchema: updatedOutputSchema, annotations: { ...descriptor.annotations, "io.invock/trust": { ...descriptor.annotations["io.invock/trust"], outputSchemaDigest: digestJson(updatedOutputSchema) } } };
    assert.equal(reopened.discover(updatedDescriptor, normalizer).tool.status, "quarantined");
    assert.equal(reopened.reviewQuarantine("read", "release", "reviewer@example.test"), true);
    assert.equal(reopened.isQuarantined("read"), false);
    assert.equal(reopened.trustInventory("read")?.review?.state, "released");
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("registry fails closed on invalid trust metadata", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-registry-invalid-trust-"));
  const store = new InvockStore(join(directory, "registry.sqlite"));
  try {
    const registry = new PersistentToolRegistry(store, "server");
    const normalizer = { fields: [] };
    const result = registry.discover({ name: "unsafe", inputSchema: { type: "object" }, annotations: { "io.invock/trust": { imageDigest: "not-a-digest" } } }, normalizer);
    assert.equal(result.tool.status, "quarantined");
    assert.equal(store.getToolRegistry("server", "unsafe")?.quarantineReason, "INVALID_IMAGE_DIGEST");
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("registry quarantines non-object trust metadata instead of spreading it", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-registry-malformed-trust-"));
  const store = new InvockStore(join(directory, "registry.sqlite"));
  try {
    const registry = new PersistentToolRegistry(store, "server");
    const result = registry.discover({ name: "unsafe", inputSchema: { type: "object" }, annotations: { "io.invock/trust": "verified" } }, { fields: [] });
    assert.equal(result.tool.status, "quarantined");
    assert.equal(store.getToolRegistry("server", "unsafe")?.quarantineReason, "INVALID_TRUST_METADATA");
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});
