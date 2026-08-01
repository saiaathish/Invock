import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { startStreamableHttpGateway } from "../src/mcp/http.js";
import { negotiateEra } from "../src/mcp/protocol.js";
import { ToolRegistry } from "../src/registry/registry.js";
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
  const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path" }] } }), store, { cwd: dir, projectRoot: realpathSync(dir), organizationDomains: [], sessionId: "http", principal: { principalId: "test", clientId: "test", scopes: [] } });
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