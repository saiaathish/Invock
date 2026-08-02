import assert from "node:assert/strict";
import test from "node:test";
import { InvockClient } from "../../src/sdk/index.js";

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

test("SDK posts normalized endpoint, bearer token, and JSON body", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const client = new InvockClient({ endpoint: "http://127.0.0.1:4317/", token: "test-token", fetchImpl: async (url, init) => { calls.push({ url: String(url), init: init ?? {} }); return response({ verdict: "ALLOW", reasonCodes: [], receiptId: "r1", containmentRequired: false }); } });
  assert.deepEqual(await client.authorize({ agent: "agent-1", tool: "read", arguments: { path: "safe.txt" } }), { verdict: "ALLOW", reasonCodes: [], receiptId: "r1", containmentRequired: false });
  assert.equal(calls[0]?.url, "http://127.0.0.1:4317/api/v1/authorize");
  assert.equal(calls[0]?.init.method, "POST");
  assert.equal((calls[0]?.init.headers as Record<string, string>).authorization, "Bearer test-token");
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { agent: "agent-1", tool: "read", arguments: { path: "safe.txt" } });
});

for (const verdict of ["ALLOW", "BLOCK", "APPROVAL_REQUIRED"] as const) {
  test(`SDK parses ${verdict}`, async () => {
    const client = new InvockClient({ endpoint: "http://localhost", token: "t", fetchImpl: async () => response({ verdict, reasonCodes: ["REASON"], approvalId: verdict === "APPROVAL_REQUIRED" ? "a1" : undefined }) });
    const result = await client.authorize({ tool: "tool", arguments: {} });
    assert.equal(result.verdict, verdict);
    assert.deepEqual(result.reasonCodes, ["REASON"]);
  });
}

test("SDK rejects HTTP errors and malformed responses", async () => {
  const httpError = new InvockClient({ endpoint: "http://localhost", token: "t", fetchImpl: async () => response({ error: "no" }, 403) });
  await assert.rejects(httpError.authorize({ tool: "tool", arguments: {} }), /HTTP 403/u);
  const malformed = new InvockClient({ endpoint: "http://localhost", token: "t", fetchImpl: async () => response({ verdict: "MAYBE", reasonCodes: [] }) });
  await assert.rejects(malformed.authorize({ tool: "tool", arguments: {} }), /malformed verdict/u);
  const missingReasons = new InvockClient({ endpoint: "http://localhost", token: "t", fetchImpl: async () => response({ verdict: "BLOCK" }) });
  await assert.rejects(missingReasons.authorize({ tool: "tool", arguments: {} }), /reasonCodes/u);
});

test("SDK health uses GET and rejects non-HTTP endpoints", async () => {
  let method = "";
  const client = new InvockClient({ endpoint: "https://localhost/base", token: "t", fetchImpl: async (_url, init) => { method = String(init?.method); return response({ status: "ok" }); } });
  assert.deepEqual(await client.health(), { status: "ok" });
  assert.equal(method, "GET");
  const invalid = new InvockClient({ endpoint: "file:///tmp/invock", token: "t", fetchImpl: async () => response({}) });
  await assert.rejects(invalid.health(), /http or https/u);
});

test("SDK execute uses the server-side contained execution endpoint and bounds results", async () => {
  const calls: string[] = [];
  const client = new InvockClient({ endpoint: "http://localhost", token: "t", fetchImpl: async url => { calls.push(String(url)); return response({ verdict: "ALLOW", reasonCodes: ["READ"], receiptId: "receipt-1", result: { content: [{ type: "text", text: "contained" }], structuredContent: { value: 1 } } }); } });
  assert.deepEqual(await client.execute({ tool: "read", arguments: {} }), { verdict: "ALLOW", reasonCodes: ["READ"], receiptId: "receipt-1", result: { content: [{ type: "text", text: "contained" }], structuredContent: { value: 1 } } });
  assert.deepEqual(calls, ["http://localhost/api/v1/execute"]);
});

test("SDK execute rejects malformed contained results", async () => {
  const client = new InvockClient({ endpoint: "http://localhost", token: "t", fetchImpl: async () => response({ verdict: "ALLOW", reasonCodes: [], receiptId: "receipt-1", result: { content: [{ type: "image", text: "not allowed" }] } }) });
  await assert.rejects(client.execute({ tool: "read", arguments: {} }), /malformed result content/u);
});
