import assert from "node:assert/strict";
import { request } from "node:http";
import { test } from "node:test";
import { InvockStore } from "../src/storage/store.js";
import { startApi } from "../src/api/server.js";
import { InvockClient } from "../src/sdk/index.js";
import { testGate } from "../fixtures/testing/invock.js";
import { digestJson } from "../src/core/canonical.js";
import { generateSigningMaterial } from "../src/storage/receipts.js";
import { signContainmentRun } from "../src/containment/lifecycle.js";

test("loopback API authenticates activity and rejects hostile Host headers", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "test-token" });
  try {
    const unauthenticated = await fetch(`${api.url}/api/v1/activity`);
    assert.equal(unauthenticated.status, 401);
    const authenticated = await fetch(`${api.url}/api/v1/activity`, { headers: { authorization: "Bearer test-token" } });
    assert.equal(authenticated.status, 200);
    assert.deepEqual(await authenticated.json(), { items: [] });
    const parsed = new URL(api.url);
    const hostileHost = await new Promise<number>((resolve, reject) => {
      const probe = request({ hostname: parsed.hostname, port: parsed.port, path: "/api/v1/health", headers: { host: "attacker.test" } }, response => { response.resume(); response.once("end", () => resolve(response.statusCode ?? 0)); });
      probe.once("error", reject); probe.end();
    });
    assert.equal(hostileHost, 403);
  } finally { await api.close(); store.close(); }
});

test("SDK authorization reaches the canonical InvocationGate", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "test-token", gate: testGate(store) });
  try {
    const client = new InvockClient({ endpoint: api.url, token: api.token });
    const result = await client.authorize({ agent: "agent-1", tool: "read", arguments: {} });
    assert.equal(result.verdict, "ALLOW");
    assert.ok(Array.isArray(result.reasonCodes));
  } finally { await api.close(); store.close(); }
});

test("authorization is non-executing even when a contained handler is configured", async () => {
  const store = new InvockStore(":memory:");
  let executions = 0;
  const api = await startApi(store, { token: "authorize-token", gate: testGate(store), onContainedForward: async outcome => { executions += 1; return { result: { content: [{ type: "text", text: "must not run" }] }, containment: signedRun(outcome) }; } });
  try {
    const response = await fetch(`${api.url}/api/v1/authorize`, { method: "POST", headers: executeHeaders(api.token), body: JSON.stringify({ tool: "read", arguments: {} }) });
    const payload = await response.json() as { verdict?: string; receiptId?: string };
    assert.equal(response.status, 200);
    assert.equal(payload.verdict, "ALLOW");
    assert.equal(payload.receiptId, undefined);
    assert.equal(executions, 0);
    assert.equal(store.listReceipts().length, 0);
  } finally { await api.close(); store.close(); }
});

test("runtime resolution cannot start the API without a canonical gate", () => {
  const store = new InvockStore(":memory:");
  try { assert.throws(() => startApi(store, { resolveRuntime: async () => ({}) }), /canonical InvocationGate/u); }
  finally { store.close(); }
});

test("API session identity is server-bound and cannot be selected by the request body", async () => {
  const store = new InvockStore(":memory:");
  const seen: string[] = [];
  const api = await startApi(store, { token: "session-token", sessionId: "server-session", gate: testGate(store), resolveRuntime: async input => { const sessionId = input.sessionId ?? "missing"; seen.push(sessionId); return { overrides: { sessionId } }; } });
  try {
    const headers = { authorization: "Bearer session-token", "content-type": "application/json" };
    const mismatched = await fetch(`${api.url}/api/v1/authorize`, { method: "POST", headers, body: JSON.stringify({ tool: "read", arguments: {}, sessionId: "caller-selected" }) });
    assert.equal(mismatched.status, 400);
    assert.deepEqual(await mismatched.json(), { error: "bad_request" });
    assert.deepEqual(seen, []);
    const accepted = await fetch(`${api.url}/api/v1/authorize`, { method: "POST", headers, body: JSON.stringify({ tool: "read", arguments: {} }) });
    assert.equal(accepted.status, 200);
    assert.deepEqual(seen, ["server-session"]);
    const unboundStore = new InvockStore(":memory:");
    const unboundApi = await startApi(unboundStore, { token: "unbound-token", gate: testGate(unboundStore), resolveRuntime: async () => { throw new Error("resolver must not receive caller session"); } });
    try {
      const unbound = await fetch(`${unboundApi.url}/api/v1/authorize`, { method: "POST", headers: { authorization: "Bearer unbound-token", "content-type": "application/json" }, body: JSON.stringify({ tool: "read", arguments: {}, sessionId: "caller-selected" }) });
      assert.equal(unbound.status, 400);
      assert.deepEqual(await unbound.json(), { error: "bad_request" });
    } finally { await unboundApi.close(); unboundStore.close(); }
  } finally { await api.close(); store.close(); }
});

test("authorization endpoint fails closed when no handler is wired", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "test-token" });
  try {
    const response = await fetch(`${api.url}/api/v1/authorize`, { method: "POST", headers: { authorization: "Bearer test-token", "content-type": "application/json" }, body: JSON.stringify({ tool: "read_file", arguments: {} }) });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "authorization_gate_unavailable" });
  } finally { await api.close(); store.close(); }
});

function executeHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, "content-type": "application/json" };
}

function signedRun(outcome: Extract<Awaited<ReturnType<ReturnType<typeof testGate>["authorizeInvocation"]>>, { kind: "forward" }>, authorizedRequestDigest = outcome.envelope.integrity.requestDigest) {
  return signContainmentRun({
    schemaVersion: "invock/containment-run/v2",
    runId: `api-contained-${outcome.envelope.invocationId}`,
    createdAt: "2026-08-01T00:00:00.000Z",
    requestDigest: digestJson({ command: "contained-test", argv: [] }),
    authorizedRequestDigest,
    command: "contained-test",
    invocationId: outcome.envelope.invocationId,
    sessionId: outcome.envelope.sessionId,
    profileDigest: digestJson({ sandbox: "test", network: "none" }),
    result: { status: "completed", stdout: "", stderr: "", durationMs: 1, reasonCodes: [], cleanup: "completed", capabilities: { sandbox: "available", network: "denied", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
  }, generateSigningMaterial());
}

test("execute endpoint denies before invoking contained execution", async () => {
  const store = new InvockStore(":memory:");
  let executions = 0;
  const api = await startApi(store, { token: "execute-token", gate: testGate(store), onContainedForward: async () => { executions += 1; throw new Error("must not run"); } });
  try {
    const response = await fetch(`${api.url}/api/v1/execute`, { method: "POST", headers: executeHeaders(api.token), body: JSON.stringify({ tool: "unknown", arguments: {} }) });
    const payload = await response.json() as { verdict?: string };
    assert.equal(response.status, 200);
    assert.equal(payload.verdict, "BLOCK");
    assert.equal(executions, 0);
  } finally { await api.close(); store.close(); }
});

test("execute endpoint fail-closes with one denial receipt when contained handler is missing", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "execute-token", gate: testGate(store) });
  try {
    const response = await fetch(`${api.url}/api/v1/execute`, { method: "POST", headers: executeHeaders(api.token), body: JSON.stringify({ tool: "read", arguments: {} }) });
    const payload = await response.json() as { verdict?: string; receiptId?: string; reasonCodes?: string[] };
    assert.equal(response.status, 200);
    assert.equal(payload.verdict, "BLOCK");
    assert.ok(payload.reasonCodes?.includes("CONTAINED_EXECUTION_UNAVAILABLE"));
    assert.equal(typeof payload.receiptId, "string");
    assert.equal(store.getReceipt(payload.receiptId as string)?.payload.upstreamForwarded, false);
  } finally { await api.close(); store.close(); }
});

test("execute endpoint attaches the signed run before returning the bounded result", async () => {
  const store = new InvockStore(":memory:");
  let executions = 0;
  const api = await startApi(store, { token: "execute-token", gate: testGate(store), onContainedForward: async outcome => { executions += 1; return { result: { content: [{ type: "text", text: "contained" }], structuredContent: { source: "sandbox" } }, containment: signedRun(outcome) }; } });
  try {
    const client = new InvockClient({ endpoint: api.url, token: api.token });
    const payload = await client.execute({ tool: "read", arguments: {} });
    assert.equal(payload.verdict, "ALLOW");
    assert.equal(payload.result?.content[0]?.text, "contained");
    assert.equal(executions, 1);
    const receipts = store.listReceipts();
    assert.equal(receipts.length, 1);
    assert.equal(typeof receipts[0]?.payload.containmentRunId, "string");
    assert.equal(store.verifyChain(), true);
  } finally { await api.close(); store.close(); }
});

test("execute endpoint rejects malformed results and incorrect containment bindings without completing execution", async () => {
  for (const mode of ["malformed", "wrong-binding"] as const) {
    const store = new InvockStore(":memory:");
    const api = await startApi(store, { token: "execute-token", gate: testGate(store), onContainedForward: async outcome => ({
      result: mode === "malformed" ? ({ content: [{ type: "image", text: "bad" }] } as never) : { content: [{ type: "text", text: "should not be released" }] },
      containment: signedRun(outcome, mode === "wrong-binding" ? digestJson({ wrong: true }) : undefined),
    }) });
    try {
      const response = await fetch(`${api.url}/api/v1/execute`, { method: "POST", headers: executeHeaders(api.token), body: JSON.stringify({ tool: "read", arguments: {} }) });
      const payload = await response.json() as { verdict?: string; receiptId?: string };
      assert.equal(response.status, 200);
      assert.equal(payload.verdict, "BLOCK");
      assert.equal(typeof payload.receiptId, "string");
      assert.equal(store.getReceipt(payload.receiptId as string)?.payload.upstreamForwarded, false);
    } finally { await api.close(); store.close(); }
  }
});

test("contained API handlers fail closed with a denial receipt when execution throws", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "execute-token", gate: testGate(store), onContainedForward: async () => { throw new Error("contained runtime crashed"); } });
  try {
    const response = await fetch(`${api.url}/api/v1/execute`, { method: "POST", headers: executeHeaders(api.token), body: JSON.stringify({ tool: "read", arguments: {} }) });
    const payload = await response.json() as { verdict?: string; receiptId?: string; reasonCodes?: string[] };
    assert.equal(response.status, 200);
    assert.equal(payload.verdict, "BLOCK");
    assert.ok(payload.reasonCodes?.includes("CONTAINED_EXECUTION_FAILED"));
    assert.equal(typeof payload.receiptId, "string");
    assert.equal(store.getReceipt(payload.receiptId as string)?.payload.upstreamForwarded, false);
    assert.equal(store.verifyChain(), true);
  } finally { await api.close(); store.close(); }
});
