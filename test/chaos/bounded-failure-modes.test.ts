import assert from "node:assert/strict";
import { createConnection } from "node:net";
import { request } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { startApi } from "../../src/api/server.js";
import { digestJson } from "../../src/core/canonical.js";
import { generateSigningMaterial } from "../../src/storage/receipts.js";
import { InvockStore } from "../../src/storage/store.js";
import { testAuthority, testCall, testGate, TEST_NOW } from "../../fixtures/testing/invock.js";
import type { InvocationRuntimeOverrides } from "../../src/gateway/engine.js";

function tempRoot(label: string): string { return mkdtempSync(join(tmpdir(), `invock-${label}-`)); }

async function authorizeAndFail(store: InvockStore, message: string) {
  const gate = testGate(store);
  const outcome = await gate.authorizeInvocation(testCall(1));
  assert.equal(outcome.kind, "forward");
  if (outcome.kind !== "forward") throw new Error("fixture did not produce a forwardable call");
  const receiptId = gate.fail(outcome, message, TEST_NOW);
  assert.ok(store.getReceipt(receiptId));
}

function httpPost(url: string, token: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = request({ hostname: target.hostname, port: Number(target.port), path: target.pathname, method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, response => {
      const chunks: Buffer[] = [];
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.setTimeout(1000, () => req.destroy(new Error("client timeout")));
    req.on("error", reject);
    req.end(body);
  });
}

test("chaos: upstream crash is recorded as a completed fail-safe receipt", async () => {
  const store = new InvockStore();
  try { await authorizeAndFail(store, "upstream process crashed"); assert.equal(store.verifyChain(), true); }
  finally { store.close(); }
});

test("chaos: upstream timeout is bounded by the existing fail API and leaves a verifiable receipt", async () => {
  const store = new InvockStore();
  try {
    const gate = testGate(store); const outcome = await gate.authorizeInvocation(testCall(2));
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") throw new Error("fixture did not produce a forwardable call");
    const bounded = await Promise.race([Promise.resolve(gate.fail(outcome, "upstream timeout", TEST_NOW)), new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout recorder exceeded bound")), 250))]);
    assert.ok(store.getReceipt(bounded)); assert.equal(store.verifyChain(), true);
  } finally { store.close(); }
});

test("chaos: SQLite database lock rejects a concurrent write and recovers after rollback", () => {
  const root = tempRoot("lock"); const database = join(root, "state.sqlite");
  const first = new InvockStore(database); const second = new InvockStore(database);
  try {
    second.db.exec("PRAGMA busy_timeout = 50");
    first.db.exec("BEGIN EXCLUSIVE");
    assert.throws(() => second.saveExpansionRecord({ recordId: "lock-case", recordType: "arena_run", digest: digestJson({ bounded: true }), payload: { bounded: true }, status: "pending", now: TEST_NOW }));
    first.db.exec("ROLLBACK");
    assert.equal(second.isReady(), true);
  } finally { try { first.db.exec("ROLLBACK"); } catch {} second.close(); first.close(); rmSync(root, { recursive: true, force: true }); }
});

test("chaos: a corrupt chain head makes the restarted store unready", async () => {
  const root = tempRoot("head"); const database = join(root, "state.sqlite");
  const store = new InvockStore(database);
  try { await authorizeAndFail(store, "head corruption fixture"); const keyDirectory = store.keyDirectory; const headPath = join(keyDirectory, "chain-head.json"); store.close(); const head = JSON.parse(readFileSync(headPath, "utf8")) as Record<string, unknown>; head.receiptCount = Number(head.receiptCount) + 1; writeFileSync(headPath, JSON.stringify(head)); assert.throws(() => new InvockStore(database), /Receipt chain verification failed/); }
  finally { try { store.close(); } catch {} rmSync(root, { recursive: true, force: true }); }
});

test("chaos: truncating the chain-head file is rejected as possible terminal truncation", async () => {
  const root = tempRoot("head-truncate"); const database = join(root, "state.sqlite"); const store = new InvockStore(database);
  try { await authorizeAndFail(store, "head truncation fixture"); const headPath = join(store.keyDirectory, "chain-head.json"); store.close(); writeFileSync(headPath, ""); assert.throws(() => new InvockStore(database), /terminal truncation/); }
  finally { try { store.close(); } catch {} rmSync(root, { recursive: true, force: true }); }
});

test("chaos: a clean restart preserves a valid receipt chain", async () => {
  const root = tempRoot("restart"); const database = join(root, "state.sqlite");
  const first = new InvockStore(database);
  try { await authorizeAndFail(first, "restart fixture"); const receiptId = first.listActivity()[0]?.receiptId; first.close(); const second = new InvockStore(database); try { assert.equal(second.isReady(), true); assert.ok(receiptId && second.getReceipt(receiptId)); } finally { second.close(); } }
  finally { try { first.close(); } catch {} rmSync(root, { recursive: true, force: true }); }
});

test("chaos: duplicate authorization with an exhausted capability lease is denied", async () => {
  const store = new InvockStore(); const gate = testGate(store); const authority = testAuthority(1); let leases: readonly typeof authority.lease[] = [authority.lease];
  try {
    const consume = (next: readonly typeof authority.lease[]) => { leases = next; };
    const runtime: InvocationRuntimeOverrides = { authority: { capsule: authority.capsule, leases, request: { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] }, sessionId: "session-a", consume } };
    const first = await gate.authorizeInvocation(testCall(10), runtime); assert.equal(first.kind, "forward");
    if (first.kind !== "forward") throw new Error("first duplicate fixture was not forwardable");
    assert.equal(leases[0]?.status, "EXPIRED");
    const second = await gate.authorizeInvocation(testCall(10), { authority: { capsule: authority.capsule, leases, request: { tool: "read", capabilities: ["fs.read" as const], effects: ["data.observe" as const] }, sessionId: "session-a", consume } });
    assert.notEqual(second.kind, "forward");
  } finally { store.close(); }
});

test("chaos: truncated JSON body returns bounded 400 without invoking authorization", async () => {
  const store = new InvockStore(); let called = false;
  const api = await startApi(store, { token: "chaos-token", gate: testGate(store), resolveRuntime: async () => { called = true; return {}; } });
  try { const response = await httpPost(`${api.url}/api/v1/authorize`, api.token, "{\"tool\":"); assert.equal(response.status, 400); assert.equal(called, false); }
  finally { await api.close(); store.close(); }
});

test("chaos: an interrupted client connection does not create an authorization receipt", async () => {
  const store = new InvockStore(); let called = false;
  const api = await startApi(store, { token: "chaos-token", gate: testGate(store), resolveRuntime: async () => { called = true; return {}; } });
  try {
    const target = new URL(api.url); await new Promise<void>((resolve) => { const socket = createConnection({ host: target.hostname, port: Number(target.port) }, () => { socket.write(`POST /api/v1/authorize HTTP/1.1\r\nHost: ${target.host}\r\nAuthorization: Bearer ${api.token}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"tool\":\"read\"`); socket.destroy(); }); socket.once("close", () => resolve()); socket.setTimeout(500, () => { socket.destroy(); resolve(); }); });
    assert.equal(called, false); assert.equal(store.verifyChain(), true);
  } finally { await api.close(); store.close(); }
});

test("chaos: API restart returns health after a prior server close", async () => {
  const store = new InvockStore();
  const first = await startApi(store, { token: "restart-token" }); const firstUrl = first.url; await first.close();
  const second = await startApi(store, { token: "restart-token" });
  try { const response = await new Promise<number>((resolve, reject) => { const req = request(`${second.url}/api/v1/health`, { headers: { host: new URL(second.url).host } }, res => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); }); req.on("error", reject); req.end(); }); assert.equal(response, 200); assert.notEqual(second.url, ""); assert.notEqual(firstUrl, ""); }
  finally { await second.close(); store.close(); }
});

test("chaos: replacing signing material makes persisted evidence unready", async () => {
  const root = tempRoot("key"); const database = join(root, "state.sqlite"); const first = new InvockStore(database);
  try { await authorizeAndFail(first, "key replacement fixture"); const keyDirectory = first.keyDirectory; first.close(); assert.throws(() => new InvockStore(database, { keyDirectory, signing: generateSigningMaterial() }), /Receipt chain verification failed/); }
  finally { try { first.close(); } catch {} rmSync(root, { recursive: true, force: true }); }
});

console.log("chaos bounded cases: 11; unsupported disk-full/container-crash/interrupted-migration faults are documented, not counted as passes");
