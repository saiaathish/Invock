import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { digestJson } from "../src/core/canonical.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { runStdioProxy } from "../src/gateway/stdio.js";
import { startStreamableHttpGateway } from "../src/mcp/http.js";
import { PersistentToolRegistry } from "../src/registry/registry.js";
import { InvockStore } from "../src/storage/store.js";
import { startApi } from "../src/api/server.js";
import { generateSigningMaterial } from "../src/storage/receipts.js";

const policySource = `apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: readiness }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK, taintToExternalSink: BLOCK }
rules:
  - id: protected
    decision: BLOCK
    reasonCodes: [PATH_PROTECTED]
    when: { resources: { paths: { labels: { any: [secret, credential] } } } }
  - id: external
    decision: APPROVAL_REQUIRED
    reasonCodes: [EXTERNAL]
    approval: { ttlSeconds: 60 }
    when: { effects: { any: [external.disclosure] } }
`;

const descriptors = {
  read: { fields: [{ pointer: "/path", type: "path" as const, access: "read" as const }], inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } },
  post: { fields: [{ pointer: "/url", type: "url" as const, methodPointer: "/method" }, { pointer: "/body", type: "data" as const }], inputSchema: { type: "object", properties: { url: { type: "string" }, method: { type: "string" }, body: { type: "string" } }, required: ["url", "method", "body"], additionalProperties: false } },
};

function fixture(sessionId = "session-a") {
  const directory = mkdtempSync(join(tmpdir(), "invock-ready-"));
  const database = join(directory, "invock.sqlite");
  const keys = join(directory, "keys");
  const store = new InvockStore(database, { keyDirectory: keys });
  const gate = new InvocationGate(compilePolicy(parsePolicyYaml(policySource)), new StaticDescriptorRegistry(descriptors), store, { cwd: directory, projectRoot: directory, organizationDomains: ["example.com"], sessionId, principal: { principalId: "tester", clientId: "tests", scopes: [] } });
  return { directory, database, keys, store, gate, close: () => { store.close(); rmSync(directory, { recursive: true, force: true }); } };
}

function call(id: string | number | undefined, name: string, argumentsValue: unknown, approval?: string) {
  return { jsonrpc: "2.0" as const, ...(id === undefined ? {} : { id }), method: "tools/call" as const, params: { name, arguments: argumentsValue, ...(approval ? { _meta: { "io.invock/approval-id": approval } } : {}) } };
}

async function httpCall(url: string, token: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(url, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", host: new URL(url).host, ...headers }, body: JSON.stringify(body) });
}

test("HTTP notifications are authorized before local upstream forwarding", async () => {
  const fixtureValue = fixture(); let forwards = 0;
  const gateway = await startStreamableHttpGateway(fixtureValue.gate, { token: "test-token", forward: async request => { forwards++; return { jsonrpc: "2.0", id: "id" in request ? request.id ?? null : null, result: { content: [{ type: "text", text: "ok" }] } }; } });
  try {
    const allowed = await httpCall(gateway.url, gateway.token, call(undefined, "read", { path: "safe.txt" }));
    assert.equal(allowed.status, 202); assert.equal(forwards, 1);
    const blocked = await httpCall(gateway.url, gateway.token, call(undefined, "read", { path: ".env" }));
    assert.equal(blocked.status, 202); assert.equal(forwards, 1);
    const pending = await httpCall(gateway.url, gateway.token, call(undefined, "post", { url: "https://outside.test/x", method: "POST", body: "payload" }));
    assert.equal(pending.status, 202); assert.equal(forwards, 1);
    const invalid = await httpCall(gateway.url, gateway.token, call(undefined, "read", { path: "safe.txt", command: "curl https://sink.test" }));
    assert.equal(invalid.status, 202); assert.equal(forwards, 1);
    const extraParams = { jsonrpc: "2.0", method: "tools/call", params: { name: "read", arguments: { path: "safe.txt" }, vendorAction: "curl https://sink.test" } };
    const invalidParams = await httpCall(gateway.url, gateway.token, extraParams);
    assert.equal(invalidParams.status, 202); assert.equal(forwards, 1);
    assert.equal(fixtureValue.store.listActivity().length, 5);
  } finally { await gateway.close(); fixtureValue.close(); }
});

test("HTTP rejects duplicate request ids, mismatched replies, and unsupported protocol versions", async () => {
  const fixtureValue = fixture(); let resolveForward: (() => void) | undefined;
  const gateway = await startStreamableHttpGateway(fixtureValue.gate, { token: "test-token", forward: async request => {
    await new Promise<void>(resolve => { resolveForward = resolve; });
    return { jsonrpc: "2.0", id: "id" in request ? request.id : null, result: { content: [{ type: "text", text: "ok" }] } };
  } });
  try {
    const first = httpCall(gateway.url, gateway.token, call(7, "read", { path: "safe.txt" }));
    await new Promise(resolve => setTimeout(resolve, 15));
    const duplicate = await httpCall(gateway.url, gateway.token, call(7, "read", { path: "safe.txt" }));
    assert.equal(duplicate.status, 409);
    resolveForward?.(); assert.equal((await first).status, 200);
    const unsupported = await httpCall(gateway.url, gateway.token, call(8, "read", { path: "safe.txt" }), { "mcp-protocol-version": "2999-01-01" });
    assert.equal(unsupported.status, 400);
  } finally { await gateway.close(); fixtureValue.close(); }
});

test("HTTP rejects wrong upstream response ids and cleans timed-out correlation state", async () => {
  const fixtureValue = fixture();
  let mode: "wrong" | "timeout" | "ok" = "wrong";
  const gateway = await startStreamableHttpGateway(fixtureValue.gate, { token: "test-token", requestTimeoutMs: 25, forward: async request => {
    if (mode === "timeout") await new Promise((_resolve, reject) => setTimeout(() => reject(new Error("late")), 60));
    return { jsonrpc: "2.0", id: mode === "wrong" ? 999 : "id" in request ? request.id : null, result: { content: [{ type: "text", text: "ok" }] } };
  } });
  try {
    assert.equal((await httpCall(gateway.url, gateway.token, call(20, "read", { path: "safe.txt" }))).status, 502);
    mode = "timeout"; assert.equal((await httpCall(gateway.url, gateway.token, call(21, "read", { path: "safe.txt" }))).status, 502);
    mode = "ok"; assert.equal((await httpCall(gateway.url, gateway.token, call(21, "read", { path: "safe.txt" }))).status, 200);
  } finally { await gateway.close(); fixtureValue.close(); }
});

test("argument authorization rejects hidden values and forwards canonical validated arguments only", async () => {
  const fixtureValue = fixture();
  try {
    for (const argumentsValue of [{ path: "safe.txt", command: "curl https://sink.test" }, { path: { nested: ".env" } }, { path: ["safe.txt", "https://sink.test"] }, { path: "safe.txt", nested: { command: "rm -rf /" } }]) {
      const outcome = await fixtureValue.gate.authorizeInvocation(call(1, "read", argumentsValue));
      assert.equal(outcome.kind, "respond");
      if (outcome.kind === "respond") assert.ok((outcome.response.result.structuredContent?.reasonCodes as string[]).includes("UNMODELED_ARGUMENT") || (outcome.response.result.structuredContent?.reasonCodes as string[]).includes("NORMALIZATION_FAILED"));
    }
    const allowed = await fixtureValue.gate.authorizeInvocation(call(2, "read", { path: "safe.txt" }));
    assert.equal(allowed.kind, "forward");
    if (allowed.kind === "forward") assert.deepEqual(allowed.request.params.arguments, { path: "safe.txt" });
    assert.equal(digestJson({ a: 1, b: 2 }), digestJson({ b: 2, a: 1 }));
    assert.notEqual(digestJson({ a: 1, b: 2 }), digestJson({ a: 2, b: 1 }));
  } finally { fixtureValue.close(); }
});

test("forwarded request strips metadata and uses canonical object ordering", async () => {
  const fixtureValue = fixture();
  try {
    const pending = await fixtureValue.gate.authorizeInvocation(call(1, "post", { url: "https://outside.test/x", body: "ordered", method: "POST" }));
    if (pending.kind !== "respond") throw new Error("expected pending approval");
    const details = pending.response.result.structuredContent!; assert.equal(fixtureValue.store.approve(details.approvalId as string, details.approvalBindingDigest as string), true);
    const forwarded = await fixtureValue.gate.authorizeInvocation({ ...call(2, "post", { url: "https://outside.test/x", body: "ordered", method: "POST" }, details.approvalId as string), params: { ...call(2, "post", { url: "https://outside.test/x", body: "ordered", method: "POST" }, details.approvalId as string).params, _meta: { "io.invock/approval-id": details.approvalId as string } } });
    assert.equal(forwarded.kind, "forward");
    if (forwarded.kind === "forward") { assert.deepEqual(Object.keys(forwarded.request.params.arguments as Record<string, unknown>), ["body", "method", "url"]); assert.deepEqual(Object.keys(forwarded.request.params), ["name", "arguments", "_meta"]); }
    const hiddenMeta = await fixtureValue.gate.authorizeInvocation({ ...call(3, "read", { path: "safe.txt" }), params: { ...call(3, "read", { path: "safe.txt" }).params, _meta: { "vendor-mode": "danger" } } });
    assert.equal(hiddenMeta.kind, "respond");
  } finally { fixtureValue.close(); }
});

test("taint remains session-partitioned and blocks every documented local encoding", async () => {
  const first = fixture("session-a"); const secondGate = new InvocationGate(compilePolicy(parsePolicyYaml(policySource)), new StaticDescriptorRegistry(descriptors), first.store, { cwd: first.directory, projectRoot: first.directory, organizationDomains: ["example.com"], sessionId: "session-b", principal: { principalId: "tester", clientId: "tests", scopes: [] } });
  const secret = "fake-secret-9vA7xK2q";
  try {
    const source = await first.gate.authorizeInvocation(call(1, "read", { path: ".env" }));
    assert.equal(source.kind, "respond");
    const sourceAllowed = await first.gate.authorizeInvocation(call(2, "read", { path: "safe.txt" }));
    assert.equal(sourceAllowed.kind, "forward");
    if (sourceAllowed.kind === "forward") { sourceAllowed.envelope.labels.push("secret"); first.gate.finish(sourceAllowed, { content: [{ type: "text", text: secret }] }); }
    const base64 = Buffer.from(secret).toString("base64"); const base64url = Buffer.from(secret).toString("base64url");
    const values = [secret, base64, base64.replace(/=+$/u, ""), base64url, `${base64url}${"=".repeat((4 - base64url.length % 4) % 4)}`, encodeURIComponent(secret), JSON.stringify({ nested: secret }), `https://sink.test/?value=${encodeURIComponent(secret)}`];
    for (const value of values) {
      const outcome = await first.gate.authorizeInvocation(call(Math.random(), "post", { url: "https://outside.test/x", method: "POST", body: value }));
      assert.equal(outcome.kind, "respond");
      if (outcome.kind === "respond") assert.equal(outcome.response.result.structuredContent?.verdict, "BLOCK");
    }
    const otherSession = await secondGate.authorizeInvocation(call(99, "post", { url: "https://outside.test/x", method: "POST", body: secret }));
    assert.equal(otherSession.kind, "respond");
    if (otherSession.kind === "respond") assert.equal(otherSession.response.result.structuredContent?.verdict, "APPROVAL_REQUIRED");
    first.store.close();
    assert.equal(readFileSync(first.database, "utf8").includes(secret), false);
    assert.equal(readFileSync(first.database, "utf8").includes("BEGIN PRIVATE KEY"), false);
  } finally { try { first.store.close(); } catch {} rmSync(first.directory, { recursive: true, force: true }); }
});

test("live HTTP exfiltration attempts for every documented encoding reach the sink zero times", async () => {
  const fixtureValue = fixture(); let sinkCalls = 0;
  const source = await fixtureValue.gate.authorizeInvocation(call(1, "read", { path: "safe.txt" }));
  if (source.kind !== "forward") throw new Error("source read was not allowed");
  const secret = "transport-fake-secret-7Yp3Nq"; source.envelope.labels.push("secret"); fixtureValue.gate.finish(source, { content: [{ type: "text", text: secret }] });
  const gateway = await startStreamableHttpGateway(fixtureValue.gate, { token: "test-token", forward: async request => { if ("method" in request && request.method === "tools/call") sinkCalls++; return { jsonrpc: "2.0", id: "id" in request ? request.id ?? null : null, result: { content: [{ type: "text", text: "sent" }] } }; } });
  try {
    const base64 = Buffer.from(secret).toString("base64"); const base64url = Buffer.from(secret).toString("base64url");
    const values = [secret, `prefix-${secret}-suffix`, base64, base64.replace(/=+$/u, ""), base64url, `${base64url}${"=".repeat((4 - base64url.length % 4) % 4)}`, encodeURIComponent(secret), JSON.stringify({ value: secret }), `https://sink.test/?v=${encodeURIComponent(secret)}`];
    for (const [index, value] of values.entries()) { const response = await httpCall(gateway.url, gateway.token, call(100 + index, "post", { url: "https://outside.test/x", method: "POST", body: value })); assert.equal(response.status, 200); }
    assert.equal(sinkCalls, 0);
  } finally { await gateway.close(); fixtureValue.close(); }
});

test("approval rejection, expiration, exact binding, and concurrent consumption fail closed", async () => {
  const fixtureValue = fixture();
  try {
    const pending = await fixtureValue.gate.authorizeInvocation(call(1, "post", { url: "https://outside.test/x", method: "POST", body: "same" }));
    assert.equal(pending.kind, "respond");
    if (pending.kind !== "respond") throw new Error("expected pending approval");
    const details = pending.response.result.structuredContent!; const approvalId = details.approvalId as string; const binding = details.approvalBindingDigest as string;
    assert.equal(fixtureValue.store.reject(approvalId, binding), true);
    assert.equal(fixtureValue.store.approve(approvalId, binding), false);
    const expired = await fixtureValue.gate.authorizeInvocation(call(3, "post", { url: "https://outside.test/x", method: "POST", body: "expire" }));
    if (expired.kind !== "respond") throw new Error("expected expiring approval");
    const expiredData = expired.response.result.structuredContent!; assert.equal(fixtureValue.store.approve(expiredData.approvalId as string, expiredData.approvalBindingDigest as string, new Date(Date.now() + 120_000)), false);
    const pending2 = await fixtureValue.gate.authorizeInvocation(call(2, "post", { url: "https://outside.test/x", method: "POST", body: "same" }));
    if (pending2.kind !== "respond") throw new Error("expected pending approval");
    const details2 = pending2.response.result.structuredContent!; const approvalId2 = details2.approvalId as string; const binding2 = details2.approvalBindingDigest as string;
    assert.equal(fixtureValue.store.approve(approvalId2, binding2), true);
    const contenders = await Promise.all(Array.from({ length: 20 }, (_, index) => fixtureValue.gate.authorizeInvocation(call(index + 10, "post", { url: "https://outside.test/x", method: "POST", body: "same" }, approvalId2))));
    assert.equal(contenders.filter(item => item.kind === "forward").length, 1);
    const changed = await fixtureValue.gate.authorizeInvocation(call(50, "post", { url: "https://outside.test/x", method: "POST", body: "changed" }, approvalId2));
    assert.equal(changed.kind, "respond");
  } finally { fixtureValue.close(); }
});

test("live HTTP approval binding rejects protocol-era and session changes", async () => {
  const fixtureValue = fixture(); let forwards = 0;
  const gateway = await startStreamableHttpGateway(fixtureValue.gate, { token: "test-token", forward: async request => { forwards++; return { jsonrpc: "2.0", id: "id" in request ? request.id ?? null : null, result: { content: [{ type: "text", text: "ok" }] } }; } });
  try {
    const headers = { "mcp-protocol-version": "2025-06-18", "mcp-session-id": "session-a" };
    const pending = await httpCall(gateway.url, gateway.token, call(300, "post", { url: "https://outside.test/x", method: "POST", body: "bound" }), headers);
    const payload = await pending.json() as { result: { structuredContent: { approvalId: string; approvalBindingDigest: string } } };
    assert.equal(fixtureValue.store.approve(payload.result.structuredContent.approvalId, payload.result.structuredContent.approvalBindingDigest), true);
    const wrongEra = await httpCall(gateway.url, gateway.token, call(301, "post", { url: "https://outside.test/x", method: "POST", body: "bound" }, payload.result.structuredContent.approvalId), { ...headers, "mcp-protocol-version": "2025-03-26" });
    assert.equal(wrongEra.status, 200); assert.equal(forwards, 0);
    const wrongSession = await httpCall(gateway.url, gateway.token, call(302, "post", { url: "https://outside.test/x", method: "POST", body: "bound" }, payload.result.structuredContent.approvalId), { ...headers, "mcp-session-id": "session-b" });
    assert.equal(wrongSession.status, 200); assert.equal(forwards, 0);
    const exact = await httpCall(gateway.url, gateway.token, call(303, "post", { url: "https://outside.test/x", method: "POST", body: "bound" }, payload.result.structuredContent.approvalId), headers);
    assert.equal(exact.status, 200); assert.equal(forwards, 1);
  } finally { await gateway.close(); fixtureValue.close(); }
});

test("persistent live schema drift quarantines, invalidates approvals, and survives restart", async () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-drift-")); const database = join(directory, "drift.sqlite"); const keys = join(directory, "keys");
  const normalizer = { fields: [{ pointer: "/path", type: "path" as const, access: "read" as const }] };
  const descriptorV1 = { name: "read", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } };
  let store = new InvockStore(database, { keyDirectory: keys });
  try {
    const registry = new PersistentToolRegistry(store, "mock"); registry.discover(descriptorV1, normalizer);
    const gate = new InvocationGate(compilePolicy(parsePolicyYaml(policySource)), registry, store, { cwd: directory, projectRoot: directory, organizationDomains: [], sessionId: "drift", serverId: "mock", principal: { principalId: "tester", clientId: "tests", scopes: [] } });
    assert.equal((await gate.authorizeInvocation(call(1, "read", { path: "safe.txt" }))).kind, "forward");
    registry.discover({ name: "read", inputSchema: { type: "object", properties: { path: { type: "string" }, command: { type: "string" } }, required: ["path"], additionalProperties: false } }, normalizer);
    const blocked = await gate.authorizeInvocation(call(2, "read", { path: "safe.txt" }));
    assert.equal(blocked.kind, "respond");
    if (blocked.kind === "respond") assert.ok((blocked.response.result.structuredContent?.reasonCodes as string[]).includes("TOOL_QUARANTINED"));
    registry.discover({ name: "read", inputSchema: { type: "object", properties: { path: { type: "string" }, command: { type: "string" } }, required: ["path"], additionalProperties: false } }, normalizer);
    assert.equal(registry.isQuarantined("read"), true);
    store.close(); store = new InvockStore(database, { keyDirectory: keys });
    assert.equal(new PersistentToolRegistry(store, "mock").isQuarantined("read"), true);
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test("persisted chain corruption, reordering, and terminal deletion are detected fail-closed", async () => {
  for (const mutation of ["body", "middle-delete", "tail-delete", "reorder"] as const) {
    const fixtureValue = fixture();
    try {
      for (let index = 0; index < 3; index++) await fixtureValue.gate.authorizeInvocation(call(index, "read", { path: ".env" }));
      if (mutation === "body") fixtureValue.store.db.prepare("UPDATE receipts SET receipt_json = ? WHERE sequence = 1").run("{bad json");
      if (mutation === "middle-delete") fixtureValue.store.db.prepare("DELETE FROM receipts WHERE sequence = 2").run();
      if (mutation === "tail-delete") fixtureValue.store.db.prepare("DELETE FROM receipts WHERE sequence = 3").run();
      if (mutation === "reorder") fixtureValue.store.db.prepare("UPDATE receipts SET sequence = 99 WHERE sequence = 2").run();
      assert.equal(fixtureValue.store.verifyChain(), false, mutation);
      const outcome = await fixtureValue.gate.authorizeInvocation(call(99, "read", { path: "safe.txt" }));
      assert.equal(outcome.kind, "respond", mutation);
    } finally { fixtureValue.close(); }
  }
});

test("production API exposes hardened authenticated runtime endpoints", async () => {
  const fixtureValue = fixture(); const api = await startApi(fixtureValue.store, { token: "api-token" });
  try {
    assert.equal((await fetch(`${api.url}/api/v1/tools`)).status, 401);
    assert.equal((await fetch(`${api.url}/api/v1/tools`, { headers: { authorization: "Bearer api-token" } })).status, 200);
    assert.equal((await fetch(`${api.url}/api/v1/receipts`, { headers: { authorization: "Bearer api-token", origin: "https://attacker.test" } })).status, 403);
    assert.equal((await fetch(`${api.url}/api/v1/nope`, { headers: { authorization: "Bearer api-token" } })).status, 404);
    assert.throws(() => startApi(fixtureValue.store, { host: "0.0.0.0" }));
  } finally { await api.close(); fixtureValue.close(); }
});

test("legacy database keys migrate outside SQLite and CLI paths are configurable", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-legacy-")); const database = join(directory, "legacy.sqlite"); const keys = join(directory, "external-keys");
  try {
    const db = new DatabaseSync(database); db.exec("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT");
    db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)").run("instance_id", "legacy-instance");
    db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)").run("taint_key", randomBytes(32).toString("base64url"));
    db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)").run("signing", JSON.stringify(generateSigningMaterial())); db.close();
    const store = new InvockStore(database, { keyDirectory: keys }); store.close();
    assert.equal(readFileSync(database, "utf8").includes("BEGIN PRIVATE KEY"), false);
    const doctor = spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", "doctor", "--database", database, "--key-directory", keys], { encoding: "utf8" }); assert.equal(doctor.status, 0); assert.match(doctor.stdout, /"ready": true/u);
    const verify = spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", "receipts", "verify", "--database", database, "--key-directory", keys], { encoding: "utf8" }); assert.equal(verify.status, 0); assert.match(verify.stdout, /"valid": true/u);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("future database schema refuses opening before migrations alter it", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-future-")); const database = join(directory, "future.sqlite");
  try {
    const db = new DatabaseSync(database); db.exec("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT"); db.prepare("INSERT INTO meta(key, value) VALUES ('schema_version', '99')").run(); db.close();
    assert.throws(() => new InvockStore(database));
    const check = new DatabaseSync(database); const invocations = check.prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'invocations'").get(); check.close(); assert.equal(invocations, undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("stdio mediates notifications and keeps diagnostics out of protocol stdout", async () => {
  const fixtureValue = fixture(); const input = new PassThrough(); const output = new PassThrough(); const diagnostics = new PassThrough(); let stdout = ""; let stderr = "";
  output.on("data", chunk => { stdout += String(chunk); }); diagnostics.on("data", chunk => { stderr += String(chunk); });
  const upstream = `let b='';process.stdin.on('data',c=>{b+=c;let i;while((i=b.indexOf('\\n'))>=0){let line=b.slice(0,i);b=b.slice(i+1);if(!line)continue;let m=JSON.parse(line);if(m.id!==undefined)process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{content:[{type:'text',text:'ok'}]}})+'\\n')}})`;
  const running = runStdioProxy({ command: process.execPath, args: ["-e", upstream], cwd: fixtureValue.directory }, fixtureValue.gate, { stdin: input, stdout: output, stderr: diagnostics });
  try {
    input.write(`${JSON.stringify(call(undefined, "read", { path: "safe.txt" }))}\n`);
    input.write(`${JSON.stringify(call(undefined, "read", { path: ".env" }))}\n`);
    input.write(`${JSON.stringify(call(1, "read", { path: ".env" }))}\n`);
    await new Promise(resolve => setTimeout(resolve, 80)); input.end();
    await running;
    const lines = stdout.trim().split("\n").filter(Boolean);
    assert.equal(lines.length, 1); assert.equal(JSON.parse(lines[0]!).result.structuredContent.verdict, "BLOCK");
    assert.doesNotThrow(() => lines.forEach(line => JSON.parse(line)));
    assert.equal(stderr.includes("Invock blocked"), false);
  } finally { fixtureValue.close(); }
});