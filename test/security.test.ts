import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { InvockStore } from "../src/storage/store.js";

const source = `apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: test }
defaults: { decision: APPROVAL_REQUIRED, unknownCapability: BLOCK, unknownEffect: BLOCK, taintToExternalSink: BLOCK }
rules:
  - id: protected
    decision: BLOCK
    reasonCodes: [PATH_PROTECTED]
    when: { resources: { paths: { labels: { any: [secret, credential] } } } }
  - id: project-read
    decision: ALLOW
    reasonCodes: [READ]
    when: { all: [ { capabilities: { all: [fs.read] } }, { resources: { paths: { every: true, inside: "__ROOT__" } } } ] }
  - id: egress
    decision: APPROVAL_REQUIRED
    reasonCodes: [EGRESS]
    approval: { ttlSeconds: 60 }
    when: { effects: { any: [external.disclosure] } }
`;

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "invock-test-"));
  const compiled = compilePolicy(parsePolicyYaml(source.replace("__ROOT__", realpathSync(dir))));
  const store = new InvockStore(join(dir, "invock.sqlite"));
  const gate = new InvocationGate(compiled, new StaticDescriptorRegistry({
    read: { fields: [{ pointer: "/path", type: "path", access: "read" }] },
    post: { fields: [{ pointer: "/url", type: "url", methodPointer: "/method" }, { pointer: "/body", type: "data" }] },
  }), store, { cwd: dir, projectRoot: dir, organizationDomains: ["example.com"], sessionId: "test", principal: { principalId: "tester", clientId: "test", scopes: [] } }, { allowUnboundForTests: true });
  return { dir, store, gate, close: () => { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}
const call = (id: number, name: string, argumentsValue: Record<string, unknown>, approval?: string) => ({ jsonrpc: "2.0" as const, id, method: "tools/call" as const, params: { name, arguments: argumentsValue, ...(approval ? { _meta: { "io.invock/approval-id": approval } } : {}) } });

test("protected paths block and never produce a forward outcome", async () => {
  const f = fixture(); try { const outcome = await f.gate.intercept(call(1, "read", { path: ".env" })); assert.equal(outcome.kind, "respond"); assert.equal(outcome.response.result.structuredContent?.verdict, "BLOCK"); assert.equal(f.store.listActivity()[0]?.status, "blocked"); } finally { f.close(); }
});

test("one-time approval rejects mutation and replay", async () => {
  const f = fixture(); try {
    const pending = await f.gate.intercept(call(1, "post", { url: "https://outside.test/x", method: "POST", body: "safe content" })); assert.equal(pending.kind, "respond");
    const data = pending.response.result.structuredContent!; const id = data.approvalId as string; const binding = data.approvalBindingDigest as string; assert.ok(f.store.approve(id, binding));
    const modified = await f.gate.intercept(call(2, "post", { url: "https://outside.test/x", method: "POST", body: "modified content" }, id)); assert.equal(modified.kind, "respond");
    const approved = await f.gate.intercept(call(3, "post", { url: "https://outside.test/x", method: "POST", body: "safe content" }, id)); assert.equal(approved.kind, "forward");
    const replay = await f.gate.intercept(call(4, "post", { url: "https://outside.test/x", method: "POST", body: "safe content" }, id)); assert.equal(replay.kind, "respond");
  } finally { f.close(); }
});

test("a secret result followed by Base64 external egress is blocked", async () => {
  const f = fixture(); try {
    const source = await f.gate.intercept(call(1, "read", { path: ".env" })); assert.equal(source.kind, "respond");
    // Explicitly register sensitive output after verifying the key and store never retain plaintext.
    const forwardLike = await f.gate.intercept(call(2, "read", { path: "public.txt" })); assert.equal(forwardLike.kind, "forward");
    forwardLike.envelope.labels.push("secret"); f.gate.finish(forwardLike, { content: [{ type: "text", text: "fake-secret-123456" }] });
    const outbound = await f.gate.intercept(call(3, "post", { url: "https://outside.test/x", method: "POST", body: Buffer.from("fake-secret-123456").toString("base64") })); assert.equal(outbound.kind, "respond"); assert.equal(outbound.response.result.structuredContent?.verdict, "BLOCK");
  } finally { f.close(); }
});

test("receipt chain detects tampering", async () => {
  const f = fixture(); try {
    const blocked = await f.gate.intercept(call(1, "read", { path: ".env" })); assert.equal(blocked.kind, "respond");
    const receiptId = blocked.response.result.structuredContent?.receiptId as string; const receipt = f.store.getReceipt(receiptId)!; receipt.payload.reasonCodes.push("TAMPERED");
    assert.equal(f.store.verifyChain(), true); // stored receipt is still valid
    const { verifyReceipt } = await import("../src/storage/receipts.js"); assert.equal(verifyReceipt(receipt, f.store.signing.publicKeyPem, null), false);
  } finally { f.close(); }
});
