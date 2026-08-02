import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { digestJson } from "../src/core/canonical.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { runStdioProxy } from "../src/gateway/stdio.js";
import { startStreamableHttpGateway } from "../src/mcp/http.js";
import { generateSigningMaterial } from "../src/storage/receipts.js";
import { InvockStore } from "../src/storage/store.js";
import { signContainmentRun } from "../src/containment/lifecycle.js";

const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: containment-contract }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK, taintToExternalSink: BLOCK }
rules:
  - id: allow-read
    decision: ALLOW
    reasonCodes: [READ]
    when: { capabilities: { any: [fs.read] } }
`));

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "invock-gateway-containment-"));
  const store = new InvockStore(join(directory, "receipts.sqlite"));
  const gate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), store, {
    cwd: directory,
    projectRoot: directory,
    organizationDomains: [],
    sessionId: "containment-session",
    principal: { principalId: "agent", clientId: "test", scopes: [] },
  }, { allowUnboundForTests: true, requireContainment: true });
  return { directory, store, gate };
}

function request(id: number) {
  return { jsonrpc: "2.0" as const, id, method: "tools/call" as const, params: { name: "read", arguments: { path: "safe.txt" } } };
}

function signedRun(outcome: Extract<Awaited<ReturnType<InvocationGate["authorizeInvocation"]>>, { kind: "forward" }>) {
  const profileDigest = digestJson({ sandbox: "required", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true });
  return signContainmentRun({
    schemaVersion: "invock/containment-run/v2",
    runId: `stdio-contained-${outcome.request.id ?? "notification"}`,
    createdAt: "2026-08-01T00:00:00.000Z",
    requestDigest: digestJson({ command: "contained-fixture", argv: [] }),
    authorizedRequestDigest: outcome.envelope.integrity.requestDigest,
    command: "contained-fixture",
    invocationId: outcome.envelope.invocationId,
    sessionId: outcome.envelope.sessionId,
    profileDigest,
    result: { status: "completed", stdout: "ok", stderr: "", durationMs: 1, reasonCodes: [], cleanup: "completed", capabilities: { sandbox: "available", network: "denied", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
  }, generateSigningMaterial());
}

test("strict stdio does not start an ordinary upstream without contained-forward", async () => {
  const value = fixture(); const input = new PassThrough(); const output = new PassThrough(); const diagnostics = new PassThrough();
  const marker = join(value.directory, "upstream-started"); let stdout = "";
  output.on("data", chunk => { stdout += String(chunk); });
  const running = runStdioProxy({ command: process.execPath, args: ["-e", `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "started")`], cwd: value.directory }, value.gate, { stdin: input, stdout: output, stderr: diagnostics });
  try {
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);
    input.write(`${JSON.stringify(request(2))}\n`);
    input.end(); await running;
    const messages = stdout.trim().split("\n").filter(Boolean).map(line => JSON.parse(line) as { id: number; error?: { code: number }; result?: { structuredContent?: { verdict?: string } } });
    assert.equal(messages.find(message => message.id === 1)?.error?.code, -32051);
    assert.equal(messages.find(message => message.id === 2)?.result?.structuredContent?.verdict, "BLOCK");
    assert.equal(existsSync(marker), false);
  } finally { value.store.close(); rmSync(value.directory, { recursive: true, force: true }); }
});

test("strict stdio attaches the contained proof before forwarding the handler response", async () => {
  const value = fixture(); const input = new PassThrough(); const output = new PassThrough(); const diagnostics = new PassThrough(); let stdout = ""; let calls = 0;
  output.on("data", chunk => { stdout += String(chunk); });
  const running = runStdioProxy({ command: process.execPath, args: ["-e", "throw new Error('ordinary child must not start')"], cwd: value.directory, containedForward: async outcome => {
    calls += 1;
    return { response: { jsonrpc: "2.0", id: outcome.request.id ?? null, result: { content: [{ type: "text", text: "contained-ok" }] } }, containment: signedRun(outcome) };
  } }, value.gate, { stdin: input, stdout: output, stderr: diagnostics });
  try {
    input.write(`${JSON.stringify(request(4))}\n`); input.end(); await running;
    const response = JSON.parse(stdout.trim()) as { result?: { content?: Array<{ text: string }>; _meta?: Record<string, string> } };
    assert.equal(calls, 1); assert.equal(response.result?.content?.[0]?.text, "contained-ok"); assert.equal(typeof response.result?._meta?.["io.invock/receipt-id"], "string");
    const receiptId = response.result?._meta?.["io.invock/receipt-id"];
    assert.equal(value.store.getReceipt(receiptId ?? "")?.payload.containmentRunId, "stdio-contained-4");
    assert.equal(value.store.verifyChain(), true);
  } finally { value.store.close(); rmSync(value.directory, { recursive: true, force: true }); }
});

test("strict gates refuse an uncontained forward before any upstream execution", async () => {
  const value = fixture();
  try {
    const outcome = await value.gate.authorizeInvocation(request(1));
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") return;
    assert.equal(outcome.containmentRequired, true);
    const rejected = value.gate.rejectForward(outcome);
    assert.equal(rejected.kind, "respond");
    if (rejected.kind !== "respond") return;
    assert.equal(rejected.response.result.structuredContent?.verdict, "BLOCK");
    const receiptId = rejected.response.result.structuredContent?.receiptId;
    assert.equal(typeof receiptId, "string");
    assert.equal(value.store.getReceipt(receiptId as string)?.payload.upstreamForwarded, false);
  } finally {
    value.store.close();
    rmSync(value.directory, { recursive: true, force: true });
  }
});

test("strict gates accept only a signed run bound to the exact invocation", async () => {
  const value = fixture();
  try {
    const outcome = await value.gate.authorizeInvocation(request(2));
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") return;
    const profileDigest = digestJson({ sandbox: "required", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true });
    const record = signContainmentRun({
      schemaVersion: "invock/containment-run/v2",
      runId: "strict-bound-run",
      createdAt: "2026-08-01T00:00:00.000Z",
      requestDigest: digestJson({ command: "probe.js", argv: [] }),
      authorizedRequestDigest: outcome.envelope.integrity.requestDigest,
      command: "probe.js",
      invocationId: outcome.envelope.invocationId,
      sessionId: outcome.envelope.sessionId,
      profileDigest,
      result: { status: "completed", stdout: "ok", stderr: "", durationMs: 1, reasonCodes: [], cleanup: "completed", capabilities: { sandbox: "available", network: "denied", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
    }, generateSigningMaterial());
    const attached = value.gate.attachContainmentRun(outcome, record);
    assert.equal(attached.containmentRequired, false);
    const receiptId = value.gate.finish(attached, { content: [{ type: "text", text: "ok" }] });
    const receipt = value.store.getReceipt(receiptId);
    assert.equal(receipt?.payload.containmentRunId, record.runId);
    assert.equal(receipt?.payload.containmentRequestDigest, record.requestDigest);
    assert.equal(receipt?.payload.containmentProfileDigest, profileDigest);
    assert.equal(value.store.verifyChain(), true);
  } finally {
    value.store.close();
    rmSync(value.directory, { recursive: true, force: true });
  }
});

test("strict gates reject a completed containment run whose cleanup failed", async () => {
  const value = fixture();
  try {
    const outcome = await value.gate.authorizeInvocation(request(7));
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") return;
    const profileDigest = digestJson({ sandbox: "required", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true });
    const record = signContainmentRun({
      schemaVersion: "invock/containment-run/v2",
      runId: "cleanup-failed-run",
      createdAt: "2026-08-01T00:00:00.000Z",
      requestDigest: digestJson({ command: "probe.js", argv: [] }),
      authorizedRequestDigest: outcome.envelope.integrity.requestDigest,
      command: "probe.js",
      invocationId: outcome.envelope.invocationId,
      sessionId: outcome.envelope.sessionId,
      profileDigest,
      result: { status: "completed", stdout: "ok", stderr: "cleanup failed", durationMs: 1, reasonCodes: ["CONTAINER_CLEANUP_FAILED"], cleanup: "failed", capabilities: { sandbox: "available", network: "denied", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
    }, generateSigningMaterial());
    assert.throws(() => value.gate.attachContainmentRun(outcome, record), /CONTAINMENT_RUN_BINDING_INVALID/u);
  } finally {
    value.store.close();
    rmSync(value.directory, { recursive: true, force: true });
  }
});

test("production containment trust rejects self-signed and capability-mismatched proofs", async () => {
  const value = fixture();
  try {
    const outcome = await value.gate.authorizeInvocation(request(6));
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") return;
    const signing = generateSigningMaterial();
    const profile = { sandbox: "required", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true };
    const approvedContainmentProfiles = [{ profileDigest: digestJson(profile), capabilities: { sandbox: "available" as const, network: "denied" as const, readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } }];
    const productionGate = new InvocationGate(policy, new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }] } }), value.store, {
      cwd: value.directory, projectRoot: value.directory, organizationDomains: [], sessionId: "containment-session", principal: { principalId: "agent", clientId: "test", scopes: [] },
    }, { trustedContainmentKeys: [{ keyId: signing.signingKeyId, publicKeyPem: signing.publicKeyPem }], approvedContainmentProfiles });
    const base = {
      schemaVersion: "invock/containment-run/v2" as const,
      runId: "trusted-containment-run",
      createdAt: "2026-08-01T00:00:00.000Z",
      requestDigest: digestJson({ command: "contained-fixture", argv: [] }),
      authorizedRequestDigest: outcome.envelope.integrity.requestDigest,
      command: "contained-fixture",
      invocationId: outcome.envelope.invocationId,
      sessionId: outcome.envelope.sessionId,
      profileDigest: digestJson(profile),
      result: { status: "completed" as const, stdout: "ok", stderr: "", durationMs: 1, reasonCodes: [], cleanup: "completed" as const, capabilities: { sandbox: "available" as const, network: "denied" as const, readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
    };
    assert.throws(() => productionGate.attachContainmentRun(outcome, signContainmentRun(base, generateSigningMaterial())), /CONTAINMENT_SIGNER_UNTRUSTED/u);
    assert.throws(() => productionGate.attachContainmentRun(outcome, signContainmentRun({ ...base, runId: "mismatched-capabilities", result: { ...base.result, capabilities: { ...base.result.capabilities, network: "unknown" } } }, signing)), /CONTAINMENT_CAPABILITIES_MISMATCH/u);
    const attached = productionGate.attachContainmentRun(outcome, signContainmentRun(base, signing));
    assert.equal(attached.containmentRequired, false);
  } finally {
    value.store.close();
    rmSync(value.directory, { recursive: true, force: true });
  }
});

test("strict gates reject a signed containment run bound to a different authorized request", async () => {
  const value = fixture();
  try {
    const outcome = await value.gate.authorizeInvocation(request(3));
    assert.equal(outcome.kind, "forward");
    if (outcome.kind !== "forward") return;
    const record = signContainmentRun({
      schemaVersion: "invock/containment-run/v2",
      runId: "wrong-request-run",
      createdAt: "2026-08-01T00:00:00.000Z",
      requestDigest: digestJson({ profile: "required", command: "probe.js", argv: [], envKeys: [] }),
      authorizedRequestDigest: digestJson({ jsonrpc: "2.0", id: 999, method: "tools/call", params: { name: "read", arguments: { path: "other.txt" } } }),
      command: "probe.js",
      invocationId: outcome.envelope.invocationId,
      sessionId: outcome.envelope.sessionId,
      profileDigest: digestJson({ sandbox: "required", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true }),
      result: { status: "completed", stdout: "ok", stderr: "", durationMs: 1, reasonCodes: [], cleanup: "completed", capabilities: { sandbox: "available", network: "denied", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
    }, generateSigningMaterial());
    assert.throws(() => value.gate.attachContainmentRun(outcome, record), /CONTAINMENT_RUN_BINDING_INVALID/u);
  } finally {
    value.store.close();
    rmSync(value.directory, { recursive: true, force: true });
  }
});

test("Streamable HTTP refuses a strict forward when no contained executor is configured", async () => {
  const value = fixture();
  let forwarded = 0;
  const gateway = await startStreamableHttpGateway(value.gate, {
    token: "containment-token",
    forward: async () => {
      forwarded += 1;
      return { jsonrpc: "2.0", id: 9, result: { content: [{ type: "text", text: "must-not-run" }] } };
    },
  });
  try {
    const response = await fetch(gateway.url, {
      method: "POST",
      headers: { authorization: "Bearer containment-token", "content-type": "application/json", host: new URL(gateway.url).host },
      body: JSON.stringify(request(9)),
    });
    assert.equal(response.status, 200);
    const payload = await response.json() as { result?: { structuredContent?: { verdict?: string } } };
    assert.equal(payload.result?.structuredContent?.verdict, "BLOCK");
    assert.equal(forwarded, 0);
  } finally {
    await gateway.close();
    value.store.close();
    rmSync(value.directory, { recursive: true, force: true });
  }
});
