import assert from "node:assert/strict";
import test from "node:test";
import { OpenAIInvockAdapter } from "../../src/integrations/openai.js";
import { SecondaryInvockAdapter } from "../../src/integrations/secondary.js";
import type { AuthorizeInput, DecisionResponse } from "../../src/sdk/index.js";

function fakeClient(seen: AuthorizeInput[], decision: DecisionResponse = { verdict: "BLOCK", reasonCodes: ["TEST"] }): { authorize(input: AuthorizeInput): Promise<DecisionResponse> } {
  return { authorize: async input => { seen.push(input); return decision; } };
}

test("OpenAI adapter maps only name and object arguments", async () => {
  const seen: AuthorizeInput[] = [];
  const result = await new OpenAIInvockAdapter(fakeClient(seen) as never).authorize({ name: "search", arguments: { query: "local" } }, { agent: "openai-agent" });
  assert.deepEqual(result, { verdict: "BLOCK", reasonCodes: ["TEST"] });
  assert.deepEqual(seen, [{ tool: "search", arguments: { query: "local" }, agent: "openai-agent" }]);
});

test("secondary adapter maps input to the common arguments field", async () => {
  const seen: AuthorizeInput[] = [];
  await new SecondaryInvockAdapter(fakeClient(seen) as never).authorize({ name: "write", input: { path: "safe.txt" } }, { intentCapsule: { id: "capsule-1" } });
  assert.deepEqual(seen, [{ tool: "write", arguments: { path: "safe.txt" }, intentCapsule: { id: "capsule-1" } }]);
});

test("OpenAI adapter never invokes the executor after a block and forwards only authorized arguments after allow", async () => {
  const seen: AuthorizeInput[] = [];
  let executions = 0;
  const blocked = await new OpenAIInvockAdapter(fakeClient(seen) as never).execute({ name: "write", arguments: { path: ".env" } }, () => { executions += 1; return "unexpected"; });
  assert.equal(blocked.executed, false);
  assert.equal(executions, 0);

  const allowed = await new OpenAIInvockAdapter(fakeClient(seen, { verdict: "ALLOW", reasonCodes: [], authorizedArguments: { path: "safe.txt" }, containmentRequired: false }) as never).execute({ name: "read", arguments: "{\"path\":\"safe.txt\"}" }, call => { executions += 1; return call.arguments.path; });
  assert.deepEqual(allowed, { decision: { verdict: "ALLOW", reasonCodes: [], authorizedArguments: { path: "safe.txt" }, containmentRequired: false }, executed: true, result: "safe.txt" });
  assert.equal(executions, 1);
});

test("OpenAI adapter rejects malformed JSON arguments before authorization", async () => {
  let called = false;
  const client = { authorize: async () => { called = true; return { verdict: "ALLOW" as const, reasonCodes: [] }; } };
  await assert.rejects(() => new OpenAIInvockAdapter(client as never).authorize({ name: "read", arguments: "not-json" }), /Unexpected token|JSON/u);
  assert.equal(called, false);
});

test("adapters fail closed when ALLOW omits canonical authorized arguments", async () => {
  const decision: DecisionResponse = { verdict: "ALLOW", reasonCodes: [], containmentRequired: false };
  let executions = 0;
  const openai = new OpenAIInvockAdapter(fakeClient([], decision) as never);
  const secondary = new SecondaryInvockAdapter(fakeClient([], decision) as never);

  await assert.rejects(
    () => openai.execute({ name: "read", arguments: { path: ".env" } }, () => { executions += 1; return "unsafe"; }),
    /INVOCK_ALLOW_MISSING_AUTHORIZED_ARGUMENTS/u,
  );
  await assert.rejects(
    () => secondary.execute({ name: "read", input: { path: ".env" } }, () => { executions += 1; return "unsafe"; }),
    /INVOCK_ALLOW_MISSING_AUTHORIZED_ARGUMENTS/u,
  );
  assert.equal(executions, 0);
});

test("adapters require an explicit containment opt-out before forwarding", async () => {
  let executions = 0;
  const authorizedArguments = { path: "safe.txt" };
  const missingStatus: DecisionResponse = { verdict: "ALLOW", reasonCodes: [], authorizedArguments };
  const requiredStatus: DecisionResponse = { verdict: "ALLOW", reasonCodes: [], authorizedArguments, containmentRequired: true };

  const missing = await new OpenAIInvockAdapter(fakeClient([], missingStatus) as never).execute({ name: "read", arguments: authorizedArguments }, () => { executions += 1; return "unsafe"; });
  assert.equal(missing.executed, false);
  assert.deepEqual(missing.decision.reasonCodes, ["CONTAINMENT_REQUIRED"]);

  const required = await new SecondaryInvockAdapter(fakeClient([], requiredStatus) as never).execute({ name: "read", input: authorizedArguments }, () => { executions += 1; return "unsafe"; });
  assert.equal(required.executed, false);
  assert.deepEqual(required.decision.reasonCodes, ["CONTAINMENT_REQUIRED"]);
  assert.equal(executions, 0);
});

test("contained adapter methods use the server execution contract and never receive a callback", async () => {
  const requests: AuthorizeInput[] = [];
  const execution = { verdict: "ALLOW" as const, reasonCodes: ["CONTAINED"], receiptId: "receipt-1", result: { content: [{ type: "text" as const, text: "safe" }] } };
  const client = { authorize: async (input: AuthorizeInput) => { requests.push(input); return { verdict: "BLOCK" as const, reasonCodes: ["UNUSED"] }; }, execute: async (input: AuthorizeInput) => { requests.push(input); return execution; } };
  const openai = await new OpenAIInvockAdapter(client as never).executeContained({ name: "read", arguments: { path: "safe.txt" } }, { agent: "openai-agent" });
  const secondary = await new SecondaryInvockAdapter(client as never).executeContained({ name: "read", input: { path: "safe.txt" } }, { agent: "secondary-agent" });
  assert.deepEqual(openai, execution);
  assert.deepEqual(secondary, execution);
  assert.deepEqual(requests, [
    { tool: "read", arguments: { path: "safe.txt" }, agent: "openai-agent" },
    { tool: "read", arguments: { path: "safe.txt" }, agent: "secondary-agent" },
  ]);
});
