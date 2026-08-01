import test from "node:test";
import assert from "node:assert/strict";
import { activateDraft, diffPolicies, forgePolicy, type HumanApproval } from "../../src/forge/index.js";

const observations = [
  { tool: "read_file", capabilities: ["fs.read"], effects: ["data.observe"], paths: ["/workspace/a"] },
  { tool: "read_file", capabilities: ["fs.read"], effects: ["data.observe"], paths: ["/workspace/a"] },
] as const;

test("forgePolicy produces a deterministic least-privilege draft", () => {
  const first = forgePolicy([...observations].reverse());
  const second = forgePolicy(observations);
  assert.deepEqual(first, second);
  assert.deepEqual(first.tools, ["read_file"]);
  assert.deepEqual(first.capabilities, ["fs.read"]);
  assert.deepEqual(first.resources.paths, ["/workspace/a"]);
  assert.equal(first.status, "DRAFT");
});

test("diffPolicies identifies authority expansion and reduction", () => {
  const from = forgePolicy(observations);
  const to = forgePolicy([...observations, { tool: "write_file", capabilities: ["fs.write"], effects: ["data.modify"] }]);
  const diff = diffPolicies(from, to);
  assert.deepEqual(diff.additions.tools, ["write_file"]);
  assert.deepEqual(diff.additions.capabilities, ["fs.write"]);
  assert.equal(diff.privilegeExpansion, true);
  assert.deepEqual(diffPolicies(to, from).removals.tools, ["write_file"]);
});

test("activateDraft requires explicit attributable human approval", () => {
  const draft = forgePolicy(observations);
  assert.throws(() => activateDraft(draft, undefined as never), /human approval/);
  const approval: HumanApproval = { approvedBy: "alice", approvalId: "approval-1", approvedAt: "2026-07-31T12:00:00.000Z", statement: "I approve this policy draft." };
  const active = activateDraft(draft, approval);
  assert.equal(active.status, "ACTIVE");
  assert.equal(active.approvalId, "approval-1");
});
