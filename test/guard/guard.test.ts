import test from "node:test";
import assert from "node:assert/strict";
import { inspectPolicyDiff, inspectWorkflow } from "../../src/guard/index.js";
import { forgePolicy, diffPolicies } from "../../src/forge/index.js";

test("inspectWorkflow detects unsafe permissions and privileged trigger", () => {
  const findings = inspectWorkflow(`name: ci\non:\n  pull_request_target:\npermissions: write-all\njobs:\n  build:\n    permissions:\n      contents: write\n`);
  assert.ok(findings.some(finding => finding.code === "UNSAFE_WORKFLOW_PERMISSION"));
  assert.ok(findings.some(finding => finding.code === "UNSAFE_TRIGGER"));
  assert.ok(findings.every(finding => finding.severity === "BLOCK"));
});

test("inspectWorkflow is clean for a read-only pinned workflow", () => {
  const findings = inspectWorkflow("name: ci\non: [push]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@abc123\n");
  assert.deepEqual(findings, []);
});

test("policy privilege expansion is guarded", () => {
  const from = forgePolicy([{ tool: "read", capabilities: ["fs.read"] }]);
  const to = forgePolicy([{ tool: "read", capabilities: ["fs.read", "fs.write"] }]);
  const findings = inspectPolicyDiff(diffPolicies(from, to));
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.code, "PRIVILEGE_EXPANSION");
});
