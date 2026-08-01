import assert from "node:assert/strict";
import test from "node:test";
import { buildReportViewModel, redactActivity, type ActivityRecord } from "../../src/ui/report.js";

const record: ActivityRecord = {
  invocationId: "inv-1", toolName: "read", verdict: "ALLOW", status: "forwarded", createdAt: "2026-07-31T00:00:00.000Z", receiptId: "receipt-1",
  arguments: { path: ".env", token: "do-not-display" }, payload: "Bearer do-not-display", arbitrarySecret: "do-not-display",
};

test("redacted view exposes only safe report fields", () => {
  const view = redactActivity([record]);
  assert.deepEqual(view, [{ invocationId: "inv-1", toolName: "read", verdict: "ALLOW", status: "forwarded", createdAt: "2026-07-31T00:00:00.000Z", receiptId: "receipt-1" }]);
  assert.equal(JSON.stringify(view).includes("do-not-display"), false);
});

test("report output is deterministic and counts redacted items", () => {
  const second: ActivityRecord = { ...record, invocationId: "inv-2" };
  const report = buildReportViewModel([record, second]);
  assert.equal(report.total, 2);
  assert.deepEqual(report, buildReportViewModel([record, second]));
});
