import assert from "node:assert/strict";
import test from "node:test";
import { negotiateProfile } from "../../src/protocol/profile.js";

test("negotiates the explicitly requested implemented profile", () => {
  const result = negotiateProfile({ clientVersions: ["2026-07-28"], requestedVersion: "2026-07-28" });
  assert.equal(result.ok, true);
  assert.equal(result.profile?.version, "2026-07-28");
  assert.equal(result.profile?.stateModel, "request");
});

test("rejects unknown versions without fallback", () => {
  const result = negotiateProfile({ clientVersions: ["2099-01-01"] });
  assert.deepEqual(result, { ok: false, reason: "UNKNOWN_VERSION", supportedVersions: ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"] });
});

test("rejects ambiguous downgrade instead of guessing", () => {
  const result = negotiateProfile({ clientVersions: ["2025-11-25", "2025-06-18"], serverVersions: ["2025-11-25", "2025-06-18"] });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "AMBIGUOUS_DOWNGRADE");
});

test("negotiation output is deterministic", () => {
  const request = { clientVersions: ["2025-03-26"], serverVersions: ["2025-03-26", "2025-06-18"] } as const;
  assert.deepEqual(negotiateProfile(request), negotiateProfile(request));
});
