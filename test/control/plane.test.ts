import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { LocalControlPlane } from "../../src/control/plane.js";

test("control-plane state persists, reloads, and keeps project ownership explicit", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-control-test-"));
  try {
    const path = join(directory, "control.json");
    const first = new LocalControlPlane(path);
    first.upsertOrganization({ id: "org-a", displayName: "Org A" });
    first.upsertOrganization({ id: "org-b", displayName: "Org B" });
    first.upsertProject({ id: "project-a", organizationId: "org-a", displayName: "Project A" });
    first.upsertProject({ id: "project-b", organizationId: "org-b", displayName: "Project B" });
    first.registerAgent({ id: "agent-a", projectId: "project-a", displayName: "Agent A", trustState: "ENROLLED" });
    first.registerAgent({ id: "agent-b", projectId: "project-b", displayName: "Agent B", trustState: "UNVERIFIED" });
    first.recordAlert({ projectId: "project-a", severity: "warning", message: "Review required" });
    assert.deepEqual(new LocalControlPlane(path).exportSnapshot(), first.exportSnapshot());
    assert.equal(JSON.parse(readFileSync(path, "utf8")).agents[0].projectId, "project-a");
    const tampered = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    tampered.organizations = [{ id: "org-a", displayName: "Attacker-controlled" }, { id: "org-b", displayName: "Org B" }];
    writeFileSync(path, JSON.stringify(tampered));
    assert.throws(() => new LocalControlPlane(path), /integrity verification failed/);
    assert.throws(() => first.registerAgent({ id: "agent-a", projectId: "project-b", displayName: "Agent A", trustState: "ENROLLED" }), /cannot move projects/);
    assert.throws(() => first.recordAlert({ projectId: "missing", severity: "critical", message: "no" }), /unknown project/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("control-plane rejects invalid state instead of silently widening it", () => {
  const directory = mkdtempSync(join(tmpdir(), "invock-control-invalid-"));
  try {
    const path = join(directory, "control.json");
    const control = new LocalControlPlane(path);
    control.upsertOrganization({ id: "org", displayName: "Org" });
    assert.throws(() => control.upsertProject({ id: "project", organizationId: "missing", displayName: "Project" }), /unknown organization/);
    assert.throws(() => new LocalControlPlane(directory), /signing key is missing/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
