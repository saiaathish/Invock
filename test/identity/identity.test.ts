import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { test } from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IdentityAuthority } from "../../src/identity/index.js";

const t0 = new Date("2026-01-01T00:00:00.000Z");
const input = { organizationId: "org_1", projectId: "project_1", displayName: "worker", runtimeType: "node" };

test("enrolls and verifies one canonical signed token", () => {
  const authority = new IdentityAuthority();
  const result = authority.enroll(input, t0);
  assert.equal(result.identity.trustState, "ENROLLED");
  assert.equal(authority.verifyEnrollment(result.token, t0), true);
  assert.throws(() => authority.verifyEnrollment(result.token, t0), /replayed/);
  assert.equal("privateKeyPem" in result.identity, false);
  assert.equal("privateKey" in result.token, false);
});

test("rejects token mutation, expiry, and project mismatch", () => {
  const authority = new IdentityAuthority();
  const result = authority.enroll(input, t0);
  assert.throws(() => authority.verifyEnrollment({ ...result.token, projectId: "other" }, t0), /mismatch|signature/);
  const expired = authority.enroll(input, t0); // distinct identity and token
  assert.throws(() => authority.verifyEnrollment(expired.token, new Date("2026-01-01T00:15:00.000Z")), /expired/);
  assert.throws(() => authority.openSession(result.identity.id, "other", 60, t0), /project/);
});

test("suspension and revocation fail closed", () => {
  const authority = new IdentityAuthority();
  const result = authority.enroll(input, t0);
  const session = authority.openSession(result.identity.id, input.projectId, 60, t0);
  authority.suspend(result.identity.id, t0);
  assert.throws(() => authority.openSession(result.identity.id, input.projectId, 60, t0), /not eligible/);
  assert.throws(() => authority.verifySession(session, t0), /not active/);
  authority.revoke(result.identity.id, t0);
  assert.throws(() => authority.openSession(result.identity.id, input.projectId, 60, t0), /not eligible/);
});

test("rotation preserves identity id and invalidates the previous key", () => {
  const authority = new IdentityAuthority();
  const result = authority.enroll(input, t0);
  const oldKey = result.identity.publicKey;
  const rotated = authority.rotate(result.identity.id, new Date("2026-01-01T00:01:00.000Z"));
  assert.equal(rotated.id, result.identity.id);
  assert.notEqual(rotated.publicKey, oldKey);
  assert.throws(() => authority.verifyEnrollment(result.token, t0), /key mismatch|signature/);
});

test("sessions enforce expiry, project binding, and TTL bounds", () => {
  const authority = new IdentityAuthority();
  const result = authority.enroll(input, t0);
  assert.throws(() => authority.openSession(result.identity.id, input.projectId, 0, t0), /TTL/);
  assert.throws(() => authority.openSession(result.identity.id, input.projectId, 86_401, t0), /TTL/);
  const session = authority.openSession(result.identity.id, input.projectId, 60, t0);
  assert.equal(authority.verifySession(session, new Date("2026-01-01T00:00:59.999Z")), true);
  assert.throws(() => authority.verifySession(session, new Date("2026-01-01T00:01:00.000Z")), /expired/);
});

test("identity digest is stable for equivalent objects", () => {
  const authority = new IdentityAuthority();
  const identity = authority.enroll(input, t0).identity;
  assert.equal(authority.identityDigest(identity), authority.identityDigest({ ...identity }));
});

function durablePath(): string {
  return join(mkdtempSync(join(tmpdir(), "invock-identity-")), "authority.json");
}

test("durable authority preserves identities, token replay, sessions, trust state, and software attestation", () => {
  const path = durablePath();
  const authority = new IdentityAuthority(path);
  const enrolled = authority.enroll(input, t0);
  const session = authority.openSession(enrolled.identity.id, input.projectId, 300, t0);
  const attested = authority.attest(enrolled.identity.id, { build: "fixture" }, t0);
  assert.equal(authority.verifyEnrollment(enrolled.token, t0), true);
  const restarted = new IdentityAuthority(path);
  assert.throws(() => restarted.verifyEnrollment(enrolled.token, t0), /replayed/u);
  assert.equal(restarted.verifySession(session, new Date("2026-01-01T00:01:00.000Z")), true);
  assert.equal(restarted.verifyAttestation(attested.attestation, { build: "fixture" }, new Date("2026-01-01T00:01:00.000Z")), true);
  restarted.suspend(enrolled.identity.id, new Date("2026-01-01T00:02:00.000Z"));
  const trustState = new IdentityAuthority(path);
  assert.throws(() => trustState.openSession(enrolled.identity.id, input.projectId, 60, new Date("2026-01-01T00:02:01.000Z")), /not eligible/u);
});

test("durable state rejects signed-state tampering and identity key mismatch", () => {
  const path = durablePath();
  const authority = new IdentityAuthority(path);
  const enrolled = authority.enroll(input, t0);
  const original = readFileSync(path, "utf8");
  const parsed = JSON.parse(original) as { state: { identities: Array<{ identity: { displayName: string } }> } };
  parsed.state.identities[0]!.identity.displayName = "tampered";
  writeFileSync(path, JSON.stringify(parsed), { mode: 0o600 });
  assert.throws(() => new IdentityAuthority(path), /signature/u);
  writeFileSync(path, original, { mode: 0o600 });
  writeFileSync(`${path}.${enrolled.identity.id}.key`, "not-a-private-key", { mode: 0o600 });
  assert.throws(() => new IdentityAuthority(path), /key mismatch|key set/u);
});

test("durable state rejects incomplete and overly-permissive sidecars", () => {
  const path = durablePath();
  const authority = new IdentityAuthority(path);
  const enrolled = authority.enroll(input, t0);
  const identitySidecar = `${path}.${enrolled.identity.id}.key`;
  // A missing identity sidecar is a fail-closed condition.
  renameSync(identitySidecar, `${identitySidecar}.missing`);
  assert.throws(() => new IdentityAuthority(path), /key set/u);

  const permissionPath = durablePath();
  const permissionAuthority = new IdentityAuthority(permissionPath);
  permissionAuthority.enroll(input, t0);
  const signerSidecar = `${permissionPath}.authority.key`;
  chmodSync(signerSidecar, 0o644);
  assert.throws(() => new IdentityAuthority(permissionPath), /permissions/u);
});
