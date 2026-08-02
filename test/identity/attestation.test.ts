import assert from "node:assert/strict";
import test from "node:test";
import { IdentityAuthority } from "../../src/identity/index.js";

test("software workload attestation is signed, expiring, and rotation-bound", () => {
  const now = new Date("2027-01-01T00:00:00.000Z");
  const authority = new IdentityAuthority();
  const enrolled = authority.enroll({ organizationId: "org", projectId: "project", displayName: "agent", runtimeType: "node" }, now);
  const manifest = { image: "local-fixture", commit: "abc123", dependenciesDigest: "lock-digest" };
  const attested = authority.attest(enrolled.identity.id, manifest, now);
  assert.equal(attested.identity.trustState, "ATTESTED");
  assert.equal(authority.verifyAttestation(attested.attestation, manifest, new Date("2027-01-01T00:10:00.000Z")), true);
  assert.throws(() => authority.verifyAttestation(attested.attestation, { ...manifest, commit: "changed" }, new Date("2027-01-01T00:10:00.000Z")), /mismatch/u);
  authority.rotate(enrolled.identity.id, new Date("2027-01-01T00:01:00.000Z"));
  assert.throws(() => authority.verifyAttestation(attested.attestation, manifest, new Date("2027-01-01T00:10:00.000Z")), /not trusted/u);
});
