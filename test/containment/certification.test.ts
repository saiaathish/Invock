import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { certifyContainment } from "../../src/containment/certification.js";

test("containment certification reports the enforced runtime it actually exercised", async () => {
  const result = await certifyContainment();
  const dockerImage = spawnSync("docker", ["image", "inspect", "invock-containment:local", "--format", "{{.Id}}"], { encoding: "utf8", timeout: 5_000 });
  const dockerDigestAvailable = dockerImage.status === 0 && /^sha256:[a-f0-9]{64}$/u.test(dockerImage.stdout.trim());
  if (dockerDigestAvailable) {
    assert.equal(result.status, "pass");
    assert.equal(result.checks.noNewPrivileges, true);
    assert.equal(result.checks.cleanup, true);
    assert.deepEqual(result.limitations, []);
    return;
  }
  assert.equal(result.status, "unsupported");
  assert.ok(result.limitations.includes("REQUIRED_CONTAINMENT_RUNTIME_UNAVAILABLE"));
});
