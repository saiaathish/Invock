import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { startApi } from "../../src/api/server.js";
import { InvockStore } from "../../src/storage/store.js";
import { testGate } from "../../fixtures/testing/invock.js";

test("dependency-free Python SDK interoperates with the live loopback API", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "python-sdk-token", gate: testGate(store) });
  try {
    const script = [
      "import json",
      "from invock_client import InvockClient",
      `client = InvockClient(${JSON.stringify(api.url)}, "python-sdk-token")`,
      "health = client.health()",
      "decision = client.authorize(\"read\", {})",
      "assert health == {\"status\": \"ok\"}",
      "assert decision[\"verdict\"] == \"ALLOW\"",
      "assert decision[\"containmentRequired\"] is False",
      "print(json.dumps({\"health\": health, \"verdict\": decision[\"verdict\"]}))",
    ].join("; ");
    const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn("python3", ["-c", script], { cwd: process.cwd(), env: { ...process.env, PYTHONPATH: `${process.cwd()}/sdk/python` } });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", chunk => { stdout += String(chunk); });
      child.stderr.on("data", chunk => { stderr += String(chunk); });
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Python SDK interoperability timed out")); }, 15_000);
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("close", code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
    });
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.deepEqual(JSON.parse(result.stdout.trim()), { health: { status: "ok" }, verdict: "ALLOW" });
  } finally {
    await api.close();
    store.close();
  }
});
