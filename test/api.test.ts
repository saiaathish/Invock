import assert from "node:assert/strict";
import { request } from "node:http";
import { test } from "node:test";
import { InvockStore } from "../src/storage/store.js";
import { startApi } from "../src/api/server.js";

test("loopback API authenticates activity and rejects hostile Host headers", async () => {
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "test-token" });
  try {
    const unauthenticated = await fetch(`${api.url}/api/v1/activity`);
    assert.equal(unauthenticated.status, 401);
    const authenticated = await fetch(`${api.url}/api/v1/activity`, { headers: { authorization: "Bearer test-token" } });
    assert.equal(authenticated.status, 200);
    assert.deepEqual(await authenticated.json(), { items: [] });
    const parsed = new URL(api.url);
    const hostileHost = await new Promise<number>((resolve, reject) => {
      const probe = request({ hostname: parsed.hostname, port: parsed.port, path: "/api/v1/health", headers: { host: "attacker.test" } }, response => { response.resume(); response.once("end", () => resolve(response.statusCode ?? 0)); });
      probe.once("error", reject); probe.end();
    });
    assert.equal(hostileHost, 403);
  } finally { await api.close(); store.close(); }
});