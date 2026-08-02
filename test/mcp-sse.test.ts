import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import type { ServerResponse } from "node:http";
import { SseSessionManager } from "../src/mcp/sse.js";
import { StreamableHttpUpstreamClient } from "../src/mcp/upstream.js";
import { startStreamableHttpGateway } from "../src/mcp/http.js";
import type { JsonRpcResponse } from "../src/mcp/protocol.js";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicy, parsePolicyYaml } from "../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../src/gateway/engine.js";
import { InvockStore } from "../src/storage/store.js";

function fixtureGate() {
  const dir = mkdtempSync(join(tmpdir(), "invock-sse-"));
  const policy = compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: sse }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: allow-all
    decision: ALLOW
    reasonCodes: []
    when: {}
`));
  const store = new InvockStore(join(dir, "gateway.sqlite"));
  const gate = new InvocationGate(policy, new StaticDescriptorRegistry({}), store, { cwd: dir, projectRoot: realpathSync(dir), organizationDomains: [], sessionId: "sse", principal: { principalId: "test", clientId: "test", scopes: [] } }, { allowUnboundForTests: true });
  return { dir, store, gate, close: () => { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(address.port);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function postOnFreshConnection(url: string, token: string, body: string): Promise<{ status: number; body: string }> {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: "POST",
      agent: false,
      headers: {
        authorization: `Bearer ${token}`,
        host: parsed.host,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
        connection: "close",
      },
    }, response => {
      const chunks: Buffer[] = [];
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end(body);
  });
}

function makeSseClient(url: string, sessionId: string, token: string, onStatus: (status: number) => void, onData: (chunk: string) => void, abortAfterMs = 5_000): Promise<void> {
  return new Promise((resolve) => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(url, {
          method: "GET",
          headers: {
            authorization: `Bearer ${token}`,
            host: new URL(url).host,
            "mcp-session-id": sessionId,
            accept: "text/event-stream",
          },
          signal: controller.signal,
        });
        onStatus(response.status);
        if (response.body) {
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) onData(decoder.decode(value, { stream: true }));
          }
        }
      } catch (error) {
        if ((error as Error).name === "AbortError") {
          resolve();
          return;
        }
      }
      resolve();
    })();
    setTimeout(() => controller.abort(), abortAfterMs).unref();
  });
}

test("SSE session manager: create, enqueue, heartbeat, close, ordering", async () => {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, callback) {
      chunks.push(chunk.toString("utf8"));
      callback();
    },
  }) as unknown as ServerResponse;

  const manager = new SseSessionManager({ idleTimeoutMs: 100, heartbeatMs: 30 });
  const session = manager.createSession(stream, "sess-1");
  assert.equal(manager.size, 1);

  manager.enqueue("sess-1", { jsonrpc: "2.0", id: 1, result: { first: true } });
  manager.enqueue("sess-1", { jsonrpc: "2.0", id: 2, result: { second: true } });
  manager.enqueue("sess-1", { jsonrpc: "2.0", id: 3, result: { third: true } });

  await new Promise((resolve) => setTimeout(resolve, 50));

  const all = chunks.join("");
  const first = all.indexOf("event: message");
  const second = all.indexOf("event: message", first + 1);
  const third = all.indexOf("event: message", second + 1);
  assert.ok(first !== -1);
  assert.ok(second !== -1);
  assert.ok(third !== -1);
  assert.ok(second > first);
  assert.ok(third > second);

  manager.heartbeat("sess-1");
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(chunks.join("").includes(": ping"));

  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(manager.size, 0);
  assert.equal(session.closed, true);

  manager.closeAll();
});

test("GET /mcp returns SSE stream with endpoint event; duplicate session is rejected", async () => {
  const fixture = fixtureGate();
  const http = await startStreamableHttpGateway(fixture.gate, {
    token: "gateway-token",
    sse: { enabled: true, idleTimeoutMs: 5_000, heartbeatMs: 100 },
    forward: async (message) => ({ jsonrpc: "2.0", id: "id" in message ? message.id : null, result: {} }),
  });

  try {
    let status = 0;
    const raw: string[] = [];
    const ssePromise = makeSseClient(
      http.url,
      "test-session-1",
      "gateway-token",
      (s) => { status = s; },
      (chunk) => { raw.push(chunk); },
      2_000,
    );
    await new Promise((resolve) => setTimeout(resolve, 100));

    const accumulated = raw.join("");
    assert.ok(accumulated.includes("event: endpoint"), `Expected endpoint event in: ${accumulated.slice(0, 200)}`);

    const dup = await fetch(http.url, {
      method: "GET",
      headers: { authorization: "Bearer gateway-token", host: new URL(http.url).host, "mcp-session-id": "test-session-1", accept: "text/event-stream" },
    });
    assert.equal(dup.status, 409);
    await dup.arrayBuffer();

    const noSession = await fetch(http.url, {
      method: "GET",
      headers: { authorization: "Bearer gateway-token", host: new URL(http.url).host, accept: "text/event-stream" },
    });
    assert.equal(noSession.status, 400);
    await noSession.arrayBuffer();

    const postResponse = await fetch(http.url, {
      method: "POST",
      headers: {
        authorization: "Bearer gateway-token",
        host: new URL(http.url).host,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-session-id": "test-session-1",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 42, method: "ping" }),
    });
    assert.equal(postResponse.status, 202);
    await postResponse.arrayBuffer();

    await new Promise((resolve) => setTimeout(resolve, 150));
    const all = raw.join("");
    assert.ok(all.includes('"id":42'), `Expected response with id 42 on SSE channel, got: ${all.slice(0, 500)}`);

    await ssePromise;
  } finally {
    await http.close();
    fixture.close();
  }
});

test("POST with session id when SSE disabled still works via direct response", async () => {
  const fixture = fixtureGate();
  const http = await startStreamableHttpGateway(fixture.gate, {
    token: "gateway-token",
    forward: async (message) => ({ jsonrpc: "2.0", id: "id" in message ? message.id : null, result: { ok: true } }),
  });
  try {
    const response = await fetch(http.url, {
      method: "POST",
      headers: { authorization: "Bearer gateway-token", host: new URL(http.url).host, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }),
    });
    assert.equal(response.status, 200);
    const body = await response.json() as JsonRpcResponse;
    assert.equal(body.id, 7);
  } finally {
    await http.close();
    fixture.close();
  }
});

test("HTTP request ids are scoped per client connection", async () => {
  const fixture = fixtureGate();
  let release!: () => void;
  let started!: () => void;
  const startedPromise = new Promise<void>(resolve => { started = resolve; });
  const releasePromise = new Promise<void>(resolve => { release = resolve; });
  const http = await startStreamableHttpGateway(fixture.gate, {
    token: "gateway-token",
    forward: async message => {
      started();
      await releasePromise;
      return { jsonrpc: "2.0", id: "id" in message ? message.id : null, result: { ok: true } };
    },
  });
  try {
    const body = JSON.stringify({ jsonrpc: "2.0", id: "same-id", method: "ping" });
    const first = postOnFreshConnection(http.url, http.token, body);
    await startedPromise;
    const second = postOnFreshConnection(http.url, http.token, body);
    await new Promise(resolve => setTimeout(resolve, 50));
    release();
    const [firstResponse, secondResponse] = await Promise.all([first, second]);
    assert.equal(firstResponse.status, 200);
    assert.equal(secondResponse.status, 200);
  } finally {
    await http.close();
    fixture.close();
  }
});

test("GET /mcp when SSE disabled returns 405", async () => {
  const fixture = fixtureGate();
  const http = await startStreamableHttpGateway(fixture.gate, {
    token: "gateway-token",
    forward: async (message) => ({ jsonrpc: "2.0", id: "id" in message ? message.id : null, result: {} }),
  });
  try {
    const response = await fetch(http.url, {
      method: "GET",
      headers: { authorization: "Bearer gateway-token", host: new URL(http.url).host, "mcp-session-id": "sess", accept: "text/event-stream" },
    });
    assert.equal(response.status, 405);
    await response.arrayBuffer();
  } finally {
    await http.close();
    fixture.close();
  }
});

test("upstream client: initialize handshake and request/response correlation", async () => {
  let requestCount = 0;
  const mock = createServer((req, res) => {
    requestCount++;
    let body = "";
    req.on("data", (chunk) => { body += chunk.toString("utf8"); });
    req.on("end", () => {
      const message = JSON.parse(body) as { id?: string | number; method?: string };
      if (message.method === "initialize") {
        res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "upstream-sess-1" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "mock", version: "1.0.0" } } }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "upstream-sess-1" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id ?? null, result: { echo: message } }));
    });
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  try {
    const init = await client.initialize();
    assert.equal(init.protocolVersion, "2025-11-25");
    assert.equal(init.sessionId, "upstream-sess-1");
    assert.equal(client.session, "upstream-sess-1");

    const response = await client.request({ jsonrpc: "2.0", id: 99, method: "tools/list", params: {} });
    assert.ok("id" in response && response.id === 99);
    assert.ok("result" in response);

    const second = await client.request({ jsonrpc: "2.0", id: 100, method: "ping" });
    assert.ok("id" in second && second.id === 100);
    assert.equal(requestCount, 3);
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("upstream client rejects an unsupported initialize protocol version", async () => {
  const mock = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2999-01-01", capabilities: {}, serverInfo: { name: "mock", version: "1.0.0" } } }));
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  try {
    await assert.rejects(client.initialize(), /UPSTREAM_INITIALIZE_UNSUPPORTED_PROTOCOL:2999-01-01/u);
    assert.equal(client.protocol, undefined);
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("upstream client: id mismatch rejection", async () => {
  const mock = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 999, result: { wrong: true } }));
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  try {
    await assert.rejects(
      client.request({ jsonrpc: "2.0", id: 1, method: "ping" }),
      /UPSTREAM_RESPONSE_ID_MISMATCH/,
    );
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("upstream client parses CRLF and multiline SSE data frames", async () => {
  const mock = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end('event: message\r\ndata: {"jsonrpc":"2.0",\r\ndata: "id":1,"result":{"ok":true}}\r\n\r\n');
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  try {
    const response = await client.request({ jsonrpc: "2.0", id: 1, method: "ping" });
    assert.ok("id" in response && response.id === 1);
    assert.deepEqual("result" in response ? response.result : undefined, { ok: true });
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("upstream client rejects a JSON-RPC request disguised as a response", async () => {
  const mock = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "unexpected" } }));
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  try {
    await assert.rejects(client.request({ jsonrpc: "2.0", id: 1, method: "ping" }), /UPSTREAM_MALFORMED_RESPONSE/u);
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("HTTP gateway rejects a request-shaped upstream control response", async () => {
  const fixture = fixtureGate();
  const http = await startStreamableHttpGateway(fixture.gate, {
    token: "gateway-token",
    forward: async message => ({ jsonrpc: "2.0", id: "id" in message ? message.id : null, method: "tools/list", params: {} } as never),
  });
  try {
    const response = await fetch(http.url, {
      method: "POST",
      headers: { authorization: "Bearer gateway-token", host: new URL(http.url).host, "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "ping" }),
    });
    assert.equal(response.status, 502);
    const body = await response.json() as JsonRpcResponse;
    assert.equal(body.error?.message, "Upstream gateway failure");
  } finally {
    await http.close();
    fixture.close();
  }
});

test("upstream client: timeout rejection", async () => {
  const mock = createServer((req, res) => {
    req.resume();
    setTimeout(() => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
    }, 5_000).unref();
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 200 });
  try {
    await assert.rejects(
      client.request({ jsonrpc: "2.0", id: 1, method: "ping" }),
      /UPSTREAM_REQUEST_TIMEOUT/,
    );
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("upstream client: redirect policy maxRedirects", async () => {
  let redirectCount = 0;
  const redirector = createServer((req, res) => {
    req.resume();
    redirectCount++;
    if (redirectCount >= 10) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
      return;
    }
    res.writeHead(302, { location: `http://127.0.0.1:${redirectorPort}/mcp` });
    res.end();
  });
  const redirectorPort = await listen(redirector);

  const client = new StreamableHttpUpstreamClient({
    url: `http://127.0.0.1:${redirectorPort}/mcp`,
    redirectPolicy: { maxRedirects: 2, allowCrossHost: true },
    requestTimeoutMs: 2_000,
  });
  try {
    await assert.rejects(
      client.request({ jsonrpc: "2.0", id: 1, method: "ping" }),
      /UPSTREAM_TOO_MANY_REDIRECTS/,
    );
    assert.ok(redirectCount >= 3);
  } finally {
    client.close();
    await closeServer(redirector);
  }
});

test("upstream client: redirect policy cross-host denied", async () => {
  const target = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
  });
  let redirectCount = 0;
  const redirector = createServer((req, res) => {
    req.resume();
    redirectCount++;
    res.writeHead(302, { location: `http://127.0.0.1:${targetPort}/mcp` });
    res.end();
  });
  const targetPort = await listen(target);
  const redirectorPort = await listen(redirector);

  const client = new StreamableHttpUpstreamClient({
    url: `http://localhost:${redirectorPort}/mcp`,
    redirectPolicy: { maxRedirects: 5, allowCrossHost: false },
    requestTimeoutMs: 2_000,
  });
  try {
    await assert.rejects(
      client.request({ jsonrpc: "2.0", id: 1, method: "ping" }),
      /UPSTREAM_CROSS_HOST_REDIRECT_DENIED/,
    );
    assert.equal(redirectCount, 1);
  } finally {
    client.close();
    await closeServer(redirector);
    await closeServer(target);
  }
});

test("upstream client strips credentials across an explicitly allowed cross-host redirect", async () => {
  let forwardedAuthorization: string | undefined;
  let forwardedCookie: string | undefined;
  let forwardedSession: string | undefined;
  const target = createServer((req, res) => {
    forwardedAuthorization = req.headers.authorization;
    forwardedCookie = req.headers.cookie;
    forwardedSession = req.headers["mcp-session-id"] as string | undefined;
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
  });
  const redirector = createServer((req, res) => {
    req.resume();
    res.writeHead(302, { location: `http://127.0.0.1:${targetPort}/mcp` });
    res.end();
  });
  const targetPort = await listen(target);
  const redirectorPort = await listen(redirector);
  const client = new StreamableHttpUpstreamClient({
    url: `http://localhost:${redirectorPort}/mcp`,
    headers: { authorization: "Bearer secret", cookie: "session=secret", "mcp-session-id": "upstream-secret" },
    redirectPolicy: { maxRedirects: 5, allowCrossHost: true, allowedHosts: ["127.0.0.1"] },
    requestTimeoutMs: 2_000,
  });
  try {
    const response = await client.request({ jsonrpc: "2.0", id: 1, method: "ping" });
    assert.equal("id" in response && response.id, 1);
    assert.equal(forwardedAuthorization, undefined);
    assert.equal(forwardedCookie, undefined);
    assert.equal(forwardedSession, undefined);
  } finally {
    client.close();
    await closeServer(redirector);
    await closeServer(target);
  }
});

test("upstream client: session terminated clears session id", async () => {
  const sessions: string[] = [];
  const mock = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk.toString("utf8"); });
    req.on("end", () => {
      const message = JSON.parse(body) as { id?: string | number; method?: string };
      if (message.method === "initialize") {
        const newSession = `upstream-sess-${sessions.length + 1}`;
        sessions.push(newSession);
        res.writeHead(200, { "content-type": "application/json", "mcp-session-id": newSession });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "mock", version: "1.0.0" } } }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json", "mcp-session-terminated": "true" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: {} }));
    });
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  try {
    const init = await client.initialize();
    assert.equal(init.sessionId, "upstream-sess-1");

    await client.request({ jsonrpc: "2.0", id: 2, method: "notifications/initialized" });
    assert.equal(client.session, undefined);
    assert.equal(sessions.length, 1);

    // Re-initialize creates a new session
    const reinit = await client.initialize();
    assert.equal(reinit.sessionId, "upstream-sess-2");
    assert.equal(sessions.length, 2);
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("hard timeouts: no leaked timers", async () => {
  const manager = new SseSessionManager({ idleTimeoutMs: 50, heartbeatMs: 10 });
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, callback) {
      chunks.push(chunk.toString("utf8"));
      callback();
    },
  }) as unknown as ServerResponse;
  manager.createSession(stream, "timeout-sess");
  manager.closeAll();
  assert.equal(manager.size, 0);

  const mock = createServer((req, res) => {
    req.resume();
    setTimeout(() => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
    }, 5_000).unref();
  });
  const port = await listen(mock);
  const client = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 100 });
  const requestPromise = client.request({ jsonrpc: "2.0", id: 1, method: "ping" }).catch(() => true);
  client.close();
  await requestPromise;
  await closeServer(mock);
});

test("SSE heartbeat obeys the bounded queue and closes a stalled session", () => {
  const stream = new Writable({
    highWaterMark: 1,
    write(_chunk, _enc, _callback) {
      // Keep the stream backpressured so heartbeat frames remain queued.
    },
  }) as unknown as ServerResponse;
  const manager = new SseSessionManager({ maxQueueLength: 1, heartbeatMs: 60_000, idleTimeoutMs: 60_000 });
  const session = manager.createSession(stream, "bounded-heartbeat");

  manager.heartbeat(session.id);
  manager.heartbeat(session.id);
  manager.heartbeat(session.id);

  assert.equal(manager.size, 0);
  assert.equal(session.closed, true);
  manager.closeAll();
});


test("upstream client: dns pinner hook", async () => {
  const mock = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
  });
  const port = await listen(mock);
  const pinned: string[] = [];
  const client = new StreamableHttpUpstreamClient({
    url: `http://127.0.0.1:${port}/mcp`,
    requestTimeoutMs: 2_000,
    dnsPinner: {
      async pin(hostname) {
        pinned.push(hostname);
        return { addresses: ["127.0.0.1"] };
      },
    },
  });
  try {
    const response = await client.request({ jsonrpc: "2.0", id: 1, method: "ping" });
    assert.ok("id" in response && response.id === 1);
    assert.ok(pinned.includes("127.0.0.1"));
  } finally {
    client.close();
    await closeServer(mock);
  }
});

test("upstream client requires HTTPS and DNS pinning for remote targets", () => {
  assert.throws(() => new StreamableHttpUpstreamClient({ url: "http://service.example/mcp" }), /UPSTREAM_REMOTE_HTTPS_REQUIRED/u);
  assert.throws(() => new StreamableHttpUpstreamClient({ url: "https://service.example/mcp" }), /UPSTREAM_REMOTE_DNS_PIN_REQUIRED/u);
  const client = new StreamableHttpUpstreamClient({ url: "https://service.example/mcp", dnsPinner: { async pin() { return { addresses: ["203.0.113.10"] }; } } });
  client.close();
});

test("gateway with upstream client forwards via Streamable HTTP", async () => {
  const fixture = fixtureGate();
  const mock = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk.toString("utf8"); });
    req.on("end", () => {
      const message = JSON.parse(body) as { id?: string | number; method?: string };
      if (message.method === "initialize") {
        res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "gw-upstream-sess" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "mock", version: "1.0.0" } } }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "gw-upstream-sess" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id ?? null, result: { echo: true } }));
    });
  });
  const port = await listen(mock);
  const upstream = new StreamableHttpUpstreamClient({ url: `http://127.0.0.1:${port}/mcp`, requestTimeoutMs: 2_000 });
  const http = await startStreamableHttpGateway(fixture.gate, {
    token: "gateway-token",
    upstream,
    forward: async (message) => ({ jsonrpc: "2.0", id: "id" in message ? message.id : null, result: {} }),
  });
  try {
    const response = await fetch(http.url, {
      method: "POST",
      headers: { authorization: "Bearer gateway-token", host: new URL(http.url).host, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "ping" }),
    });
    assert.equal(response.status, 200);
    const body = await response.json() as JsonRpcResponse;
    assert.equal(body.id, 5);
    assert.ok("result" in body);
  } finally {
    await http.close();
    upstream.close();
    fixture.close();
    await closeServer(mock);
  }
});
