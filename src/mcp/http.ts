import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { InvocationGate } from "../gateway/engine.js";
import { deniedToolCall, isControlPlane, isToolCall, negotiateEra, parseJsonRpc, protocolError, type JsonRpcMessage, type JsonRpcResponse } from "./protocol.js";
import type { ToolResult } from "../core/types.js";
import { SseSessionManager, startSseEndpoint } from "./sse.js";
import type { StreamableHttpUpstreamClient } from "./upstream.js";

const MAX_BODY_BYTES = 2 * 1024 * 1024;
function safeToken(actual: string | undefined, expected: string): boolean { if (!actual?.startsWith("Bearer ")) return false; const a = Buffer.from(actual.slice(7)); const b = Buffer.from(expected); return a.length === b.length && timingSafeEqual(a, b); }
function send(response: ServerResponse, status: number, message?: JsonRpcResponse): void { response.writeHead(status, message ? { "content-type": "application/json", "cache-control": "no-store" } : { "cache-control": "no-store" }).end(message ? JSON.stringify(message) : undefined); }
async function readJson(request: IncomingMessage): Promise<unknown> { const chunks: Buffer[] = []; let total = 0; for await (const raw of request) { const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw); total += chunk.length; if (total > MAX_BODY_BYTES) throw new Error("MCP request exceeds 2 MiB"); chunks.push(chunk); } return JSON.parse(Buffer.concat(chunks).toString("utf8")); }

export interface HttpMcpGatewaySseOptions { enabled: boolean; idleTimeoutMs?: number; heartbeatMs?: number; maxSessions?: number; }
export interface HttpMcpGatewayOptions { host?: string; port?: number; token?: string; candidate2026?: boolean; allowedOrigins?: string[]; requestTimeoutMs?: number; sse?: HttpMcpGatewaySseOptions; upstream?: StreamableHttpUpstreamClient; forward(message: JsonRpcMessage, signal: AbortSignal): Promise<JsonRpcMessage>; }
export interface HttpMcpGateway { server: Server; url: string; token: string; close(): Promise<void>; }

/** Streamable HTTP entry point: validates HTTP/JSON-RPC then applies the same invocation gate used by stdio. */
export async function startStreamableHttpGateway(gate: InvocationGate, options: HttpMcpGatewayOptions): Promise<HttpMcpGateway> {
  const host = options.host ?? "127.0.0.1"; const token = options.token ?? randomBytes(32).toString("base64url"); const allowedOrigins = new Set(options.allowedOrigins ?? []);
  const inFlight = new Set<string | number>();
  const sseEnabled = options.sse?.enabled === true;
  const sseManagerOpts: { idleTimeoutMs?: number; heartbeatMs?: number; maxSessions?: number } = {};
  if (options.sse?.idleTimeoutMs !== undefined) sseManagerOpts.idleTimeoutMs = options.sse.idleTimeoutMs;
  if (options.sse?.heartbeatMs !== undefined) sseManagerOpts.heartbeatMs = options.sse.heartbeatMs;
  if (options.sse?.maxSessions !== undefined) sseManagerOpts.maxSessions = options.sse.maxSessions;
  const sseManager = sseEnabled ? new SseSessionManager(sseManagerOpts) : undefined;
  const forward = async (message: JsonRpcMessage, signal: AbortSignal): Promise<JsonRpcMessage> => {
    if (options.upstream) {
      const reqOpts: { timeoutMs?: number } = {};
      if (options.requestTimeoutMs !== undefined) reqOpts.timeoutMs = options.requestTimeoutMs;
      return options.upstream.request(message, reqOpts);
    }
    return options.forward(message, signal);
  };
  const server = createServer((request, response) => { void (async () => {
    const hostHeader = request.headers.host ?? "";
    if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/iu.test(hostHeader)) { send(response, 403); return; }
    const origin = request.headers.origin;
    if (origin && !allowedOrigins.has(origin)) { send(response, 403); return; }
    if (!safeToken(request.headers.authorization, token)) { send(response, 401); return; }
    if (request.url !== "/mcp") { send(response, 404); return; }
    if (request.method === "GET") {
      if (!sseEnabled || !sseManager) { send(response, 405); return; }
      const sessionHeader = request.headers["mcp-session-id"];
      if (typeof sessionHeader !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(sessionHeader)) { send(response, 400, protocolError(null, -32600, "Invalid MCP session id")); return; }
      const sseEndpointOpts: { postUrl: string; idleTimeoutMs?: number; heartbeatMs?: number } = { postUrl: `http://${hostHeader}/mcp` };
      if (options.sse?.idleTimeoutMs !== undefined) sseEndpointOpts.idleTimeoutMs = options.sse.idleTimeoutMs;
      if (options.sse?.heartbeatMs !== undefined) sseEndpointOpts.heartbeatMs = options.sse.heartbeatMs;
      startSseEndpoint(request, response, sessionHeader, sseManager, sseEndpointOpts);
      return;
    }
    if (request.method !== "POST") { send(response, 405); return; }
    if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) { send(response, 415); return; }
    let message: JsonRpcMessage;
    let protocolEra: ReturnType<typeof negotiateEra>;
    try { protocolEra = negotiateEra(request.headers["mcp-protocol-version"] as string | undefined, options.candidate2026); message = parseJsonRpc(await readJson(request)); }
    catch (error) { send(response, 400, protocolError(null, -32700, error instanceof Error ? error.message : "Parse error")); return; }
    const sessionHeader = request.headers["mcp-session-id"];
    if (sessionHeader !== undefined && (typeof sessionHeader !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(sessionHeader))) { send(response, 400, protocolError(null, -32600, "Invalid MCP session id")); return; }
    const hasSseSession = typeof sessionHeader === "string" && sseManager !== undefined && sseManager.getSession(sessionHeader) !== undefined;
    const deliver = async (payload: JsonRpcMessage): Promise<void> => {
      if (hasSseSession && sseManager && typeof sessionHeader === "string") {
        sseManager.enqueue(sessionHeader, payload);
        response.writeHead(202, { "cache-control": "no-store" }).end();
        return;
      }
      send(response, 200, payload as JsonRpcResponse);
    };
    if (!isToolCall(message)) {
      if (!isControlPlane(message)) { send(response, 400, protocolError("id" in message && (typeof message.id === "string" || typeof message.id === "number") ? message.id : null, -32601, "Method is outside the supported mediation boundary")); return; }
      const controlId = "id" in message && (typeof message.id === "string" || typeof message.id === "number") ? message.id : undefined;
      if (controlId !== undefined && inFlight.has(controlId)) { send(response, 409, protocolError(controlId, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID")); return; }
      if (controlId !== undefined) inFlight.add(controlId);
      const controller = new AbortController(); request.once("aborted", () => controller.abort()); const timeout = setTimeout(() => controller.abort(), options.requestTimeoutMs ?? 30_000); timeout.unref();
      try {
        const upstream = await forward(message, controller.signal);
        if (controlId !== undefined && (!("id" in upstream) || upstream.id !== controlId)) throw new Error("UPSTREAM_RESPONSE_ID_MISMATCH");
        if ("method" in message && message.method === "tools/list" && "result" in upstream) gate.observeToolsList(upstream.result);
        await deliver(upstream); return;
      } catch { send(response, 502, protocolError(controlId ?? null, -32050, "Upstream gateway failure")); return; }
      finally { clearTimeout(timeout); if (controlId !== undefined) inFlight.delete(controlId); }
    }
    const requestId = "id" in message && (typeof message.id === "string" || typeof message.id === "number") ? message.id : undefined;
    if (requestId !== undefined && inFlight.has(requestId)) { send(response, 409, protocolError(requestId, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID")); return; }
    if (requestId !== undefined) inFlight.add(requestId);
    const outcome = await gate.authorizeInvocation(message, { protocolEra: protocolEra.negotiatedVersion, ...(typeof sessionHeader === "string" ? { sessionId: sessionHeader } : {}) });
    if (outcome.kind === "respond") { if (requestId !== undefined) inFlight.delete(requestId); if (message.id === undefined) { send(response, 204); return; } await deliver(deniedToolCall(message.id, outcome.response.result)); return; }
    if (outcome.kind === "notification") {
      if (outcome.request) await forward(outcome.request, new AbortController().signal);
      if (requestId !== undefined) inFlight.delete(requestId);
      send(response, 202); return;
    }
    const controller = new AbortController(); request.once("aborted", () => controller.abort());
    const timeout = setTimeout(() => controller.abort(), options.requestTimeoutMs ?? 30_000); timeout.unref();
    try {
      const upstream = await forward(outcome.request, controller.signal);
      if (outcome.request.id === undefined) { gate.finishNotification(outcome); send(response, 202); return; }
      if (upstream && "id" in upstream && upstream.id !== undefined && upstream.id !== outcome.request.id) throw new Error("UPSTREAM_RESPONSE_ID_MISMATCH");
      if (!("result" in upstream) || upstream.result === undefined) throw new Error("Upstream tools/call did not return a result");
      const result = upstream.result as ToolResult; const receiptId = gate.finish(outcome, result);
      if (result._meta === undefined) result._meta = {}; result._meta["io.invock/receipt-id"] = receiptId;
      if (outcome.request.id === undefined) send(response, 202); else await deliver({ jsonrpc: "2.0", id: outcome.request.id, result });
    } catch (error) { gate.fail(outcome, error instanceof Error ? error.message : "Upstream failure"); send(response, 502, protocolError(outcome.request.id ?? null, -32050, "Upstream gateway failure")); }
    finally { clearTimeout(timeout); if (requestId !== undefined) inFlight.delete(requestId); }
  })().catch(error => send(response, 500, protocolError(null, -32050, error instanceof Error ? error.message : "Internal gateway failure"))); });
  return await new Promise((resolve, reject) => { server.once("error", reject); server.listen(options.port ?? 0, host, () => { const address = server.address(); if (!address || typeof address === "string") { reject(new Error("Could not bind MCP HTTP gateway")); return; } resolve({ server, url: `http://${host}:${address.port}/mcp`, token, close: () => new Promise((done, fail) => { if (sseManager) sseManager.closeAll(); server.close(error => error ? fail(error) : done()); }) }); }); });
}
