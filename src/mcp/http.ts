import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { InvocationGate } from "../gateway/engine.js";
import { deniedToolCall, isControlPlane, isJsonRpcResponse, isToolCall, negotiateEra, parseJsonRpc, parseToolResult, protocolError, type JsonRpcMessage, type JsonRpcResponse } from "./protocol.js";
import { SseSessionManager, startSseEndpoint } from "./sse.js";
import type { StreamableHttpUpstreamClient } from "./upstream.js";
import type { ContainmentRunRecord } from "../containment/lifecycle.js";

const MAX_BODY_BYTES = 2 * 1024 * 1024;
function safeToken(actual: string | undefined, expected: string): boolean { if (!actual?.startsWith("Bearer ")) return false; const a = Buffer.from(actual.slice(7)); const b = Buffer.from(expected); return a.length === b.length && timingSafeEqual(a, b); }
function send(response: ServerResponse, status: number, message?: JsonRpcResponse): void { response.writeHead(status, message ? { "content-type": "application/json", "cache-control": "no-store" } : { "cache-control": "no-store" }).end(message ? JSON.stringify(message) : undefined); }
async function readJson(request: IncomingMessage): Promise<unknown> { const chunks: Buffer[] = []; let total = 0; for await (const raw of request) { const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw); total += chunk.length; if (total > MAX_BODY_BYTES) throw new Error("MCP request exceeds 2 MiB"); chunks.push(chunk); } return JSON.parse(Buffer.concat(chunks).toString("utf8")); }

export interface HttpMcpGatewaySseOptions { enabled: boolean; idleTimeoutMs?: number; heartbeatMs?: number; maxSessions?: number; }
export interface ContainedMcpForwardResult { response: JsonRpcMessage; containment: ContainmentRunRecord; }
export interface HttpMcpGatewayOptions { host?: string; port?: number; token?: string; candidate2026?: boolean; allowedOrigins?: string[]; requestTimeoutMs?: number; sse?: HttpMcpGatewaySseOptions; upstream?: StreamableHttpUpstreamClient; forward(message: JsonRpcMessage, signal: AbortSignal): Promise<JsonRpcMessage>; /** Required when the gate marks a tool call as containment-required. The handler must execute inside an enforceable profile and return its signed run record. */ containedForward?(message: JsonRpcMessage, signal: AbortSignal): Promise<ContainedMcpForwardResult>; }
export interface HttpMcpGateway { server: Server; url: string; token: string; close(): Promise<void>; }

/** Streamable HTTP entry point: validates HTTP/JSON-RPC then applies the same invocation gate used by stdio. */
export async function startStreamableHttpGateway(gate: InvocationGate, options: HttpMcpGatewayOptions): Promise<HttpMcpGateway> {
  const host = options.host ?? "127.0.0.1"; const token = options.token ?? randomBytes(32).toString("base64url"); const allowedOrigins = new Set(options.allowedOrigins ?? []);
  const negotiatedProtocolBySession = new Map<string, string>();
  const maxTrackedProtocolSessions = 1024;
  type RequestId = string | number;
  type RequestScope = { kind: "session"; id: string } | { kind: "connection"; socket: object };
  const inFlightBySession = new Map<string, Set<RequestId>>();
  const inFlightByConnection = new WeakMap<object, Set<RequestId>>();
  const idsFor = (scope: RequestScope): Set<RequestId> => {
    if (scope.kind === "session") {
      let ids = inFlightBySession.get(scope.id);
      if (!ids) { ids = new Set<RequestId>(); inFlightBySession.set(scope.id, ids); }
      return ids;
    }
    let ids = inFlightByConnection.get(scope.socket);
    if (!ids) { ids = new Set<RequestId>(); inFlightByConnection.set(scope.socket, ids); }
    return ids;
  };
  const reserve = (scope: RequestScope, id: RequestId): boolean => {
    const ids = idsFor(scope);
    if (ids.has(id)) return false;
    ids.add(id);
    return true;
  };
  const release = (scope: RequestScope, id: RequestId): void => {
    const ids = idsFor(scope);
    ids.delete(id);
    if (ids.size === 0 && scope.kind === "session") inFlightBySession.delete(scope.id);
  };
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
      return options.upstream.request(message, { ...reqOpts, signal });
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
    let requestedProtocolVersion: string;
    try {
      const headerValue = request.headers["mcp-protocol-version"];
      if (Array.isArray(headerValue)) throw new Error("MCP_PROTOCOL_VERSION_HEADER_INVALID");
      const headerVersion = headerValue;
      message = parseJsonRpc(await readJson(request));
      const sessionHeader = request.headers["mcp-session-id"];
      const sessionId = typeof sessionHeader === "string" ? sessionHeader : undefined;
      const rememberedVersion = sessionId === undefined ? undefined : negotiatedProtocolBySession.get(sessionId);
      const isInitialize = "method" in message && message.method === "initialize";
      if (isInitialize) {
        const params = "params" in message && message.params !== null && typeof message.params === "object" ? message.params : undefined;
        const bodyVersion = params && typeof params.protocolVersion === "string" ? params.protocolVersion : undefined;
        if (bodyVersion === undefined) throw new Error("MCP_INITIALIZE_PROTOCOL_VERSION_REQUIRED");
        if (headerVersion !== undefined && headerVersion !== bodyVersion) throw new Error("MCP_PROTOCOL_VERSION_HEADER_MISMATCH");
        if (rememberedVersion !== undefined && rememberedVersion !== bodyVersion) throw new Error("MCP_PROTOCOL_VERSION_SESSION_MISMATCH");
        requestedProtocolVersion = bodyVersion;
      } else {
        requestedProtocolVersion = headerVersion ?? rememberedVersion ?? "2025-11-25";
        if (rememberedVersion !== undefined && headerVersion !== undefined && headerVersion !== rememberedVersion) throw new Error("MCP_PROTOCOL_VERSION_SESSION_MISMATCH");
      }
      protocolEra = negotiateEra(requestedProtocolVersion, options.candidate2026);
    }
    catch (error) { send(response, 400, protocolError(null, -32602, error instanceof Error ? error.message : "Invalid MCP protocol negotiation")); return; }
    const sessionHeader = request.headers["mcp-session-id"];
    if (sessionHeader !== undefined && (typeof sessionHeader !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(sessionHeader))) { send(response, 400, protocolError(null, -32600, "Invalid MCP session id")); return; }
    const hasSseSession = typeof sessionHeader === "string" && sseManager !== undefined && sseManager.getSession(sessionHeader) !== undefined;
    const requestScope: RequestScope = hasSseSession && typeof sessionHeader === "string"
      ? { kind: "session", id: sessionHeader }
      : { kind: "connection", socket: request.socket };
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
      if (controlId !== undefined && !reserve(requestScope, controlId)) { send(response, 409, protocolError(controlId, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID")); return; }
      const controller = new AbortController(); request.once("aborted", () => controller.abort()); const timeout = setTimeout(() => controller.abort(), options.requestTimeoutMs ?? 30_000); timeout.unref();
      try {
        const upstream = await forward(message, controller.signal);
        if (!isJsonRpcResponse(upstream)) throw new Error("UPSTREAM_MALFORMED_RESPONSE");
        if (controlId !== undefined && (!("id" in upstream) || upstream.id !== controlId)) throw new Error("UPSTREAM_RESPONSE_ID_MISMATCH");
        if ("method" in message && message.method === "initialize") {
          const result = "result" in upstream && upstream.result !== null && typeof upstream.result === "object" && !Array.isArray(upstream.result)
            ? upstream.result as Record<string, unknown>
            : undefined;
          const selectedVersion = result?.protocolVersion;
          if (typeof selectedVersion !== "string" || selectedVersion !== protocolEra.negotiatedVersion) throw new Error("UPSTREAM_PROTOCOL_NEGOTIATION_FAILED");
          negotiateEra(selectedVersion, options.candidate2026);
          const sessionId = request.headers["mcp-session-id"];
          if (typeof sessionId === "string") {
            if (!negotiatedProtocolBySession.has(sessionId) && negotiatedProtocolBySession.size >= maxTrackedProtocolSessions) throw new Error("MCP_PROTOCOL_SESSION_LIMIT_REACHED");
            negotiatedProtocolBySession.set(sessionId, selectedVersion);
          }
        }
        if ("method" in message && message.method === "tools/list" && "result" in upstream) gate.observeToolsList(upstream.result);
        await deliver(upstream); return;
      } catch { send(response, 502, protocolError(controlId ?? null, -32050, "Upstream gateway failure")); return; }
      finally { clearTimeout(timeout); if (controlId !== undefined) release(requestScope, controlId); }
    }
    const requestId = "id" in message && (typeof message.id === "string" || typeof message.id === "number") ? message.id : undefined;
    if (requestId !== undefined && !reserve(requestScope, requestId)) { send(response, 409, protocolError(requestId, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID")); return; }
    // `mcp-session-id` is a transport routing handle for SSE.  It is supplied
    // by the peer and is not an authenticated identity/session boundary.  Do
    // not let it select the gate's lineage or authority partition; the gate's
    // server-bound runtime context remains authoritative.
    const outcome = await gate.authorizeInvocation(message, { protocolEra: protocolEra.negotiatedVersion });
    if (outcome.kind === "respond") { if (requestId !== undefined) release(requestScope, requestId); if (message.id === undefined) { send(response, 204); return; } await deliver(deniedToolCall(message.id, outcome.response.result)); return; }
    if (outcome.kind === "notification") {
      if (requestId !== undefined) release(requestScope, requestId);
      send(response, 202); return;
    }
    if (outcome.containmentRequired && !options.containedForward) {
      const rejected = gate.rejectForward(outcome);
      if (requestId !== undefined) release(requestScope, requestId);
      if (rejected.kind === "respond") await deliver(deniedToolCall(requestId!, rejected.response.result));
      else send(response, 202);
      return;
    }
    const controller = new AbortController(); request.once("aborted", () => controller.abort());
    const timeout = setTimeout(() => controller.abort(), options.requestTimeoutMs ?? 30_000); timeout.unref();
    let completedOutcome = outcome;
    try {
      const contained = outcome.containmentRequired ? await options.containedForward!(outcome.request, controller.signal) : undefined;
      const upstream = contained?.response ?? await forward(outcome.request, controller.signal);
      if (contained) completedOutcome = gate.attachContainmentRun(outcome, contained.containment);
      if (!isJsonRpcResponse(upstream)) throw new Error("UPSTREAM_MALFORMED_RESPONSE");
      if (outcome.request.id === undefined) { gate.finishNotification(completedOutcome); send(response, 202); return; }
      if (upstream && "id" in upstream && upstream.id !== undefined && upstream.id !== outcome.request.id) throw new Error("UPSTREAM_RESPONSE_ID_MISMATCH");
      if (!("result" in upstream) || upstream.result === undefined) throw new Error("Upstream tools/call did not return a result");
      const result = parseToolResult(upstream.result); const receiptId = gate.finish(completedOutcome, result);
      if (result._meta === undefined) result._meta = {}; result._meta["io.invock/receipt-id"] = receiptId;
      if (outcome.request.id === undefined) send(response, 202); else await deliver({ jsonrpc: "2.0", id: outcome.request.id, result });
    } catch (error) { if (completedOutcome.containmentRequired) gate.rejectForward(completedOutcome, "CONTAINMENT_EXECUTION_FAILED"); else gate.fail(completedOutcome, error instanceof Error ? error.message : "Upstream failure"); send(response, 502, protocolError(outcome.request.id ?? null, -32050, "Upstream gateway failure")); }
    finally { clearTimeout(timeout); if (requestId !== undefined) release(requestScope, requestId); }
  })().catch(error => send(response, 500, protocolError(null, -32050, error instanceof Error ? error.message : "Internal gateway failure"))); });
  return await new Promise((resolve, reject) => { server.once("error", reject); server.listen(options.port ?? 0, host, () => { const address = server.address(); if (!address || typeof address === "string") { reject(new Error("Could not bind MCP HTTP gateway")); return; } resolve({ server, url: `http://${host}:${address.port}/mcp`, token, close: () => new Promise((done, fail) => { if (sseManager) sseManager.closeAll(); server.close(error => error ? fail(error) : done()); }) }); }); });
}
