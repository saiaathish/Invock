import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import type { InvocationGate, ForwardedCall } from "./engine.js";
import type { ToolCallRequest, ToolResult } from "../core/types.js";
import { isJsonRpcResponse, parseJsonRpc, parseToolResult, type JsonRpcMessage } from "../mcp/protocol.js";
import type { ContainmentRunRecord } from "../containment/lifecycle.js";

const MAX_FRAME_BYTES = 2 * 1024 * 1024;

interface JsonRpcObject { jsonrpc: "2.0"; id?: string | number; method?: string; params?: unknown; result?: unknown; error?: unknown; }
function isRecord(value: unknown): value is Record<string, unknown> { return value !== null && !Array.isArray(value) && typeof value === "object"; }
function parseFrame(line: string): JsonRpcObject {
  if (Buffer.byteLength(line) > MAX_FRAME_BYTES) throw new Error("MCP frame exceeds 2 MiB");
  if (line.includes("\0")) throw new Error("MCP frame contains NUL");
  const parsed: unknown = JSON.parse(line);
  if (!isRecord(parsed) || parsed.jsonrpc !== "2.0" || Array.isArray(parsed)) throw new Error("Invalid JSON-RPC 2.0 object");
  parseJsonRpc(parsed);
  return parsed as unknown as JsonRpcObject;
}
function isToolCall(message: JsonRpcObject): message is ToolCallRequest {
  return message.method === "tools/call" && (message.id === undefined || typeof message.id === "string" || typeof message.id === "number") && isRecord(message.params) && typeof message.params.name === "string";
}
function toolResult(value: unknown): ToolResult { return parseToolResult(value); }
function stringify(message: unknown): string { return `${JSON.stringify(message)}\n`; }

export interface StdioContainedForwardResult { response: JsonRpcMessage; containment: ContainmentRunRecord; }
export type StdioContainedForward = (forwarded: ForwardedCall, signal: AbortSignal) => Promise<StdioContainedForwardResult>;
export interface StdioProxyConfig { command: string; args: string[]; cwd: string; envAllowlist?: string[]; serverId?: string; requestTimeoutMs?: number; /** Required for strict forwards. The returned signed run is verified and bound before completion. */ containedForward?: StdioContainedForward; }
export interface StdioIo { stdin: NodeJS.ReadableStream; stdout: NodeJS.WritableStream; stderr: NodeJS.WritableStream; }

/**
 * Newline-delimited MCP 2025-era stdio proxy. It emits protocol objects only to stdout.
 * A tool call enters child.stdin only after gate.intercept returns `forward`.
 */
export async function runStdioProxy(config: StdioProxyConfig, gate: InvocationGate, io: StdioIo = process): Promise<void> {
  if (!config.command || !Array.isArray(config.args)) throw new Error("A structured upstream command and args are required");
  const allowed = new Set(["PATH", "HOME", "LANG", "LC_ALL", ...(config.envAllowlist ?? [])]);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key, value]) => allowed.has(key) && value !== undefined)) as NodeJS.ProcessEnv;
  const strictContainment = gate.requiresContainment();
  // A strict proxy has no ordinary upstream process. The only strict execution
  // path is the proof-returning handler below. The child exists solely for the
  // explicit INVOCK_TEST_MODE + requireContainment=false fixture path.
  const child: ChildProcessWithoutNullStreams | undefined = strictContainment ? undefined : spawn(config.command, config.args, { cwd: config.cwd, env, shell: false, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const inFlight = new Map<string | number, ForwardedCall>();
  const controlInFlight = new Map<string | number, string>();
  const reservedIds = new Set<string | number>();
  const timeouts = new Map<string | number, NodeJS.Timeout>();
  let closed = false;
  let inputEnded = false;
  let childClosed = child === undefined;
  let pendingLines = 0;
  let resolveDone!: () => void;
  const done = new Promise<void>(resolve => { resolveDone = resolve; });
  const maybeDone = (): void => { if (inputEnded && childClosed && pendingLines === 0) resolveDone(); };
  let writeChain = Promise.resolve();
  const downstreamWrite = (message: unknown): void => { writeChain = writeChain.then(() => new Promise<void>((resolve, reject) => io.stdout.write(stringify(message), error => error ? reject(error) : resolve()))); writeChain.catch(() => { closed = true; }); };
  const upstreamWrite = (message: unknown): void => { if (!closed && child) child.stdin.write(stringify(message)); };
  const protocolError = (id: string | number | null, code: number, message: string): void => downstreamWrite({ jsonrpc: "2.0", id, error: { code, message } });
  if (child) {
    child.stderr.on("data", chunk => io.stderr.write(`[invock upstream=${config.serverId ?? "default"}] ${String(chunk).replaceAll(/(authorization|cookie|token)=\S+/gi, "$1=[REDACTED]")}`));
    child.on("error", error => { closed = true; io.stderr.write(`[invock] upstream process error: ${error.message}\n`); });
    child.on("close", code => {
      closed = true; childClosed = true;
      for (const [id, forwarded] of inFlight) { const timeout = timeouts.get(id); if (timeout) clearTimeout(timeout); gate.fail(forwarded, "UPSTREAM_PROCESS_EXIT"); }
      inFlight.clear(); timeouts.clear(); controlInFlight.clear(); reservedIds.clear();
      io.stderr.write(`[invock] upstream exited (${code ?? "signal"})\n`);
      maybeDone();
    });
  }
  const downstream = createInterface({ input: io.stdin, crlfDelay: Infinity, terminal: false });
  const upstream = child ? createInterface({ input: child.stdout, crlfDelay: Infinity, terminal: false }) : undefined;
  const executeContained = async (outcome: ForwardedCall): Promise<void> => {
    if (!config.containedForward) {
      const rejected = gate.rejectForward(outcome);
      if (outcome.request.id !== undefined && rejected.kind === "respond") downstreamWrite(rejected.response);
      return;
    }
    const controller = new AbortController();
    let timeout: NodeJS.Timeout | undefined;
    let attached = outcome;
    try {
      const timeoutFailure = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => { controller.abort(); reject(new Error("UPSTREAM_TIMEOUT")); }, config.requestTimeoutMs ?? 30_000);
        timeout.unref();
      });
      const execution = await Promise.race([config.containedForward(outcome, controller.signal), timeoutFailure]);
      attached = gate.attachContainmentRun(outcome, execution.containment);
      if (!isJsonRpcResponse(execution.response)) throw new Error("UPSTREAM_MALFORMED_RESPONSE");
      if (outcome.request.id !== undefined && execution.response.id !== outcome.request.id) throw new Error("UPSTREAM_RESPONSE_ID_MISMATCH");
      if (outcome.request.id === undefined && execution.response.id !== null) throw new Error("UPSTREAM_RESPONSE_ID_MISMATCH");
      const result = toolResult(execution.response.result);
      if (outcome.request.id === undefined) { gate.finishNotification(attached); return; }
      const receiptId = gate.finish(attached, result);
      if (isRecord(execution.response.result)) execution.response.result._meta = { ...(isRecord(execution.response.result._meta) ? execution.response.result._meta : {}), "io.invock/receipt-id": receiptId };
      downstreamWrite(execution.response);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Containment execution failed";
      if (attached.containmentRequired) gate.rejectForward(attached, message === "UPSTREAM_TIMEOUT" ? "CONTAINMENT_TIMEOUT" : "CONTAINMENT_EXECUTION_FAILED");
      else gate.fail(attached, message);
      if (outcome.request.id !== undefined) protocolError(outcome.request.id, -32050, message === "UPSTREAM_TIMEOUT" ? "Contained execution timed out" : "Contained execution failed");
      else io.stderr.write(`[invock] contained notification failed: ${message}\n`);
    } finally { if (timeout) clearTimeout(timeout); }
  };
  downstream.on("line", line => {
    pendingLines += 1;
    const task = (async () => {
    if (closed) return;
    let message: JsonRpcObject;
    try { message = parseFrame(line); } catch (error) { protocolError(null, -32700, error instanceof Error ? error.message : "Parse error"); return; }
    if (message.method === "tools/call" && !isToolCall(message)) { if (message.id === undefined) io.stderr.write("[invock] invalid tools/call notification rejected\n"); else protocolError(typeof message.id === "string" || typeof message.id === "number" ? message.id : null, -32602, "Invalid tools/call parameters"); return; }
    if (!isToolCall(message)) {
      if (message.method && ["initialize", "initialized", "notifications/initialized", "tools/list", "ping", "logging/setLevel", "resources/list", "prompts/list"].includes(message.method)) {
        if (message.id !== undefined && (reservedIds.has(message.id) || inFlight.has(message.id) || controlInFlight.has(message.id))) { protocolError(message.id, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID"); return; }
        if (strictContainment) { protocolError(typeof message.id === "string" || typeof message.id === "number" ? message.id : null, -32051, "CONTAINMENT_REQUIRED_FOR_CONTROL_PLANE"); return; }
        if (message.id !== undefined) controlInFlight.set(message.id, message.method);
        upstreamWrite(message);
      }
      else protocolError(typeof message.id === "string" || typeof message.id === "number" ? message.id : null, -32601, "Method is outside the supported mediation boundary");
      return;
    }
    if (message.id !== undefined && (reservedIds.has(message.id) || inFlight.has(message.id) || controlInFlight.has(message.id))) { protocolError(message.id, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID"); return; }
    if (message.id !== undefined) reservedIds.add(message.id);
    const outcome = await gate.authorizeInvocation(message);
    if (outcome.kind === "respond") { if (message.id !== undefined) reservedIds.delete(message.id); downstreamWrite(outcome.response); return; }
    if (outcome.kind === "notification") { if (outcome.request) upstreamWrite(outcome.request); if (message.id !== undefined) reservedIds.delete(message.id); return; }
    if (outcome.containmentRequired) {
      if (message.id !== undefined) reservedIds.delete(message.id);
      await executeContained(outcome);
      return;
    }
    if (outcome.request.id === undefined) { upstreamWrite(outcome.request); gate.finishNotification(outcome); return; }
    reservedIds.delete(outcome.request.id);
    inFlight.set(outcome.request.id, outcome);
    const id = outcome.request.id; const timeout = setTimeout(() => { const forwarded = inFlight.get(id); inFlight.delete(id); timeouts.delete(id); if (forwarded) { gate.fail(forwarded, "UPSTREAM_TIMEOUT"); protocolError(id, -32050, "Upstream request timed out"); } child?.kill("SIGTERM"); const kill = setTimeout(() => child?.kill("SIGKILL"), 1_000); kill.unref(); }, config.requestTimeoutMs ?? 30_000); timeout.unref(); timeouts.set(id, timeout);
    upstreamWrite(outcome.request);
  })().catch(error => protocolError(null, -32050, error instanceof Error ? error.message : "Internal gateway failure"));
    void task.finally(() => { pendingLines -= 1; maybeDone(); });
  });
  upstream?.on("line", line => { void (async () => {
    let message: JsonRpcObject;
    try { message = parseFrame(line); } catch (error) { closed = true; child?.kill("SIGTERM"); io.stderr.write(`[invock] upstream framing violation: ${error instanceof Error ? error.message : "unknown"}\n`); return; }
    if ((typeof message.id === "string" || typeof message.id === "number") && inFlight.has(message.id)) {
      const forwarded = inFlight.get(message.id)!; inFlight.delete(message.id); const timeout = timeouts.get(message.id); if (timeout) clearTimeout(timeout); timeouts.delete(message.id);
      try {
        if (!isJsonRpcResponse(message)) throw new Error("UPSTREAM_MALFORMED_RESPONSE");
        const result = toolResult(message.result); const receiptId = gate.finish(forwarded, result); if (isRecord(message.result)) { message.result._meta = { ...(isRecord(message.result._meta) ? message.result._meta : {}), "io.invock/receipt-id": receiptId }; }
        downstreamWrite(message);
      } catch (error) { gate.fail(forwarded, error instanceof Error ? error.message : "Malformed upstream result"); protocolError(message.id, -32050, "Upstream malformed response"); }
      return;
    }
    if ((typeof message.id === "string" || typeof message.id === "number") && controlInFlight.has(message.id)) {
      const method = controlInFlight.get(message.id)!; controlInFlight.delete(message.id);
      if (!isJsonRpcResponse(message)) { protocolError(message.id, -32050, "Upstream malformed response"); return; }
      if (method === "tools/list" && isRecord(message.result)) gate.observeToolsList(message.result);
      downstreamWrite(message); return;
    }
    if ((message.result !== undefined || message.error !== undefined) && typeof message.id !== "string" && typeof message.id !== "number") { io.stderr.write("[invock] upstream response without a correlatable id rejected\n"); return; }
    if (typeof message.id === "string" || typeof message.id === "number") io.stderr.write(`[invock] upstream response correlation rejected for id ${String(message.id)}\n`);
    else downstreamWrite(message);
  })().catch(error => { closed = true; io.stderr.write(`[invock] upstream processing failure: ${error instanceof Error ? error.message : "unknown"}\n`); }); });
  io.stdin.on("end", () => {
    inputEnded = true;
    if (child) { child.stdin.end(); const term = setTimeout(() => child.kill("SIGTERM"), 1_000); term.unref(); const kill = setTimeout(() => child.kill("SIGKILL"), 2_000); kill.unref(); child.once("close", () => { clearTimeout(term); clearTimeout(kill); }); }
    maybeDone();
  });
  await done;
}
