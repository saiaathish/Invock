import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import type { InvocationGate, ForwardedCall } from "./engine.js";
import type { ToolCallRequest, ToolResult } from "../core/types.js";

const MAX_FRAME_BYTES = 2 * 1024 * 1024;

interface JsonRpcObject { jsonrpc: "2.0"; id?: string | number; method?: string; params?: unknown; result?: unknown; error?: unknown; }
function isRecord(value: unknown): value is Record<string, unknown> { return value !== null && !Array.isArray(value) && typeof value === "object"; }
function parseFrame(line: string): JsonRpcObject {
  if (Buffer.byteLength(line) > MAX_FRAME_BYTES) throw new Error("MCP frame exceeds 2 MiB");
  if (line.includes("\0")) throw new Error("MCP frame contains NUL");
  const parsed: unknown = JSON.parse(line);
  if (!isRecord(parsed) || parsed.jsonrpc !== "2.0" || Array.isArray(parsed)) throw new Error("Invalid JSON-RPC 2.0 object");
  return parsed as unknown as JsonRpcObject;
}
function isToolCall(message: JsonRpcObject): message is ToolCallRequest {
  return message.method === "tools/call" && (message.id === undefined || typeof message.id === "string" || typeof message.id === "number") && isRecord(message.params) && typeof message.params.name === "string";
}
function toolResult(value: unknown): ToolResult {
  if (!isRecord(value) || !Array.isArray(value.content) || value.content.some(item => !isRecord(item) || item.type !== "text" || typeof item.text !== "string")) throw new Error("Upstream tools/call result is malformed");
  return value as unknown as ToolResult;
}
function stringify(message: unknown): string { return `${JSON.stringify(message)}\n`; }

export interface StdioProxyConfig { command: string; args: string[]; cwd: string; envAllowlist?: string[]; serverId?: string; requestTimeoutMs?: number; }
export interface StdioIo { stdin: NodeJS.ReadableStream; stdout: NodeJS.WritableStream; stderr: NodeJS.WritableStream; }

/**
 * Newline-delimited MCP 2025-era stdio proxy. It emits protocol objects only to stdout.
 * A tool call enters child.stdin only after gate.intercept returns `forward`.
 */
export async function runStdioProxy(config: StdioProxyConfig, gate: InvocationGate, io: StdioIo = process): Promise<void> {
  if (!config.command || !Array.isArray(config.args)) throw new Error("A structured upstream command and args are required");
  const allowed = new Set(["PATH", "HOME", "LANG", "LC_ALL", ...(config.envAllowlist ?? [])]);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key, value]) => allowed.has(key) && value !== undefined)) as NodeJS.ProcessEnv;
  const child: ChildProcessWithoutNullStreams = spawn(config.command, config.args, { cwd: config.cwd, env, shell: false, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const inFlight = new Map<string | number, ForwardedCall>();
  const controlInFlight = new Map<string | number, string>();
  const reservedIds = new Set<string | number>();
  const timeouts = new Map<string | number, NodeJS.Timeout>();
  let closed = false;
  let writeChain = Promise.resolve();
  const downstreamWrite = (message: unknown): void => { writeChain = writeChain.then(() => new Promise<void>((resolve, reject) => io.stdout.write(stringify(message), error => error ? reject(error) : resolve()))); writeChain.catch(() => { closed = true; }); };
  const upstreamWrite = (message: unknown): void => { if (!closed) child.stdin.write(stringify(message)); };
  const protocolError = (id: string | number | null, code: number, message: string): void => downstreamWrite({ jsonrpc: "2.0", id, error: { code, message } });
  child.stderr.on("data", chunk => io.stderr.write(`[invock upstream=${config.serverId ?? "default"}] ${String(chunk).replaceAll(/(authorization|cookie|token)=\S+/gi, "$1=[REDACTED]")}`));
  child.on("error", error => { closed = true; io.stderr.write(`[invock] upstream process error: ${error.message}\n`); });
  child.on("close", code => {
    closed = true;
    for (const [id, forwarded] of inFlight) { const timeout = timeouts.get(id); if (timeout) clearTimeout(timeout); gate.fail(forwarded, "UPSTREAM_PROCESS_EXIT"); }
    inFlight.clear(); timeouts.clear(); controlInFlight.clear(); reservedIds.clear();
    io.stderr.write(`[invock] upstream exited (${code ?? "signal"})\n`);
  });
  const downstream = createInterface({ input: io.stdin, crlfDelay: Infinity, terminal: false });
  const upstream = createInterface({ input: child.stdout, crlfDelay: Infinity, terminal: false });
  downstream.on("line", line => { void (async () => {
    if (closed) return;
    let message: JsonRpcObject;
    try { message = parseFrame(line); } catch (error) { protocolError(null, -32700, error instanceof Error ? error.message : "Parse error"); return; }
    if (message.method === "tools/call" && !isToolCall(message)) { if (message.id === undefined) io.stderr.write("[invock] invalid tools/call notification rejected\n"); else protocolError(typeof message.id === "string" || typeof message.id === "number" ? message.id : null, -32602, "Invalid tools/call parameters"); return; }
    if (!isToolCall(message)) {
      if (message.method && ["initialize", "initialized", "notifications/initialized", "tools/list", "ping", "logging/setLevel", "resources/list", "prompts/list"].includes(message.method)) {
        if (message.id !== undefined && (reservedIds.has(message.id) || inFlight.has(message.id) || controlInFlight.has(message.id))) { protocolError(message.id, -32600, "DUPLICATE_IN_FLIGHT_REQUEST_ID"); return; }
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
    if (outcome.request.id === undefined) { upstreamWrite(outcome.request); gate.finishNotification(outcome); return; }
    reservedIds.delete(outcome.request.id);
    inFlight.set(outcome.request.id, outcome);
    const id = outcome.request.id; const timeout = setTimeout(() => { const forwarded = inFlight.get(id); inFlight.delete(id); timeouts.delete(id); if (forwarded) { gate.fail(forwarded, "UPSTREAM_TIMEOUT"); protocolError(id, -32050, "Upstream request timed out"); } }, config.requestTimeoutMs ?? 30_000); timeout.unref(); timeouts.set(id, timeout);
    upstreamWrite(outcome.request);
  })().catch(error => protocolError(null, -32050, error instanceof Error ? error.message : "Internal gateway failure")); });
  upstream.on("line", line => { void (async () => {
    let message: JsonRpcObject;
    try { message = parseFrame(line); } catch (error) { closed = true; child.kill("SIGTERM"); io.stderr.write(`[invock] upstream framing violation: ${error instanceof Error ? error.message : "unknown"}\n`); return; }
    if ((typeof message.id === "string" || typeof message.id === "number") && inFlight.has(message.id)) {
      const forwarded = inFlight.get(message.id)!; inFlight.delete(message.id); const timeout = timeouts.get(message.id); if (timeout) clearTimeout(timeout); timeouts.delete(message.id);
      try { const result = toolResult(message.result); const receiptId = gate.finish(forwarded, result); if (isRecord(message.result)) { message.result._meta = { ...(isRecord(message.result._meta) ? message.result._meta : {}), "io.invock/receipt-id": receiptId }; } }
      catch (error) { gate.fail(forwarded, error instanceof Error ? error.message : "Malformed upstream result"); }
      downstreamWrite(message);
      return;
    }
    if ((typeof message.id === "string" || typeof message.id === "number") && controlInFlight.has(message.id)) {
      const method = controlInFlight.get(message.id)!; controlInFlight.delete(message.id);
      if (method === "tools/list" && isRecord(message.result)) gate.observeToolsList(message.result);
      downstreamWrite(message); return;
    }
    if ((message.result !== undefined || message.error !== undefined) && typeof message.id !== "string" && typeof message.id !== "number") { io.stderr.write("[invock] upstream response without a correlatable id rejected\n"); return; }
    if (typeof message.id === "string" || typeof message.id === "number") io.stderr.write(`[invock] upstream response correlation rejected for id ${String(message.id)}\n`);
    else downstreamWrite(message);
  })().catch(error => { closed = true; io.stderr.write(`[invock] upstream processing failure: ${error instanceof Error ? error.message : "unknown"}\n`); }); });
  io.stdin.on("end", () => { child.stdin.end(); const term = setTimeout(() => child.kill("SIGTERM"), 1_000); term.unref(); const kill = setTimeout(() => child.kill("SIGKILL"), 2_000); kill.unref(); child.once("close", () => { clearTimeout(term); clearTimeout(kill); }); });
  await new Promise<void>(resolve => child.once("close", () => resolve()));
}