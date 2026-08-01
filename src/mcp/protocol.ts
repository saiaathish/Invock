import type { ToolCallRequest, ToolResult } from "../core/types.js";

export type McpProtocolEra =
  | { kind: "stable-2025"; negotiatedVersion: "2025-11-25" | "2025-06-18" | "2025-03-26"; stateModel: "session" }
  | { kind: "candidate-2026"; negotiatedVersion: "2026-07-28"; stateModel: "request" };

export interface JsonRpcRequest { jsonrpc: "2.0"; id: string | number; method: string; params?: Record<string, unknown>; }
export interface JsonRpcResponse { jsonrpc: "2.0"; id: string | number | null; result?: unknown; error?: { code: number; message: string; data?: unknown }; }
export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse | { jsonrpc: "2.0"; method: string; params?: Record<string, unknown> };

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON-RPC message must be an object");
  return value as Record<string, unknown>;
}

export function negotiateEra(version: string | undefined, candidateEnabled = false): McpProtocolEra {
  if (version === "2026-07-28") {
    if (!candidateEnabled) throw new Error("MCP 2026-07-28 compatibility is disabled");
    return { kind: "candidate-2026", negotiatedVersion: "2026-07-28", stateModel: "request" };
  }
  if (version === undefined || version === "2025-11-25" || version === "2025-06-18" || version === "2025-03-26") return { kind: "stable-2025", negotiatedVersion: version ?? "2025-11-25", stateModel: "session" };
  throw new Error(`Unsupported MCP protocol version: ${version}`);
}

/** Strict single-object JSON-RPC decoder shared by stdio and Streamable HTTP. */
export function parseJsonRpc(value: unknown): JsonRpcMessage {
  const message = object(value);
  if (message.jsonrpc !== "2.0") throw new Error("JSON-RPC version must be 2.0");
  if (typeof message.method === "string") {
    if (message.params !== undefined && (message.params === null || typeof message.params !== "object" || Array.isArray(message.params))) throw new Error("JSON-RPC params must be an object");
    if (message.id !== undefined && typeof message.id !== "string" && typeof message.id !== "number") throw new Error("JSON-RPC request id must be string or number");
    return message as unknown as JsonRpcMessage;
  }
  if ((typeof message.id !== "string" && typeof message.id !== "number" && message.id !== null) || (message.result === undefined && message.error === undefined)) throw new Error("Invalid JSON-RPC response");
  return message as unknown as JsonRpcMessage;
}

export function isToolCall(message: JsonRpcMessage): message is ToolCallRequest {
  if (!("method" in message) || message.method !== "tools/call") return false;
  const params = message.params;
  const id = "id" in message ? message.id : undefined;
  return (id === undefined || typeof id === "string" || typeof id === "number") && typeof params?.name === "string";
}

export function isControlPlane(message: JsonRpcMessage): boolean {
  return "method" in message && ["initialize", "initialized", "notifications/initialized", "tools/list", "ping", "logging/setLevel", "resources/list", "prompts/list"].includes(message.method);
}

export function protocolError(id: string | number | null, code: number, message: string, data?: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

export function deniedToolCall(id: string | number, result: ToolResult): JsonRpcResponse { return { jsonrpc: "2.0", id, result }; }