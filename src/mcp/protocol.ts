import type { ToolCallRequest, ToolResult } from "../core/types.js";
import { negotiateProfile } from "../protocol/profile.js";

export type McpProtocolEra =
  | { kind: "stable-2025"; negotiatedVersion: "2025-11-25" | "2025-06-18" | "2025-03-26"; stateModel: "session" }
  | { kind: "candidate-2026"; negotiatedVersion: "2026-07-28"; stateModel: "request" };

export interface JsonRpcRequest { jsonrpc: "2.0"; id: string | number; method: string; params?: Record<string, unknown>; }
export interface JsonRpcResponse { jsonrpc: "2.0"; id: string | number | null; result?: unknown; error?: { code: number; message: string; data?: unknown }; }
export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse | { jsonrpc: "2.0"; method: string; params?: Record<string, unknown> };

const REQUEST_KEYS = new Set(["jsonrpc", "id", "method", "params"]);
const RESPONSE_KEYS = new Set(["jsonrpc", "id", "result", "error"]);

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON-RPC message must be an object");
  return value as Record<string, unknown>;
}

export function isJsonRpcResponse(value: unknown): value is JsonRpcResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.jsonrpc !== "2.0" || "method" in record) return false;
  if (Object.keys(record).some(key => !RESPONSE_KEYS.has(key))) return false;
  if (typeof record.id !== "string" && typeof record.id !== "number" && record.id !== null) return false;
  const hasResult = Object.prototype.hasOwnProperty.call(record, "result");
  const hasError = Object.prototype.hasOwnProperty.call(record, "error");
  if (hasResult === hasError) return false;
  if (hasError) {
    const error = record.error;
    if (error === null || typeof error !== "object" || Array.isArray(error)) return false;
    const errorRecord = error as Record<string, unknown>;
    if (Object.keys(errorRecord).some(key => !new Set(["code", "message", "data"]).has(key))) return false;
    if (!Number.isInteger(errorRecord.code) || typeof errorRecord.message !== "string") return false;
  }
  return true;
}

export function negotiateEra(version: string | undefined, candidateEnabled = false): McpProtocolEra {
  const requestedVersion = version ?? "2025-11-25";
  if (requestedVersion === "2026-07-28" && !candidateEnabled) throw new Error("MCP 2026-07-28 compatibility is disabled");
  const negotiated = negotiateProfile({ clientVersions: [requestedVersion], serverVersions: [requestedVersion], requestedVersion });
  if (!negotiated.ok || !negotiated.profile) throw new Error(`Unsupported MCP protocol version: ${version ?? requestedVersion}`);
  return negotiated.profile.generation === "candidate-2026"
    ? { kind: "candidate-2026", negotiatedVersion: "2026-07-28", stateModel: "request" }
    : { kind: "stable-2025", negotiatedVersion: negotiated.profile.version as "2025-11-25" | "2025-06-18" | "2025-03-26", stateModel: "session" };
}

/** Strict single-object JSON-RPC decoder shared by stdio and Streamable HTTP. */
export function parseJsonRpc(value: unknown): JsonRpcMessage {
  const message = object(value);
  if (message.jsonrpc !== "2.0") throw new Error("JSON-RPC version must be 2.0");
  if (typeof message.method === "string") {
    if (Object.keys(message).some(key => !REQUEST_KEYS.has(key))) throw new Error("JSON-RPC request contains unsupported fields");
    if (message.params !== undefined && (message.params === null || typeof message.params !== "object" || Array.isArray(message.params))) throw new Error("JSON-RPC params must be an object");
    if (message.id !== undefined && typeof message.id !== "string" && typeof message.id !== "number") throw new Error("JSON-RPC request id must be string or number");
    return message as unknown as JsonRpcMessage;
  }
  if (!isJsonRpcResponse(message)) throw new Error("Invalid JSON-RPC response");
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

export function parseToolResult(value: unknown): ToolResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Upstream tools/call result is malformed");
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.content) || record.content.some(item => item === null || typeof item !== "object" || Array.isArray(item) || (item as Record<string, unknown>).type !== "text" || typeof (item as Record<string, unknown>).text !== "string")) {
    throw new Error("Upstream tools/call result is malformed");
  }
  if (record.structuredContent !== undefined && (record.structuredContent === null || typeof record.structuredContent !== "object" || Array.isArray(record.structuredContent))) throw new Error("Upstream tools/call structured content is malformed");
  return value as ToolResult;
}
