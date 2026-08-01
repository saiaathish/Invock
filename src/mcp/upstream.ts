import { request as httpRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import type { JsonRpcMessage, JsonRpcRequest, JsonRpcResponse } from "./protocol.js";

export interface RedirectPolicy {
  maxRedirects: number;
  allowCrossHost: boolean;
  allowedHosts?: string[];
}

export interface DnsPinner {
  pin(hostname: string): Promise<{ addresses: string[] }>;
}

export interface StreamableHttpUpstreamOptions {
  url: string;
  redirectPolicy?: RedirectPolicy;
  dnsPinner?: DnsPinner;
  connectTimeoutMs?: number;
  headerTimeoutMs?: number;
  bodyTimeoutMs?: number;
  requestTimeoutMs?: number;
  headers?: Record<string, string>;
}

interface PendingRequest {
  resolve: (message: JsonRpcMessage) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_HEADER_TIMEOUT_MS = 10_000;
const DEFAULT_BODY_TIMEOUT_MS = 30_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_REDIRECTS = 5;

function isJsonRpcResponse(value: unknown): value is JsonRpcResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.jsonrpc !== "2.0") return false;
  if (typeof record.id !== "string" && typeof record.id !== "number" && record.id !== null) return false;
  if (record.result === undefined && record.error === undefined) return false;
  return true;
}

function isJsonRpcRequest(value: unknown): value is JsonRpcRequest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.jsonrpc !== "2.0") return false;
  if (typeof record.method !== "string") return false;
  if (record.id !== undefined && typeof record.id !== "string" && typeof record.id !== "number") return false;
  return true;
}

export class StreamableHttpUpstreamClient {
  private readonly baseUrl: URL;
  private readonly redirectPolicy: RedirectPolicy;
  private readonly dnsPinner: DnsPinner | undefined;
  private readonly connectTimeoutMs: number;
  private readonly headerTimeoutMs: number;
  private readonly bodyTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly headers: Record<string, string>;
  private sessionId: string | undefined;
  private protocolVersion: string | undefined;
  private readonly pending = new Map<string | number, PendingRequest>();
  private closed = false;

  constructor(options: StreamableHttpUpstreamOptions) {
    this.baseUrl = new URL(options.url);
    this.redirectPolicy = options.redirectPolicy ?? { maxRedirects: DEFAULT_MAX_REDIRECTS, allowCrossHost: false };
    this.dnsPinner = options.dnsPinner;
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.headerTimeoutMs = options.headerTimeoutMs ?? DEFAULT_HEADER_TIMEOUT_MS;
    this.bodyTimeoutMs = options.bodyTimeoutMs ?? DEFAULT_BODY_TIMEOUT_MS;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.headers = options.headers ?? {};
  }

  get session(): string | undefined {
    return this.sessionId;
  }

  get protocol(): string | undefined {
    return this.protocolVersion;
  }

  async initialize(): Promise<{ protocolVersion: string; sessionId?: string }> {
    const response = await this.request({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "invock", version: "0.1.0" },
      },
    });
    if (!("result" in response) || response.result === undefined) {
      throw new Error("UPSTREAM_INITIALIZE_FAILED");
    }
    const result = response.result as Record<string, unknown>;
    if (typeof result.protocolVersion !== "string") {
      throw new Error("UPSTREAM_INITIALIZE_NO_PROTOCOL");
    }
    this.protocolVersion = result.protocolVersion;
    if (this.sessionId === undefined) {
      return { protocolVersion: this.protocolVersion };
    }
    return { protocolVersion: this.protocolVersion, sessionId: this.sessionId };
  }

  async request(message: JsonRpcMessage, opts: { timeoutMs?: number } = {}): Promise<JsonRpcMessage> {
    if (this.closed) throw new Error("UPSTREAM_CLOSED");
    const id = "id" in message && (typeof message.id === "string" || typeof message.id === "number") ? message.id : undefined;
    const timeoutMs = opts.timeoutMs ?? this.requestTimeoutMs;

    if (id !== undefined && this.pending.has(id)) throw new Error("DUPLICATE_REQUEST_ID");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref();

    return new Promise<JsonRpcMessage>((resolve, reject) => {
      const onTimeout = (): void => {
        if (id !== undefined) {
          const pending = this.pending.get(id);
          if (pending) {
            this.pending.delete(id);
            clearTimeout(pending.timer);
            pending.reject(new Error("UPSTREAM_REQUEST_TIMEOUT"));
          }
        } else {
          reject(new Error("UPSTREAM_REQUEST_TIMEOUT"));
        }
      };
      controller.signal.addEventListener("abort", onTimeout, { once: true });

      if (id !== undefined) {
        this.pending.set(id, { resolve, reject, timer });
      }

      this.sendPost(message, controller.signal)
        .then((response) => {
          if (id === undefined) {
            controller.signal.removeEventListener("abort", onTimeout);
            clearTimeout(timer);
            resolve(response);
            return;
          }
          if (!("id" in response) || response.id !== id) {
            const pending = this.pending.get(id);
            if (pending) {
              this.pending.delete(id);
              clearTimeout(pending.timer);
              controller.signal.removeEventListener("abort", onTimeout);
              pending.reject(new Error("UPSTREAM_RESPONSE_ID_MISMATCH"));
            }
            return;
          }
          const pending = this.pending.get(id);
          if (pending) {
            this.pending.delete(id);
            clearTimeout(pending.timer);
            controller.signal.removeEventListener("abort", onTimeout);
            pending.resolve(response);
          }
        })
        .catch((error: unknown) => {
          if (id !== undefined) {
            const pending = this.pending.get(id);
            if (pending) {
              this.pending.delete(id);
              clearTimeout(pending.timer);
              controller.signal.removeEventListener("abort", onTimeout);
              pending.reject(error instanceof Error ? error : new Error(String(error)));
            }
          } else {
            controller.signal.removeEventListener("abort", onTimeout);
            clearTimeout(timer);
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        });
    });
  }

  close(): void {
    this.closed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("UPSTREAM_CLOSED"));
    }
    this.pending.clear();
  }

  private async sendPost(message: JsonRpcMessage, signal: AbortSignal): Promise<JsonRpcMessage> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...this.headers,
    };
    if (this.sessionId !== undefined) {
      headers["mcp-session-id"] = this.sessionId;
    }

    const body = JSON.stringify(message);
    const response = await this.doRequest("POST", this.baseUrl, headers, body, signal, 0);

    const sessionHeader = response.headers["mcp-session-id"];
    if (typeof sessionHeader === "string" && sessionHeader.length > 0) {
      this.sessionId = sessionHeader;
    }

    if (response.headers["mcp-session-terminated"] !== undefined) {
      this.sessionId = undefined;
      this.protocolVersion = undefined;
    }

    const contentType = response.headers["content-type"] ?? "";
    if (contentType.includes("text/event-stream")) {
      return this.readSseResponse(response, signal);
    }

    const text = await this.readBody(response, signal);
    if (text.length === 0) {
      return { jsonrpc: "2.0", id: "id" in message && (typeof message.id === "string" || typeof message.id === "number") ? message.id : null, result: {} };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error("UPSTREAM_INVALID_JSON");
    }
    if (!isJsonRpcResponse(parsed) && !isJsonRpcRequest(parsed)) {
      throw new Error("UPSTREAM_MALFORMED_RESPONSE");
    }
    return parsed;
  }

  private async readSseResponse(response: IncomingMessage, signal: AbortSignal): Promise<JsonRpcMessage> {
    return new Promise<JsonRpcMessage>((resolve, reject) => {
      let buffer = "";
      const onData = (chunk: Buffer): void => {
        buffer += chunk.toString("utf8");
        let idx: number;
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          const eventLine = frame.split("\n").find((line) => line.startsWith("event: "));
          const dataLine = frame.split("\n").find((line) => line.startsWith("data: "));
          if (eventLine === "event: message" && dataLine !== undefined) {
            const data = dataLine.slice(6);
            try {
              const parsed = JSON.parse(data) as unknown;
              if (isJsonRpcResponse(parsed) || isJsonRpcRequest(parsed)) {
                cleanup();
                resolve(parsed);
                return;
              }
            } catch {
              // Ignore malformed frames
            }
          }
        }
      };
      const onEnd = (): void => {
        cleanup();
        reject(new Error("UPSTREAM_SSE_ENDED"));
      };
      const onError = (error: Error): void => {
        cleanup();
        reject(error);
      };
      const onAbort = (): void => {
        cleanup();
        reject(new Error("UPSTREAM_ABORTED"));
      };
      const cleanup = (): void => {
        response.removeListener("data", onData);
        response.removeListener("end", onEnd);
        response.removeListener("error", onError);
        response.removeListener("aborted", onAbort);
        signal.removeEventListener("abort", onAbort);
      };
      response.on("data", onData);
      response.once("end", onEnd);
      response.once("error", onError);
      response.once("aborted", onAbort);
      signal.addEventListener("abort", onAbort);
    });
  }

  private async readBody(response: IncomingMessage, signal: AbortSignal): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let total = 0;
      const bodyTimer = setTimeout(() => {
        cleanup();
        reject(new Error("UPSTREAM_BODY_TIMEOUT"));
      }, this.bodyTimeoutMs);
      bodyTimer.unref();

      const onData = (chunk: Buffer): void => {
        total += chunk.length;
        if (total > 2 * 1024 * 1024) {
          cleanup();
          reject(new Error("UPSTREAM_BODY_TOO_LARGE"));
          return;
        }
        chunks.push(chunk);
      };
      const onEnd = (): void => {
        cleanup();
        resolve(Buffer.concat(chunks).toString("utf8"));
      };
      const onError = (error: Error): void => {
        cleanup();
        reject(error);
      };
      const onAbort = (): void => {
        cleanup();
        reject(new Error("UPSTREAM_ABORTED"));
      };
      const cleanup = (): void => {
        clearTimeout(bodyTimer);
        response.removeListener("data", onData);
        response.removeListener("end", onEnd);
        response.removeListener("error", onError);
        response.removeListener("aborted", onAbort);
        signal.removeEventListener("abort", onAbort);
      };
      response.on("data", onData);
      response.once("end", onEnd);
      response.once("error", onError);
      response.once("aborted", onAbort);
      signal.addEventListener("abort", onAbort);
    });
  }

  private async doRequest(
    method: string,
    url: URL,
    headers: Record<string, string>,
    body: string | undefined,
    signal: AbortSignal,
    redirectCount: number,
  ): Promise<IncomingMessage> {
    if (redirectCount > this.redirectPolicy.maxRedirects) {
      throw new Error("UPSTREAM_TOO_MANY_REDIRECTS");
    }

    const controller = new AbortController();
    const onOuterAbort = (): void => controller.abort();
    signal.addEventListener("abort", onOuterAbort);

    const connectTimer = setTimeout(() => controller.abort(), this.connectTimeoutMs);
    connectTimer.unref();
    const headerTimer = setTimeout(() => controller.abort(), this.headerTimeoutMs);
    headerTimer.unref();

    const requestOptions: RequestOptions = {
      method,
      hostname: url.hostname,
      port: url.port === "" ? undefined : Number(url.port),
      path: `${url.pathname}${url.search}`,
      headers,
      signal: controller.signal,
    };

    if (url.protocol === "https:") {
      requestOptions.port = url.port === "" ? 443 : Number(url.port);
    }

    let pinnedAddress: string | undefined;
    if (this.dnsPinner !== undefined) {
      const pinned = await this.dnsPinner.pin(url.hostname);
      if (pinned.addresses.length === 0) throw new Error("UPSTREAM_DNS_PIN_EMPTY");
      pinnedAddress = pinned.addresses[0];
    }

    const doSend = (): Promise<IncomingMessage> => {
      return new Promise<IncomingMessage>((resolve, reject) => {
        const send = url.protocol === "https:" ? httpsRequest : httpRequest;
        const reqOptions: RequestOptions = pinnedAddress === undefined
          ? requestOptions
          : {
              ...requestOptions,
              hostname: pinnedAddress,
              ...(url.protocol === "https:" ? { servername: url.hostname } : {}),
            };
        const req = send(reqOptions, (res) => {
          clearTimeout(connectTimer);
          clearTimeout(headerTimer);
          resolve(res);
        });
        req.once("error", (error) => {
          clearTimeout(connectTimer);
          clearTimeout(headerTimer);
          reject(error);
        });
        if (body !== undefined) {
          req.write(body);
        }
        req.end();
      });
    };

    let response: IncomingMessage;
    try {
      response = await doSend();
    } catch (error) {
      signal.removeEventListener("abort", onOuterAbort);
      clearTimeout(connectTimer);
      clearTimeout(headerTimer);
      throw error;
    }

    if (response.statusCode !== undefined && response.statusCode >= 300 && response.statusCode < 400) {
      const location = response.headers.location;
      response.resume();
      signal.removeEventListener("abort", onOuterAbort);
      clearTimeout(connectTimer);
      clearTimeout(headerTimer);
      if (typeof location !== "string" || location.length === 0) {
        throw new Error("UPSTREAM_REDIRECT_NO_LOCATION");
      }
      const nextUrl = new URL(location, url);
      if (nextUrl.hostname !== url.hostname && !this.redirectPolicy.allowCrossHost) {
        throw new Error("UPSTREAM_CROSS_HOST_REDIRECT_DENIED");
      }
      if (this.redirectPolicy.allowedHosts !== undefined && !this.redirectPolicy.allowedHosts.includes(nextUrl.hostname)) {
        throw new Error("UPSTREAM_REDIRECT_HOST_NOT_ALLOWED");
      }
      return this.doRequest(method, nextUrl, headers, body, signal, redirectCount + 1);
    }

    signal.removeEventListener("abort", onOuterAbort);
    clearTimeout(connectTimer);
    clearTimeout(headerTimer);
    return response;
  }
}
