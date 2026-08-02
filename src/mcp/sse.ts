import type { IncomingMessage, ServerResponse } from "node:http";
import type { JsonRpcMessage } from "./protocol.js";

export interface SseSession {
  readonly id: string;
  readonly response: ServerResponse;
  readonly createdAt: number;
  lastActivity: number;
  closed: boolean;
}

interface InternalSession extends SseSession {
  queue: string[];
  heartbeatTimer: NodeJS.Timeout;
  idleTimer: NodeJS.Timeout;
  pumping: boolean;
}

export interface SseSessionManagerOptions {
  idleTimeoutMs?: number;
  heartbeatMs?: number;
  maxSessions?: number;
  maxQueueLength?: number;
}

export interface SseEndpointOptions {
  postUrl: string;
  idleTimeoutMs?: number;
  heartbeatMs?: number;
}

const DEFAULT_IDLE_TIMEOUT_MS = 300_000;
const DEFAULT_HEARTBEAT_MS = 15_000;
const DEFAULT_MAX_SESSIONS = 64;
const DEFAULT_MAX_QUEUE_LENGTH = 1024;

function sseFrame(event: string, data: string): string {
  return `event: ${event}\ndata: ${data}\n\n`;
}

export class SseSessionManager {
  private readonly sessions = new Map<string, InternalSession>();
  private readonly idleTimeoutMs: number;
  private readonly heartbeatMs: number;
  private readonly maxSessions: number;
  private readonly maxQueueLength: number;

  constructor(options: SseSessionManagerOptions = {}) {
    this.idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.heartbeatMs = options.heartbeatMs ?? DEFAULT_HEARTBEAT_MS;
    this.maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
    this.maxQueueLength = options.maxQueueLength ?? DEFAULT_MAX_QUEUE_LENGTH;
  }

  get size(): number {
    return this.sessions.size;
  }

  createSession(response: ServerResponse, sessionId: string, options: { idleTimeoutMs?: number; heartbeatMs?: number } = {}): SseSession {
    if (this.sessions.has(sessionId)) {
      throw new Error("SSE_SESSION_EXISTS");
    }
    if (this.sessions.size >= this.maxSessions) {
      throw new Error("SSE_SESSION_LIMIT_REACHED");
    }
    const now = Date.now();
    const session: InternalSession = {
      id: sessionId,
      response,
      createdAt: now,
      lastActivity: now,
      closed: false,
      queue: [],
      heartbeatTimer: setInterval(() => this.heartbeat(sessionId), options.heartbeatMs ?? this.heartbeatMs),
      idleTimer: setTimeout(() => this.closeSession(sessionId), options.idleTimeoutMs ?? this.idleTimeoutMs),
      pumping: false,
    };
    session.heartbeatTimer.unref();
    session.idleTimer.unref();
    this.sessions.set(sessionId, session);
    return session;
  }

  getSession(id: string): SseSession | undefined {
    return this.sessions.get(id);
  }

  closeSession(id: string): void {
    const session = this.sessions.get(id);
    if (!session) return;
    this.sessions.delete(id);
    session.closed = true;
    clearInterval(session.heartbeatTimer);
    clearTimeout(session.idleTimer);
    try {
      if (!session.response.writableEnded) {
        session.response.end();
      }
    } catch {
      // Ignore errors on close
    }
  }

  enqueue(sessionId: string, message: JsonRpcMessage): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.closed) return false;
    if (session.queue.length >= this.maxQueueLength) {
      this.closeSession(sessionId);
      return false;
    }
    session.lastActivity = Date.now();
    clearTimeout(session.idleTimer);
    session.idleTimer = setTimeout(() => this.closeSession(sessionId), this.idleTimeoutMs);
    session.idleTimer.unref();
    session.queue.push(sseFrame("message", JSON.stringify(message)));
    this.pump(session);
    return true;
  }

  heartbeat(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.closed) return;
    if (session.queue.length >= this.maxQueueLength) {
      this.closeSession(sessionId);
      return;
    }
    session.queue.push(": ping\n\n");
    this.pump(session);
  }

  closeAll(): void {
    for (const id of [...this.sessions.keys()]) {
      this.closeSession(id);
    }
  }

  private pump(session: InternalSession): void {
    if (session.pumping) return;
    session.pumping = true;

    const processQueue = async (): Promise<void> => {
      while (session.queue.length > 0 && !session.closed) {
        const frame = session.queue.shift();
        if (frame === undefined) break;
        const ok = session.response.write(frame);
        if (!ok) {
          await new Promise<void>((resolve) => {
            const onDrain = (): void => { cleanup(); resolve(); };
            const onClose = (): void => { cleanup(); resolve(); };
            const cleanup = (): void => {
              session.response.removeListener("drain", onDrain);
              session.response.removeListener("close", onClose);
            };
            session.response.once("drain", onDrain);
            session.response.once("close", onClose);
          });
        }
      }
    };

    processQueue()
      .catch(() => {
        this.closeSession(session.id);
      })
      .finally(() => {
        session.pumping = false;
      });
  }
}

export function startSseEndpoint(
  request: IncomingMessage,
  response: ServerResponse,
  sessionId: string,
  manager: SseSessionManager,
  options: SseEndpointOptions,
): void {
  if (manager.getSession(sessionId)) {
    response.writeHead(409, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "SESSION_ALREADY_EXISTS" } }));
    return;
  }

  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-store",
    "connection": "keep-alive",
    "x-accel-buffering": "no",
  });

  let session: SseSession;
  try {
    const sessionOpts: { idleTimeoutMs?: number; heartbeatMs?: number } = {};
    if (options.idleTimeoutMs !== undefined) sessionOpts.idleTimeoutMs = options.idleTimeoutMs;
    if (options.heartbeatMs !== undefined) sessionOpts.heartbeatMs = options.heartbeatMs;
    session = manager.createSession(response, sessionId, sessionOpts);
  } catch {
    response.end();
    return;
  }

  // Register the session before emitting the first frame so a fast peer can
  // never observe an endpoint event from a response that the manager does not
  // yet own.
  response.write(sseFrame("endpoint", options.postUrl));

  const onClose = (): void => {
    manager.closeSession(session.id);
  };
  request.once("close", onClose);
  request.once("aborted", onClose);
  response.once("close", onClose);
}
