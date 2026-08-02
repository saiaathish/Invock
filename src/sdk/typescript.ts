export type DecisionVerdict = "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED";

export interface InvockClientOptions {
  readonly endpoint: string;
  readonly token: string;
  readonly fetchImpl?: typeof fetch;
}

export interface AuthorizeInput {
  readonly agent?: string;
  readonly projectId?: string;
  readonly tool: string;
  readonly arguments: Record<string, unknown>;
  readonly intentCapsule?: unknown;
  readonly authorityBinding?: unknown;
  readonly capabilityLeases?: readonly unknown[];
  readonly sessionId?: string;
}

export interface DecisionResponse {
  readonly verdict: DecisionVerdict;
  readonly reasonCodes: readonly string[];
  readonly receiptId?: string;
  readonly approvalId?: string;
  readonly authorizedArguments?: Record<string, unknown>;
  readonly containmentRequired?: boolean;
}

export interface ExecutionResult {
  readonly content: ReadonlyArray<{ readonly type: "text"; readonly text: string }>;
  readonly structuredContent?: Record<string, unknown>;
  readonly isError?: boolean;
}

export interface ExecutionResponse extends DecisionResponse {
  readonly result?: ExecutionResult;
}

export class InvockHttpError extends Error {
  public readonly status: number;
  public readonly body: unknown;

  public constructor(status: number, body: unknown) {
    super(`Invock authorization request failed with HTTP ${status}`);
    this.name = "InvockHttpError";
    this.status = status;
    this.body = body;
  }
}

export interface HealthResponse {
  readonly status: string;
}

const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_EXECUTION_RESULT_BYTES = 128 * 1024;
const MAX_RESULT_CONTENT_ITEMS = 128;
const MAX_RESULT_TEXT_BYTES = 64 * 1024;
const MAX_RESULT_DEPTH = 16;
const MAX_RESULT_NODES = 4096;

function normalizeEndpoint(endpoint: string, path: string): string {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error("Invock endpoint must be a valid HTTP URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Invock endpoint must use http or https");
  }
  const basePath = parsed.pathname.replace(/\/+$/u, "");
  const suffix = path.replace(/^\//u, "");
  parsed.pathname = `${basePath}/${suffix}`.replace(/\/+/gu, "/");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedJson(value: unknown, depth = 0, state = { nodes: 0 }): boolean {
  if (depth > MAX_RESULT_DEPTH || ++state.nodes > MAX_RESULT_NODES) return false;
  if (value === null || typeof value === "boolean" || typeof value === "number") return typeof value !== "number" || Number.isFinite(value);
  if (typeof value === "string") return new TextEncoder().encode(value).byteLength <= MAX_RESULT_TEXT_BYTES;
  if (Array.isArray(value)) return value.length <= MAX_RESULT_CONTENT_ITEMS && value.every(item => boundedJson(item, depth + 1, state));
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.length <= MAX_RESULT_NODES && keys.every(key => key.length <= 512 && boundedJson(value[key], depth + 1, state));
}

function parseExecutionResult(value: unknown): ExecutionResult {
  if (!isRecord(value) || !Array.isArray(value.content) || value.content.length === 0 || value.content.length > MAX_RESULT_CONTENT_ITEMS) {
    throw new Error("Invock execution response has malformed result");
  }
  const content = value.content.map(item => {
    if (!isRecord(item) || item.type !== "text" || typeof item.text !== "string" || Object.keys(item).some(key => key !== "type" && key !== "text") || new TextEncoder().encode(item.text).byteLength > MAX_RESULT_TEXT_BYTES) {
      throw new Error("Invock execution response has malformed result content");
    }
    return { type: "text" as const, text: item.text };
  });
  if (value.structuredContent !== undefined && (!isRecord(value.structuredContent) || !boundedJson(value.structuredContent))) throw new Error("Invock execution response has malformed structuredContent");
  if (value.isError !== undefined && typeof value.isError !== "boolean") throw new Error("Invock execution response has malformed isError");
  const result: ExecutionResult = { content, ...(isRecord(value.structuredContent) ? { structuredContent: { ...value.structuredContent } } : {}), ...(typeof value.isError === "boolean" ? { isError: value.isError } : {}) };
  if (new TextEncoder().encode(JSON.stringify(result)).byteLength > MAX_EXECUTION_RESULT_BYTES) throw new Error("Invock execution result exceeds 128 KiB");
  return result;
}

async function readJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && Number.isFinite(Number(declaredLength)) && Number(declaredLength) > MAX_RESPONSE_BYTES) {
    throw new Error("Invock response exceeds 256 KiB");
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) throw new Error("Invock response exceeds 256 KiB");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("Invock response was not valid JSON");
  }
}

function parseDecision(value: unknown): DecisionResponse {
  if (!isRecord(value) || (value.verdict !== "ALLOW" && value.verdict !== "BLOCK" && value.verdict !== "APPROVAL_REQUIRED")) {
    throw new Error("Invock response has a malformed verdict");
  }
  if (!Array.isArray(value.reasonCodes) || value.reasonCodes.some(code => typeof code !== "string")) {
    throw new Error("Invock response has malformed reasonCodes");
  }
  if (value.receiptId !== undefined && typeof value.receiptId !== "string") throw new Error("Invock response has a malformed receiptId");
  if (value.approvalId !== undefined && typeof value.approvalId !== "string") throw new Error("Invock response has a malformed approvalId");
  if (value.authorizedArguments !== undefined && !isRecord(value.authorizedArguments)) throw new Error("Invock response has malformed authorizedArguments");
  if (value.containmentRequired !== undefined && typeof value.containmentRequired !== "boolean") throw new Error("Invock response has malformed containmentRequired");
  return {
    verdict: value.verdict,
    reasonCodes: [...value.reasonCodes],
    ...(typeof value.receiptId === "string" ? { receiptId: value.receiptId } : {}),
    ...(typeof value.approvalId === "string" ? { approvalId: value.approvalId } : {}),
    ...(isRecord(value.authorizedArguments) ? { authorizedArguments: { ...value.authorizedArguments } } : {}),
    ...(typeof value.containmentRequired === "boolean" ? { containmentRequired: value.containmentRequired } : {}),
  };
}

function parseExecution(value: unknown): ExecutionResponse {
  const decision = parseDecision(value);
  if (decision.verdict === "ALLOW") {
    if (decision.receiptId === undefined || !isRecord(value) || value.result === undefined) throw new Error("Invock execution response is missing receiptId or result");
    return { ...decision, result: parseExecutionResult(value.result) };
  }
  if (!isRecord(value) || value.result === undefined) return decision;
  return { ...decision, result: parseExecutionResult(value.result) };
}

export class InvockClient {
  private readonly endpoint: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  public constructor(options: InvockClientOptions) {
    if (options.token.length === 0) throw new Error("Invock token must not be empty");
    this.endpoint = options.endpoint;
    this.token = options.token;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  public async authorize(input: AuthorizeInput): Promise<DecisionResponse> {
    const response = await this.fetchImpl(normalizeEndpoint(this.endpoint, "/api/v1/authorize"), {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(input),
    });
    const payload = await readJson(response);
    if (!response.ok) throw new InvockHttpError(response.status, payload);
    return parseDecision(payload);
  }

  public async execute(input: AuthorizeInput): Promise<ExecutionResponse> {
    const response = await this.fetchImpl(normalizeEndpoint(this.endpoint, "/api/v1/execute"), {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(input),
    });
    const payload = await readJson(response);
    if (!response.ok) throw new InvockHttpError(response.status, payload);
    return parseExecution(payload);
  }

  public async health(): Promise<HealthResponse> {
    const response = await this.fetchImpl(normalizeEndpoint(this.endpoint, "/api/v1/health"), {
      method: "GET",
      headers: { authorization: `Bearer ${this.token}`, accept: "application/json" },
    });
    const value = await readJson(response);
    if (!response.ok) throw new InvockHttpError(response.status, value);
    if (!isRecord(value) || typeof value.status !== "string") throw new Error("Invock health response was malformed");
    return { status: value.status };
  }
}
