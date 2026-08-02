import { InvockClient, type AuthorizeInput, type DecisionResponse, type ExecutionResponse } from "../sdk/typescript.js";
import type { AdapterExecution, ToolExecutor } from "./types.js";

export interface OpenAIToolCall {
  readonly name: string;
  /** OpenAI function calls may provide JSON arguments as an object or string. */
  readonly arguments: Record<string, unknown> | string;
}

export interface AdapterOptions {
  readonly agent?: string;
  readonly projectId?: string;
  readonly intentCapsule?: unknown;
  readonly authorityBinding?: unknown;
  readonly capabilityLeases?: readonly unknown[];
  readonly sessionId?: string;
}

function normalizedArguments(value: OpenAIToolCall["arguments"]): Record<string, unknown> {
  const parsed: unknown = typeof value === "string" ? JSON.parse(value) : value;
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("OPENAI_TOOL_ARGUMENTS_INVALID");
  return { ...(parsed as Record<string, unknown>) };
}

export class OpenAIInvockAdapter {
  public constructor(private readonly client: InvockClient) {}

  private input(call: OpenAIToolCall, options: AdapterOptions): AuthorizeInput {
    return { tool: call.name, arguments: normalizedArguments(call.arguments), ...(options.agent !== undefined ? { agent: options.agent } : {}), ...(options.projectId !== undefined ? { projectId: options.projectId } : {}), ...(options.intentCapsule !== undefined ? { intentCapsule: options.intentCapsule } : {}), ...(options.authorityBinding !== undefined ? { authorityBinding: options.authorityBinding } : {}), ...(options.capabilityLeases !== undefined ? { capabilityLeases: options.capabilityLeases } : {}), ...(options.sessionId !== undefined ? { sessionId: options.sessionId } : {}) };
  }

  public async authorize(call: OpenAIToolCall, options: AdapterOptions = {}): Promise<DecisionResponse> {
    return this.client.authorize(this.input(call, options));
  }

  /** Execute through Invock's server-owned containment boundary. No caller callback is accepted. */
  public executeContained(call: OpenAIToolCall, options: AdapterOptions = {}): Promise<ExecutionResponse> {
    return this.client.execute(this.input(call, options));
  }

  /** Authorize before invoking the framework's upstream tool executor. */
  public async execute<T>(call: OpenAIToolCall, forward: ToolExecutor<T>, options: AdapterOptions = {}): Promise<AdapterExecution<T>> {
    const decision = await this.authorize(call, options);
    if (decision.verdict !== "ALLOW") return { decision, executed: false };
    if (decision.containmentRequired !== false) return { decision: { ...decision, verdict: "BLOCK", reasonCodes: [...decision.reasonCodes, "CONTAINMENT_REQUIRED"] }, executed: false };
    if (decision.authorizedArguments === undefined) throw new Error("INVOCK_ALLOW_MISSING_AUTHORIZED_ARGUMENTS");
    const result = await forward({ name: call.name, arguments: { ...decision.authorizedArguments } });
    return { decision, executed: true, result };
  }
}
