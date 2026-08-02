import { InvockClient, type AuthorizeInput, type DecisionResponse, type ExecutionResponse } from "../sdk/typescript.js";
import type { AdapterExecution, ToolExecutor } from "./types.js";

export interface SecondaryToolCall {
  readonly name: string;
  readonly input: Record<string, unknown>;
}

export interface SecondaryAdapterOptions {
  readonly agent?: string;
  readonly projectId?: string;
  readonly intentCapsule?: unknown;
  readonly authorityBinding?: unknown;
  readonly capabilityLeases?: readonly unknown[];
  readonly sessionId?: string;
}

export class SecondaryInvockAdapter {
  public constructor(private readonly client: InvockClient) {}

  private input(call: SecondaryToolCall, options: SecondaryAdapterOptions): AuthorizeInput {
    return { tool: call.name, arguments: call.input, ...(options.agent !== undefined ? { agent: options.agent } : {}), ...(options.projectId !== undefined ? { projectId: options.projectId } : {}), ...(options.intentCapsule !== undefined ? { intentCapsule: options.intentCapsule } : {}), ...(options.authorityBinding !== undefined ? { authorityBinding: options.authorityBinding } : {}), ...(options.capabilityLeases !== undefined ? { capabilityLeases: options.capabilityLeases } : {}), ...(options.sessionId !== undefined ? { sessionId: options.sessionId } : {}) };
  }

  public authorize(call: SecondaryToolCall, options: SecondaryAdapterOptions = {}): Promise<DecisionResponse> {
    return this.client.authorize(this.input(call, options));
  }

  /** Execute through Invock's server-owned containment boundary. No caller callback is accepted. */
  public executeContained(call: SecondaryToolCall, options: SecondaryAdapterOptions = {}): Promise<ExecutionResponse> {
    return this.client.execute(this.input(call, options));
  }

  /** Authorize before invoking the secondary framework's upstream tool executor. */
  public async execute<T>(call: SecondaryToolCall, forward: ToolExecutor<T>, options: SecondaryAdapterOptions = {}): Promise<AdapterExecution<T>> {
    const decision = await this.authorize(call, options);
    if (decision.verdict !== "ALLOW") return { decision, executed: false };
    if (decision.containmentRequired !== false) return { decision: { ...decision, verdict: "BLOCK", reasonCodes: [...decision.reasonCodes, "CONTAINMENT_REQUIRED"] }, executed: false };
    if (decision.authorizedArguments === undefined) throw new Error("INVOCK_ALLOW_MISSING_AUTHORIZED_ARGUMENTS");
    const result = await forward({ name: call.name, arguments: { ...decision.authorizedArguments } });
    return { decision, executed: true, result };
  }
}
