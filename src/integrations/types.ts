import type { DecisionResponse } from "../sdk/typescript.js";

/** The only value an adapter may pass to an upstream tool after ALLOW. */
export interface AuthorizedToolCall {
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

export interface AdapterExecution<T> {
  readonly decision: DecisionResponse;
  readonly executed: boolean;
  readonly result?: T;
}

export type ToolExecutor<T> = (call: AuthorizedToolCall) => Promise<T> | T;
