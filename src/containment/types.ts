export type ContainmentStatus = "completed" | "failed" | "timed_out" | "denied" | "unsupported";

export interface ContainmentProfile {
  fixtureRoot: string;
  allowedCommands: string[];
  timeoutMs?: number;
  maxOutputBytes?: number;
  maxArgvBytes?: number;
  /** Required means an OS sandbox must be available; none makes no isolation claim. */
  sandbox?: "required" | "none";
}

export interface ContainmentRequest {
  profile: ContainmentProfile;
  command: string;
  argv?: string[];
  env?: Record<string, string>;
}

export interface ContainmentResult {
  status: ContainmentStatus;
  stdout: string;
  stderr: string;
  exitCode?: number;
  signal?: string;
  durationMs: number;
  reasonCodes: string[];
  capabilities: { sandbox: "available" | "unavailable" | "not_requested"; network: "denied" };
}
