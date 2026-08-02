export type JudgeMode = "automated" | "presentation";
export type JudgeStatus = "passed" | "degraded" | "failed" | "unsupported";

export interface JudgeCheckpoint {
  id: string;
  label: string;
  status: JudgeStatus;
  details: Record<string, unknown>;
}

export interface JudgeResult {
  schemaVersion: "invock/judge-result/v1";
  command: "judge";
  mode: JudgeMode;
  overall: Exclude<JudgeStatus, "unsupported">;
  deterministic: {
    decisionOutcomes: true;
    fakeDataOnly: true;
    externalNetworkCalls: false;
    transport: "loopback-only";
    volatileFields: string[];
  };
  prerequisites: {
    status: JudgeStatus;
    node: { version: string; compatible: boolean; required: string };
    policyFixture: { path: string; present: boolean };
    localOnly: true;
  };
  checkpoints: JudgeCheckpoint[];
  narrative: {
    userIntent: string;
    delegatedAuthority: { capsule: string; lease: string; budgetCalls: number; expiresAt: string };
    safeExample: { verdict: "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED"; upstreamExecutionCount: number; sinkExecutionCount: number; receiptPresent: boolean };
    blockedAttack: { verdict: "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED"; upstreamExecutionCount: number; sinkExecutionCount: number; reasonCodes: string[]; receiptPresent: boolean };
    containment: { status: JudgeStatus; resultStatus: string; reasonCodes: string[]; network: string; browserVerified: false };
    signedEvidence: { chainValid: boolean; receiptCount: number; redacted: boolean; publicKeyPresent: boolean };
  };
  integrations: {
    supported: string[];
    unsupported: string[];
    runtimeProof: Record<string, "not-run" | "unsupported" | "verified">;
  };
  cleanup: { attempted: boolean; completed: boolean; temporaryRootRemoved: boolean; errors: string[] };
  presentation: { checkpointsPause: boolean; automatedModeAvailable: true; browserEvidence: "not-collected" };
  error?: string;
}
