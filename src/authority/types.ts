import type { Capability, Effect } from "../core/types.js";

export type CapsuleStatus = "PROPOSED" | "ACTIVE" | "REVOKED" | "EXPIRED";

export interface AuthorityResourceConstraints {
  paths: string[];
  domains: string[];
  recipients: string[];
}

export interface AuthorityDataConstraints {
  allowedLabels: string[];
  forbiddenLabels: string[];
}

export interface AuthorityBudgets {
  calls?: number;
  bytes?: number;
  durationSeconds?: number;
}

export interface IntentCapsule {
  capsuleId: string;
  version: number;
  purpose: string;
  allowedTools: string[];
  allowedCapabilities: Capability[];
  allowedEffects: Effect[];
  resourceConstraints: AuthorityResourceConstraints;
  dataConstraints: AuthorityDataConstraints;
  budgets: AuthorityBudgets;
  expiresAt: string;
  status: CapsuleStatus;
  digest: string;
  revokedAt?: string;
  revocationDigest?: string;
}

export interface CapabilityLease {
  leaseId: string;
  parentLeaseId?: string;
  issuer: string;
  subject: string;
  capabilities: Capability[];
  constraints: {
    tools: string[];
    effects: Effect[];
    resources: AuthorityResourceConstraints;
    data: AuthorityDataConstraints;
  };
  remainingCalls: number;
  issuedAt: string;
  expiresAt: string;
  revocationDigest: string;
  status: "ACTIVE" | "REVOKED" | "EXPIRED";
  digest: string;
}

export interface AuthorityRequest {
  tool: string;
  capabilities: Capability[];
  effects: Effect[];
  resources?: Partial<AuthorityResourceConstraints>;
  dataLabels?: string[];
  bytes?: number;
}

export interface AuthorityEvaluation {
  allowed: boolean;
  reasonCodes: string[];
  effectiveDigest: string;
}
