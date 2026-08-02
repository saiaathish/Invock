import type { Capability, Effect } from "../core/types.js";
import type { AuthorityBinding, HumanActivation } from "./binding.js";

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
  /** Optional binding for the production-shaped identity/policy/registry path. */
  authorityBinding?: AuthorityBinding;
  /** Present only after a bound capsule has received human activation evidence. */
  humanActivation?: HumanActivation;
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
  authorityBindingDigest?: string;
  status: "ACTIVE" | "REVOKED" | "EXPIRED";
  digest: string;
}

export interface AuthorityRequest {
  tool: string;
  /** Runtime principal selected by the gateway; never supplied by an untrusted lease caller. */
  runtimeSubject?: string;
  capabilities: Capability[];
  effects: Effect[];
  resources?: Partial<AuthorityResourceConstraints>;
  dataLabels?: string[];
  bytes?: number;
  authorityBindingDigest?: string;
}

export interface AuthorityEvaluation {
  allowed: boolean;
  reasonCodes: string[];
  effectiveDigest: string;
}
