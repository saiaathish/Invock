import { digestJson } from "./canonical.js";
import type { Capability, Effect } from "./types.js";

export interface ToolConstraint { allow: string[]; deny: string[]; }
export interface CapabilityConstraint { allow: Capability[]; deny: Capability[]; }
export interface EffectConstraint { allow: Effect[]; deny: Effect[]; }
export interface ResourceConstraintSet { paths: string[]; domains: string[]; recipients: string[]; }
export interface DataConstraintSet { allowedLabels: string[]; forbiddenLabels: string[]; }
export interface AuthorityBudget { calls?: number; bytes?: number; durationSeconds?: number; }
export interface TemporalConstraint { notBefore?: string; expiresAt?: string; }
export interface AuthorityConstraintSet { tools: ToolConstraint; capabilities: CapabilityConstraint; effects: EffectConstraint; resources: ResourceConstraintSet; data: DataConstraintSet; budgets: AuthorityBudget; temporal: TemporalConstraint; }
export interface EffectiveAuthority { staticPolicyDigest: string; intentCapsuleDigest?: string; capabilityLeaseChainDigest?: string; toolSchemaDigest: string; registryVersion: string; containmentProfileDigest?: string; constraints: AuthorityConstraintSet; }
export interface AuthorityReduction { source: "STATIC_POLICY" | "INTENT_CAPSULE" | "CAPABILITY_LEASE" | "TOOL_SCHEMA" | "DATA_FLOW" | "CONTAINMENT"; removedCapabilities: string[]; removedEffects: string[]; narrowedResources: string[]; addedApprovalRequirements: string[]; }
export interface AuthorityEvaluation { verdict: "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED"; reasonCodes: string[]; matchedRuleIds: string[]; effectiveAuthorityDigest: string; reductions: AuthorityReduction[]; }
export function effectiveAuthorityDigest(authority: EffectiveAuthority): string { return digestJson(authority); }
