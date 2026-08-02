import { digestJson } from "../core/canonical.js";
import type { CapabilityLease, IntentCapsule, AuthorityEvaluation, AuthorityRequest } from "./types.js";
import type { TrustedApproverKeys } from "./binding.js";
import { assertCapsule } from "./capsule.js";
import { assertLease } from "./lease.js";

const MAX_DELEGATION_DEPTH = 16;

function subset(child: readonly string[], parent: readonly string[]): boolean {
  return child.every(value => parent.includes(value));
}

function narrows(child: CapabilityLease["constraints"], parent: CapabilityLease["constraints"]): boolean {
  return subset(child.tools, parent.tools)
    && subset(child.effects, parent.effects)
    && subset(child.resources.paths, parent.resources.paths)
    && subset(child.resources.domains, parent.resources.domains)
    && subset(child.resources.recipients, parent.resources.recipients)
    && subset(child.data.allowedLabels, parent.data.allowedLabels)
    && parent.data.forbiddenLabels.every(value => child.data.forbiddenLabels.includes(value));
}

export function evaluateMonotonicAuthority(capsule: IntentCapsule, leases: readonly CapabilityLease[], request: AuthorityRequest, now = new Date(), trustedApproverKeys?: TrustedApproverKeys): AuthorityEvaluation {
  const reasons: string[] = [];
  if (capsule.allowedCapabilities.includes("unknown") || capsule.allowedEffects.includes("unknown")) reasons.push("UNKNOWN_CAPSULE_AUTHORITY");
  try { assertCapsule(capsule, trustedApproverKeys); } catch { reasons.push("MALFORMED_CAPSULE"); }
  if (capsule.status !== "ACTIVE") reasons.push("CAPSULE_NOT_ACTIVE");
  if (Date.parse(capsule.expiresAt) <= now.getTime()) reasons.push("CAPSULE_EXPIRED");
  const chain = [...leases];
  if (chain.length > MAX_DELEGATION_DEPTH) reasons.push("DELEGATION_DEPTH_EXCEEDED");
  const seenLeaseIds = new Set<string>();
  for (const lease of chain) {
    if (seenLeaseIds.has(lease.leaseId)) reasons.push("DUPLICATE_LEASE");
    seenLeaseIds.add(lease.leaseId);
    try { assertLease(lease); } catch { reasons.push("MALFORMED_LEASE"); }
    if (lease.capabilities.includes("unknown") || lease.constraints.effects.includes("unknown")) reasons.push("UNKNOWN_LEASE_AUTHORITY");
    if (lease.status !== "ACTIVE") reasons.push("LEASE_NOT_ACTIVE");
    if (Date.parse(lease.expiresAt) <= now.getTime()) reasons.push("LEASE_EXPIRED");
    if (lease.authorityBindingDigest !== capsule.authorityBinding?.bindingDigest) reasons.push(capsule.authorityBinding ? "LEASE_AUTHORITY_BINDING_MISMATCH" : "LEASE_AUTHORITY_BINDING_UNEXPECTED");
  }
  if (request.capabilities.includes("unknown")) reasons.push("UNKNOWN_CAPABILITY");
  if (request.effects.includes("unknown")) reasons.push("UNKNOWN_EFFECT");
  if (capsule.authorityBinding && request.authorityBindingDigest !== capsule.authorityBinding.bindingDigest) reasons.push("AUTHORITY_BINDING_MISMATCH");
  if (!capsule.authorityBinding && request.authorityBindingDigest !== undefined) reasons.push("UNEXPECTED_AUTHORITY_BINDING");
  const leaf = chain.at(-1);
  if (chain[0] && chain[0].parentLeaseId === undefined && chain[0].issuer !== capsule.rootIssuer) reasons.push("ROOT_LEASE_ISSUER_MISMATCH");
  if (request.runtimeSubject !== undefined) {
    if (capsule.authorityBinding && !capsule.humanActivation) reasons.push("HUMAN_ACTIVATION_REQUIRED");
    if (leaf && leaf.subject !== request.runtimeSubject) reasons.push("LEASE_SUBJECT_RUNTIME_MISMATCH");
  }
  if (chain[0]?.parentLeaseId !== undefined) reasons.push("INVALID_LEASE_CHAIN");
  for (let index = 1; index < chain.length; index += 1) {
    const parent = chain[index - 1];
    const child = chain[index];
    if (!parent || !child) continue;
    if (child.parentLeaseId !== parent.leaseId || child.issuer !== parent.subject) reasons.push("INVALID_LEASE_CHAIN");
    if (child.remainingCalls > parent.remainingCalls || Date.parse(child.expiresAt) > Date.parse(parent.expiresAt) || child.capabilities.some(capability => !parent.capabilities.includes(capability)) || !narrows(child.constraints, parent.constraints)) reasons.push("LEASE_AUTHORITY_AMPLIFICATION");
  }
  if (!leaf) reasons.push("NO_LEASE");
  if (leaf && leaf.remainingCalls < 1) reasons.push("LEASE_CALL_BUDGET_EXHAUSTED");
  if (leaf && request.capabilities.some(cap => !leaf.capabilities.includes(cap))) reasons.push("CAPABILITY_OUTSIDE_LEASE");
  if (leaf && request.tool && !leaf.constraints.tools.includes(request.tool)) reasons.push("TOOL_OUTSIDE_LEASE");
  if (leaf && request.effects.some(effect => !leaf.constraints.effects.includes(effect))) reasons.push("EFFECT_OUTSIDE_LEASE");
  if (!capsule.allowedTools.includes(request.tool)) reasons.push("TOOL_OUTSIDE_CAPSULE");
  if (request.capabilities.some(cap => !capsule.allowedCapabilities.includes(cap)) || request.effects.some(effect => !capsule.allowedEffects.includes(effect))) reasons.push("AUTHORITY_OUTSIDE_CAPSULE");
  if (request.dataLabels?.some(label => !leaf?.constraints.data.allowedLabels.includes(label) || leaf.constraints.data.forbiddenLabels.includes(label))) reasons.push("DATA_LABEL_OUTSIDE_LEASE");
  if (request.dataLabels?.some(label => !capsule.dataConstraints.allowedLabels.includes(label) || capsule.dataConstraints.forbiddenLabels.includes(label))) reasons.push("DATA_LABEL_OUTSIDE_CAPSULE");
  for (const [kind, values] of Object.entries(request.resources ?? {})) {
    if (!Array.isArray(values)) continue;
    if (leaf && values.some(value => !(leaf.constraints.resources as unknown as Record<string, string[]>)[kind]?.includes(value))) reasons.push(`RESOURCE_${kind.toUpperCase()}_OUTSIDE_LEASE`);
    if (values.some(value => !(capsule.resourceConstraints as unknown as Record<string, string[]>)[kind]?.includes(value))) reasons.push(`RESOURCE_${kind.toUpperCase()}_OUTSIDE_CAPSULE`);
  }
  if (request.bytes !== undefined && (!Number.isSafeInteger(request.bytes) || request.bytes < 0 || request.bytes > (capsule.budgets.bytes ?? Number.MAX_SAFE_INTEGER))) reasons.push("BYTE_BUDGET_EXCEEDED");
  if (capsule.budgets.durationSeconds !== undefined) {
    const startedAt = chain[0]?.issuedAt;
    const startedAtMs = startedAt === undefined ? Number.NaN : Date.parse(startedAt);
    if (!Number.isFinite(startedAtMs) || now.getTime() - startedAtMs >= capsule.budgets.durationSeconds * 1000) reasons.push("DURATION_BUDGET_EXCEEDED");
  }
  const digest = digestJson({ capsule: capsule.digest, leases: leases.map(lease => lease.digest), request });
  return { allowed: reasons.length === 0, reasonCodes: [...new Set(reasons)].sort(), effectiveDigest: digest };
}
