import { digestJson } from "../core/canonical.js";
import type { CapabilityLease, IntentCapsule, AuthorityEvaluation, AuthorityRequest } from "./types.js";
import { assertCapsule } from "./capsule.js";
import { assertLease } from "./lease.js";

const MAX_DELEGATION_DEPTH = 16;

export function evaluateMonotonicAuthority(capsule: IntentCapsule, leases: readonly CapabilityLease[], request: AuthorityRequest, now = new Date()): AuthorityEvaluation {
  const reasons: string[] = [];
  try { assertCapsule(capsule); } catch { reasons.push("MALFORMED_CAPSULE"); }
  if (capsule.status !== "ACTIVE") reasons.push("CAPSULE_NOT_ACTIVE");
  if (Date.parse(capsule.expiresAt) <= now.getTime()) reasons.push("CAPSULE_EXPIRED");
  const chain = [...leases];
  if (chain.length > MAX_DELEGATION_DEPTH) reasons.push("DELEGATION_DEPTH_EXCEEDED");
  for (const lease of chain) { try { assertLease(lease); } catch { reasons.push("MALFORMED_LEASE"); } if (lease.status !== "ACTIVE") reasons.push("LEASE_NOT_ACTIVE"); if (Date.parse(lease.expiresAt) <= now.getTime()) reasons.push("LEASE_EXPIRED"); }
  const leaf = chain.at(-1);
  for (let index = 1; index < chain.length; index += 1) if (chain[index]?.parentLeaseId !== chain[index - 1]?.leaseId || chain[index]?.issuer !== chain[index - 1]?.subject) reasons.push("INVALID_LEASE_CHAIN");
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
  const digest = digestJson({ capsule: capsule.digest, leases: leases.map(lease => lease.digest), request });
  return { allowed: reasons.length === 0, reasonCodes: [...new Set(reasons)].sort(), effectiveDigest: digest };
}
