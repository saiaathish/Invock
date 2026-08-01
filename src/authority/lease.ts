import { digestJson, newId } from "../core/canonical.js";
import type { Capability, Effect } from "../core/types.js";
import type { CapabilityLease, IntentCapsule } from "./types.js";
import { assertCapsule } from "./capsule.js";
import { capabilities, constraints, enumStrings, future, iso, object, strings } from "./validation.js";

export interface CapabilityLeaseInput {
  leaseId?: string; parentLeaseId?: string; issuer: string; subject: string; capabilities: Capability[];
  constraints: { tools: string[]; effects: Effect[]; resources: { paths: string[]; domains: string[]; recipients: string[] }; data: { allowedLabels: string[]; forbiddenLabels: string[] } };
  remainingCalls: number; issuedAt: string; expiresAt: string;
}

function subset(child: readonly string[], parent: readonly string[]): boolean { return child.every(item => parent.includes(item)); }
function narrows(child: CapabilityLease["constraints"], parent: CapabilityLease["constraints"]): boolean {
  return subset(child.tools, parent.tools) && subset(child.effects, parent.effects) && subset(child.resources.paths, parent.resources.paths) && subset(child.resources.domains, parent.resources.domains) && subset(child.resources.recipients, parent.resources.recipients) && subset(child.data.allowedLabels, parent.data.allowedLabels) && parent.data.forbiddenLabels.every(item => child.data.forbiddenLabels.includes(item));
}

function body(input: unknown, now: Date): Omit<CapabilityLease, "digest" | "revocationDigest" | "status"> {
  const source = object(input, "lease");
  for (const field of ["issuer", "subject"] as const) if (typeof source[field] !== "string" || (source[field] as string).length === 0) throw new Error(`${field} is required`);
  const issuedAt = iso(source.issuedAt, "issuedAt"); const expiresAt = iso(source.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt) || Date.parse(issuedAt) > now.getTime()) throw new Error("Invalid lease time window");
  future(expiresAt, now);
  if (!Number.isSafeInteger(source.remainingCalls) || (source.remainingCalls as number) < 1) throw new Error("remainingCalls must be a positive safe integer");
  const c = object(source.constraints, "constraints"); const nested = constraints({ resources: c.resources, data: c.data }, "constraints");
  return { leaseId: typeof source.leaseId === "string" && source.leaseId.length > 0 ? source.leaseId : newId("lease"), ...(typeof source.parentLeaseId === "string" ? { parentLeaseId: source.parentLeaseId } : {}), issuer: source.issuer as string, subject: source.subject as string, capabilities: enumStrings(source.capabilities, "capabilities", capabilities), constraints: { tools: strings(c.tools, "constraints.tools"), effects: enumStrings(c.effects, "constraints.effects", new Set<Effect>(["data.observe", "data.modify", "data.delete", "external.read", "external.disclosure", "external.communication", "process.spawn", "command.interpretation", "persistent.change", "irreversible.action", "unknown"])), ...nested }, remainingCalls: source.remainingCalls as number, issuedAt, expiresAt };
}

export function issueCapabilityLease(input: CapabilityLeaseInput, capsule: IntentCapsule, parent: CapabilityLease | undefined = undefined, now = new Date()): CapabilityLease {
  assertCapsule(capsule); if (capsule.status !== "ACTIVE") throw new Error("Lease requires an active capsule");
  const candidate = body(input, now); if (parent) { assertLease(parent); if (parent.status !== "ACTIVE" || parent.subject !== candidate.issuer || candidate.parentLeaseId !== parent.leaseId) throw new Error("Invalid parent lease delegation"); if (candidate.remainingCalls > parent.remainingCalls || Date.parse(candidate.expiresAt) > Date.parse(parent.expiresAt)) throw new Error("Child lease exceeds parent budget or expiry"); if (candidate.capabilities.some(cap => !parent.capabilities.includes(cap)) || !narrows(candidate.constraints, parent.constraints)) throw new Error("Child lease amplifies authority"); }
  const capsuleConstraints = { tools: capsule.allowedTools, effects: capsule.allowedEffects, resources: capsule.resourceConstraints, data: capsule.dataConstraints };
  if (candidate.capabilities.some(cap => !capsule.allowedCapabilities.includes(cap)) || !narrows(candidate.constraints, capsuleConstraints) || candidate.remainingCalls > (capsule.budgets.calls ?? Number.MAX_SAFE_INTEGER) || Date.parse(candidate.expiresAt) > Date.parse(capsule.expiresAt)) throw new Error("Lease exceeds capsule authority");
  const revocationDigest = digestJson({ leaseId: candidate.leaseId, parentLeaseId: candidate.parentLeaseId ?? null, issuedAt: candidate.issuedAt });
  return { ...candidate, status: "ACTIVE", revocationDigest, digest: digestJson(candidate) };
}

export function consumeCapabilityLease(lease: CapabilityLease, request: { calls?: number } = {}, now = new Date()): CapabilityLease {
  assertLease(lease); if (lease.status !== "ACTIVE") throw new Error("Lease is not active"); future(lease.expiresAt, now); const calls = request.calls ?? 1;
  if (!Number.isSafeInteger(calls) || calls < 1 || calls > lease.remainingCalls) throw new Error("Lease call budget exhausted");
  const remainingCalls = lease.remainingCalls - calls;
  return { ...lease, remainingCalls, ...(remainingCalls === 0 ? { status: "EXPIRED" as const } : {}), digest: digestJson({ leaseId: lease.leaseId, ...(lease.parentLeaseId ? { parentLeaseId: lease.parentLeaseId } : {}), issuer: lease.issuer, subject: lease.subject, capabilities: lease.capabilities, constraints: lease.constraints, remainingCalls, issuedAt: lease.issuedAt, expiresAt: lease.expiresAt }) };
}

export function revokeCapabilityLease(lease: CapabilityLease): CapabilityLease { assertLease(lease); return { ...lease, status: "REVOKED", revocationDigest: digestJson({ leaseDigest: lease.digest, revoked: true }) }; }
export function assertLease(lease: CapabilityLease): void { if (lease.digest !== digestJson({ leaseId: lease.leaseId, ...(lease.parentLeaseId ? { parentLeaseId: lease.parentLeaseId } : {}), issuer: lease.issuer, subject: lease.subject, capabilities: lease.capabilities, constraints: lease.constraints, remainingCalls: lease.remainingCalls, issuedAt: lease.issuedAt, expiresAt: lease.expiresAt })) throw new Error("Lease digest mismatch"); }
