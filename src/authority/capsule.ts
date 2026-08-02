import { digestJson, newId } from "../core/canonical.js";
import type { Capability, Effect } from "../core/types.js";
import { assertAuthorityBinding, assertHumanActivation, type AuthorityBinding, type HumanActivation, type TrustedApproverKeys } from "./binding.js";
import type { CapsuleStatus, IntentCapsule } from "./types.js";
import { budgets, enumStrings, future, iso, immutable, object, strings, capabilities, effects } from "./validation.js";

export interface IntentCapsuleInput {
  capsuleId?: string;
  version: number;
  rootIssuer?: string;
  purpose: string;
  allowedTools: string[];
  allowedCapabilities: Capability[];
  allowedEffects: Effect[];
  resourceConstraints: { paths: string[]; domains: string[]; recipients: string[] };
  dataConstraints: { allowedLabels: string[]; forbiddenLabels: string[] };
  budgets: { calls?: number; bytes?: number; durationSeconds?: number };
  expiresAt: string;
  authorityBinding?: AuthorityBinding;
}

function validateInput(input: unknown, now: Date): Omit<IntentCapsule, "digest" | "status"> {
  const source = object(input, "capsule");
  if (source.capsuleId !== undefined && (typeof source.capsuleId !== "string" || source.capsuleId.length === 0)) throw new Error("capsuleId must be a non-empty string");
  if (!Number.isSafeInteger(source.version) || (source.version as number) < 1) throw new Error("version must be a positive safe integer");
  if (source.rootIssuer !== undefined && (typeof source.rootIssuer !== "string" || source.rootIssuer.length === 0 || source.rootIssuer.length > 256)) throw new Error("rootIssuer must be a bounded non-empty string");
  if (typeof source.purpose !== "string" || source.purpose.trim().length === 0) throw new Error("purpose is required");
  const allowedTools = strings(source.allowedTools, "allowedTools");
  const allowedCapabilities = enumStrings(source.allowedCapabilities, "allowedCapabilities", capabilities);
  const allowedEffects = enumStrings(source.allowedEffects, "allowedEffects", effects);
  const resources = object(source.resourceConstraints, "resourceConstraints");
  const data = object(source.dataConstraints, "dataConstraints");
  const expiresAt = iso(source.expiresAt, "expiresAt"); future(expiresAt, now);
  const capsule = {
    capsuleId: (source.capsuleId as string | undefined) ?? newId("cap"), version: source.version as number, rootIssuer: (source.rootIssuer as string | undefined) ?? "capsule", purpose: source.purpose as string,
    allowedTools, allowedCapabilities, allowedEffects,
    resourceConstraints: { paths: strings(resources.paths, "resourceConstraints.paths"), domains: strings(resources.domains, "resourceConstraints.domains"), recipients: strings(resources.recipients, "resourceConstraints.recipients") },
    dataConstraints: { allowedLabels: strings(data.allowedLabels, "dataConstraints.allowedLabels"), forbiddenLabels: strings(data.forbiddenLabels, "dataConstraints.forbiddenLabels") },
    budgets: budgets(source.budgets), expiresAt,
    ...(source.authorityBinding !== undefined ? { authorityBinding: source.authorityBinding as AuthorityBinding } : {}),
  };
  if (capsule.authorityBinding) assertAuthorityBinding(capsule.authorityBinding);
  return capsule;
}

export function createIntentCapsule(input: IntentCapsuleInput, now = new Date()): IntentCapsule {
  const body = validateInput(input, now);
  const status = "PROPOSED" as const;
  return immutable({ ...body, status, digest: capsuleDigest(body, status) });
}

/** Adds the immutable execution binding before a human activation signature is issued. */
export function bindIntentCapsule(capsule: IntentCapsule, binding: AuthorityBinding): IntentCapsule {
  assertCapsule(capsule);
  if (capsule.status !== "PROPOSED") throw new Error("Only a proposed capsule can be bound");
  assertAuthorityBinding(binding);
  const { humanActivation: _humanActivation, ...withoutActivation } = capsule;
  return immutable({ ...withoutActivation, authorityBinding: binding, digest: capsuleDigest({ ...withoutActivation, authorityBinding: binding }, "PROPOSED") });
}

/** Activates a bound capsule only after verifying the attributable human signature. */
export function activateBoundIntentCapsule(capsule: IntentCapsule, activation: HumanActivation, now = new Date(), trustedApproverKeys?: TrustedApproverKeys): IntentCapsule {
  assertCapsule(capsule);
  future(capsule.expiresAt, now);
  if (capsule.status !== "PROPOSED") throw new Error("Only a proposed capsule can be activated");
  if (!capsule.authorityBinding) throw new Error("Authority binding is required for signed activation");
  assertHumanActivation(capsule.capsuleId, capsule.version, capsule.digest, capsule.authorityBinding, activation, trustedApproverKeys);
  const status = "ACTIVE" as const;
  return immutable({ ...capsule, status, humanActivation: activation, digest: capsuleDigest({ ...capsule, humanActivation: activation }, status) });
}

export function activateIntentCapsule(capsule: IntentCapsule, now = new Date()): IntentCapsule {
  assertCapsule(capsule); future(capsule.expiresAt, now);
  if (capsule.status !== "PROPOSED") throw new Error("Only a proposed capsule can be activated");
  if (capsule.authorityBinding) throw new Error("HUMAN_ACTIVATION_REQUIRED");
  const status = "ACTIVE" as const;
  return immutable({ ...capsule, status, digest: capsuleDigest(capsule, status) });
}

export function revokeIntentCapsule(capsule: IntentCapsule, now = new Date(), trustedApproverKeys?: TrustedApproverKeys): IntentCapsule {
  assertCapsule(capsule, trustedApproverKeys);
  if (capsule.status === "REVOKED") return capsule;
  const revokedAt = now.toISOString();
  const status = "REVOKED" as const;
  return immutable({ ...capsule, status, digest: capsuleDigest(capsule, status), revokedAt, revocationDigest: capsuleRevocationDigest(capsule, revokedAt) });
}

export function assertCapsule(capsule: IntentCapsule, trustedApproverKeys?: TrustedApproverKeys): void {
  const source = object(capsule, "capsule");
  if (!["PROPOSED", "ACTIVE", "REVOKED", "EXPIRED"].includes(capsule.status)) throw new Error("Invalid capsule status");
  if (typeof capsule.rootIssuer !== "string" || capsule.rootIssuer.length === 0 || capsule.rootIssuer.length > 256) throw new Error("Invalid capsule root issuer");
  if (source.digest !== capsuleDigest(capsule, capsule.status)) throw new Error("Capsule digest mismatch");
  if (capsule.authorityBinding) {
    assertAuthorityBinding(capsule.authorityBinding);
    if (capsule.status !== "PROPOSED") {
      if (!capsule.humanActivation) throw new Error("Human activation evidence is required");
      const { humanActivation: _humanActivation, ...withoutActivation } = capsule;
      const proposed = capsuleDigest(withoutActivation, "PROPOSED");
      assertHumanActivation(capsule.capsuleId, capsule.version, proposed, capsule.authorityBinding, capsule.humanActivation, trustedApproverKeys);
    } else if (capsule.humanActivation !== undefined) {
      throw new Error("Human activation cannot precede active status");
    }
  } else if (capsule.humanActivation !== undefined) {
    throw new Error("Human activation requires authority binding");
  }
  if (capsule.status === "REVOKED") {
    if (typeof capsule.revokedAt !== "string" || capsule.revocationDigest !== capsuleRevocationDigest(capsule, capsule.revokedAt)) throw new Error("Capsule revocation metadata mismatch");
  } else if (capsule.revokedAt !== undefined || capsule.revocationDigest !== undefined) {
    throw new Error("Unexpected capsule revocation metadata");
  }
}

function capsuleRevocationDigest(capsule: Pick<IntentCapsule, "capsuleId" | "version">, revokedAt: string): string {
  return digestJson({ capsuleId: capsule.capsuleId, version: capsule.version, revoked: true, revokedAt });
}

function capsuleDigest(capsule: Pick<IntentCapsule, "capsuleId" | "version" | "rootIssuer" | "purpose" | "allowedTools" | "allowedCapabilities" | "allowedEffects" | "resourceConstraints" | "dataConstraints" | "budgets" | "expiresAt" | "authorityBinding" | "humanActivation">, status: CapsuleStatus): string {
  return digestJson({ capsuleId: capsule.capsuleId, version: capsule.version, rootIssuer: capsule.rootIssuer, purpose: capsule.purpose, allowedTools: capsule.allowedTools, allowedCapabilities: capsule.allowedCapabilities, allowedEffects: capsule.allowedEffects, resourceConstraints: capsule.resourceConstraints, dataConstraints: capsule.dataConstraints, budgets: capsule.budgets, expiresAt: capsule.expiresAt, authorityBinding: capsule.authorityBinding ?? null, humanActivation: capsule.humanActivation ?? null, status });
}
