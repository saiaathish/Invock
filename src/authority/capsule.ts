import { digestJson, newId } from "../core/canonical.js";
import type { Capability, Effect } from "../core/types.js";
import type { IntentCapsule } from "./types.js";
import { budgets, constraints, enumStrings, future, iso, object, strings, capabilities, effects } from "./validation.js";

export interface IntentCapsuleInput {
  capsuleId?: string;
  version: number;
  purpose: string;
  allowedTools: string[];
  allowedCapabilities: Capability[];
  allowedEffects: Effect[];
  resourceConstraints: { paths: string[]; domains: string[]; recipients: string[] };
  dataConstraints: { allowedLabels: string[]; forbiddenLabels: string[] };
  budgets: { calls?: number; bytes?: number; durationSeconds?: number };
  expiresAt: string;
}

function validateInput(input: unknown, now: Date): Omit<IntentCapsule, "digest" | "status"> {
  const source = object(input, "capsule");
  if (source.capsuleId !== undefined && (typeof source.capsuleId !== "string" || source.capsuleId.length === 0)) throw new Error("capsuleId must be a non-empty string");
  if (!Number.isSafeInteger(source.version) || (source.version as number) < 1) throw new Error("version must be a positive safe integer");
  if (typeof source.purpose !== "string" || source.purpose.trim().length === 0) throw new Error("purpose is required");
  const allowedTools = strings(source.allowedTools, "allowedTools");
  const allowedCapabilities = enumStrings(source.allowedCapabilities, "allowedCapabilities", capabilities);
  const allowedEffects = enumStrings(source.allowedEffects, "allowedEffects", effects);
  const resources = object(source.resourceConstraints, "resourceConstraints");
  const data = object(source.dataConstraints, "dataConstraints");
  const expiresAt = iso(source.expiresAt, "expiresAt"); future(expiresAt, now);
  const capsule = {
    capsuleId: (source.capsuleId as string | undefined) ?? newId("cap"), version: source.version as number, purpose: source.purpose as string,
    allowedTools, allowedCapabilities, allowedEffects,
    resourceConstraints: { paths: strings(resources.paths, "resourceConstraints.paths"), domains: strings(resources.domains, "resourceConstraints.domains"), recipients: strings(resources.recipients, "resourceConstraints.recipients") },
    dataConstraints: { allowedLabels: strings(data.allowedLabels, "dataConstraints.allowedLabels"), forbiddenLabels: strings(data.forbiddenLabels, "dataConstraints.forbiddenLabels") },
    budgets: budgets(source.budgets), expiresAt,
  };
  return capsule;
}

export function createIntentCapsule(input: IntentCapsuleInput, now = new Date()): IntentCapsule {
  const body = validateInput(input, now);
  return { ...body, status: "PROPOSED", digest: digestJson(body) };
}

export function activateIntentCapsule(capsule: IntentCapsule, now = new Date()): IntentCapsule {
  assertCapsule(capsule); future(capsule.expiresAt, now);
  if (capsule.status !== "PROPOSED") throw new Error("Only a proposed capsule can be activated");
  return { ...capsule, status: "ACTIVE" };
}

export function revokeIntentCapsule(capsule: IntentCapsule, now = new Date()): IntentCapsule {
  assertCapsule(capsule);
  if (capsule.status === "REVOKED") return capsule;
  const revokedAt = now.toISOString();
  return { ...capsule, status: "REVOKED", revokedAt, revocationDigest: digestJson({ capsuleDigest: capsule.digest, revokedAt }) };
}

export function assertCapsule(capsule: IntentCapsule): void {
  if (object(capsule, "capsule").digest !== digestJson({ capsuleId: capsule.capsuleId, version: capsule.version, purpose: capsule.purpose, allowedTools: capsule.allowedTools, allowedCapabilities: capsule.allowedCapabilities, allowedEffects: capsule.allowedEffects, resourceConstraints: capsule.resourceConstraints, dataConstraints: capsule.dataConstraints, budgets: capsule.budgets, expiresAt: capsule.expiresAt })) throw new Error("Capsule digest mismatch");
  if (!["PROPOSED", "ACTIVE", "REVOKED", "EXPIRED"].includes(capsule.status)) throw new Error("Invalid capsule status");
}
