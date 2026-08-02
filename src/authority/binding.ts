import { createPublicKey, sign, verify } from "node:crypto";
import { canonicalize, digestJson } from "../core/canonical.js";
import { immutable, iso, object } from "./validation.js";

const DIGEST = /^[A-Za-z0-9_-]{43}$/u;

/** The immutable execution context an intent and its delegated leases are allowed to inhabit. */
export interface AuthorityBinding {
  agentId: string;
  sessionId: string;
  projectId: string;
  policyVersionId: string;
  policyDigest: string;
  registryVersion: string;
  toolSchemaDigest: string;
  bindingDigest: string;
}

/** Human activation evidence. The private key is never part of this record. */
export interface HumanActivation {
  approverId: string;
  approvedAt: string;
  statementDigest: string;
  publicKeyPem: string;
  signature: string;
}
export type TrustedApproverKeys = ReadonlyMap<string, string>;

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) throw new Error(`${name} must be a bounded non-empty string`);
  return value;
}

function digest(value: unknown, name: string): string {
  const result = requiredString(value, name);
  if (!DIGEST.test(result)) throw new Error(`${name} must be a canonical SHA-256 digest`);
  return result;
}

function bindingBody(input: unknown): Omit<AuthorityBinding, "bindingDigest"> {
  const source = object(input, "authorityBinding");
  return {
    agentId: requiredString(source.agentId, "authorityBinding.agentId"),
    sessionId: requiredString(source.sessionId, "authorityBinding.sessionId"),
    projectId: requiredString(source.projectId, "authorityBinding.projectId"),
    policyVersionId: requiredString(source.policyVersionId, "authorityBinding.policyVersionId"),
    policyDigest: digest(source.policyDigest, "authorityBinding.policyDigest"),
    registryVersion: requiredString(source.registryVersion, "authorityBinding.registryVersion"),
    toolSchemaDigest: digest(source.toolSchemaDigest, "authorityBinding.toolSchemaDigest"),
  };
}

export function createAuthorityBinding(input: Omit<AuthorityBinding, "bindingDigest">): AuthorityBinding {
  const body = bindingBody(input);
  return immutable({ ...body, bindingDigest: digestJson(body) });
}

export function assertAuthorityBinding(binding: AuthorityBinding): void {
  const body = bindingBody(binding);
  if (binding.bindingDigest !== digestJson(body)) throw new Error("Authority binding digest mismatch");
}

export function humanActivationMessage(capsuleId: string, version: number, proposedDigest: string, binding: AuthorityBinding, activation: Pick<HumanActivation, "approverId" | "approvedAt" | "statementDigest">): string {
  assertAuthorityBinding(binding);
  return canonicalize({ domain: "invock-human-intent-activation-v1", capsuleId: requiredString(capsuleId, "capsuleId"), version, proposedDigest: digest(proposedDigest, "proposedDigest"), bindingDigest: binding.bindingDigest, approverId: requiredString(activation.approverId, "approverId"), approvedAt: iso(activation.approvedAt, "approvedAt"), statementDigest: digest(activation.statementDigest, "statementDigest") });
}

export function createHumanActivation(input: { capsuleId: string; version: number; proposedDigest: string; binding: AuthorityBinding; approverId: string; approvedAt: string; statementDigest: string; privateKeyPem: string }): HumanActivation {
  const message = humanActivationMessage(input.capsuleId, input.version, input.proposedDigest, input.binding, input);
  const signature = sign(null, Buffer.from(message, "utf8"), input.privateKeyPem).toString("base64url");
  const publicKeyPem = createPublicKey(input.privateKeyPem).export({ type: "spki", format: "pem" }).toString();
  return immutable({ approverId: requiredString(input.approverId, "approverId"), approvedAt: iso(input.approvedAt, "approvedAt"), statementDigest: digest(input.statementDigest, "statementDigest"), publicKeyPem, signature });
}

/** Builds an activation record from an already-separated public key. */
export function signHumanActivation(input: { capsuleId: string; version: number; proposedDigest: string; binding: AuthorityBinding; approverId: string; approvedAt: string; statementDigest: string; privateKeyPem: string; publicKeyPem: string }): HumanActivation {
  const message = humanActivationMessage(input.capsuleId, input.version, input.proposedDigest, input.binding, input);
  if (!input.publicKeyPem.includes("PUBLIC KEY")) throw new Error("publicKeyPem is required");
  const activation = { approverId: requiredString(input.approverId, "approverId"), approvedAt: iso(input.approvedAt, "approvedAt"), statementDigest: digest(input.statementDigest, "statementDigest"), publicKeyPem: input.publicKeyPem, signature: sign(null, Buffer.from(message, "utf8"), input.privateKeyPem).toString("base64url") };
  return immutable(activation);
}

export function assertHumanActivation(capsuleId: string, version: number, proposedDigest: string, binding: AuthorityBinding, activation: HumanActivation, trustedApproverKeys?: TrustedApproverKeys): void {
  const source = object(activation, "humanActivation");
  const message = humanActivationMessage(capsuleId, version, proposedDigest, binding, activation);
  if (typeof source.publicKeyPem !== "string" || !source.publicKeyPem.includes("PUBLIC KEY")) throw new Error("humanActivation.publicKeyPem is invalid");
  if (typeof source.signature !== "string" || source.signature.length === 0) throw new Error("humanActivation.signature is invalid");
  const trustedKey = trustedApproverKeys?.get(activation.approverId);
  if (!trustedKey) throw new Error("TRUSTED_APPROVER_KEY_REQUIRED");
  if (trustedKey !== activation.publicKeyPem) throw new Error("TRUSTED_APPROVER_KEY_MISMATCH");
  let valid = false;
  try { valid = verify(null, Buffer.from(message, "utf8"), trustedKey, Buffer.from(source.signature, "base64url")); } catch { valid = false; }
  if (!valid) throw new Error("Human activation signature invalid");
}
