import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalize, digestJson, newId } from "../core/canonical.js";
import type { ActionEnvelope, LineageReference, PolicyDecision, Verdict } from "../core/types.js";
import { assertIdentityEvidenceBinding } from "../identity/authority.js";
import type { IdentityEvidenceBinding } from "../identity/types.js";

export interface ReceiptPayload {
  receiptVersion: "1.0";
  receiptId: string;
  instanceId: string;
  sequence: number;
  createdAt: string;
  invocationId: string;
  sessionId: string;
  principalId: string;
  serverId: string;
  toolName: string;
  argumentsDigest: string;
  envelopeDigest: string;
  policyDigest: string;
  toolSchemaDigest: string;
  lineageDigest: string;
  lineageReferences: LineageReference[];
  verdict: Verdict;
  matchedRuleIds: string[];
  reasonCodes: string[];
  upstreamForwarded: boolean;
  upstreamResultDigest?: string;
  approvalId?: string;
  intentCapsuleDigest?: string;
  capabilityLeaseChainDigest?: string;
  effectiveAuthorityDigest?: string;
  authorityBindingDigest?: string;
  identityDigest?: string;
  sessionDigest?: string;
  projectDigest?: string;
  agentDigest?: string;
  identityBindingDigest?: string;
  attestationDigest?: string;
  containmentRunId?: string;
  containmentRequestDigest?: string;
  containmentProfileDigest?: string;
  arenaRunId?: string;
  policyDraftDigest?: string;
  protocolProfileId?: string;
  previousReceiptHash: string | null;
}
export interface ReceiptMetadata {
  intentCapsuleDigest?: string;
  capabilityLeaseChainDigest?: string;
  effectiveAuthorityDigest?: string;
  authorityBindingDigest?: string;
  identityDigest?: string;
  sessionDigest?: string;
  projectDigest?: string;
  agentDigest?: string;
  identityBindingDigest?: string;
  attestationDigest?: string;
  containmentRunId?: string;
  containmentRequestDigest?: string;
  containmentProfileDigest?: string;
  arenaRunId?: string;
  policyDraftDigest?: string;
  protocolProfileId?: string;
}
export interface SignedReceipt { payload: ReceiptPayload; canonicalization: "RFC8785-JCS"; hashAlgorithm: "SHA-256"; receiptHash: string; signatureAlgorithm: "Ed25519"; signingKeyId: string; signature: string; }
export interface SigningMaterial { signingKeyId: string; privateKeyPem: string; publicKeyPem: string; }
export interface SignedChainHead {
  chainId: string;
  receiptCount: number;
  lastSequence: number;
  lastReceiptHash: string | null;
  keyId: string;
  updatedAt: string;
  signature: string;
}

export function generateSigningMaterial(): SigningMaterial {
  const keys = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  return { signingKeyId: newId("key"), privateKeyPem: keys.privateKey, publicKeyPem: keys.publicKey };
}

function receiptHash(payload: ReceiptPayload): Buffer {
  const previous = payload.previousReceiptHash ? Buffer.from(payload.previousReceiptHash, "base64url") : Buffer.alloc(0);
  return createHash("sha256").update("invock-receipt-v1\0", "utf8").update(previous).update(canonicalize(payload)).digest();
}

export function signReceipt(payload: ReceiptPayload, signing: SigningMaterial): SignedReceipt {
  const hash = receiptHash(payload);
  const receiptHashValue = hash.toString("base64url");
  const signedMetadata = { receiptHash: receiptHashValue, canonicalization: "RFC8785-JCS" as const, hashAlgorithm: "SHA-256" as const, signatureAlgorithm: "Ed25519" as const, signingKeyId: signing.signingKeyId };
  const signature = sign(null, Buffer.from(`invock-receipt-signature-v2\0${canonicalize(signedMetadata)}`, "utf8"), signing.privateKeyPem);
  return { payload, ...signedMetadata, signature: signature.toString("base64url") };
}

export function verifyReceipt(receipt: SignedReceipt, publicKeyPem: string, expectedPrevious: string | null, expectedKeyId?: string): boolean {
  try {
    if (receipt.canonicalization !== "RFC8785-JCS" || receipt.hashAlgorithm !== "SHA-256" || receipt.signatureAlgorithm !== "Ed25519") return false;
    if (expectedKeyId !== undefined && receipt.signingKeyId !== expectedKeyId) return false;
    if (receipt.payload.previousReceiptHash !== expectedPrevious) return false;
    const hash = receiptHash(receipt.payload);
    if (hash.toString("base64url") !== receipt.receiptHash) return false;
    const signedMetadata = { receiptHash: receipt.receiptHash, canonicalization: receipt.canonicalization, hashAlgorithm: receipt.hashAlgorithm, signatureAlgorithm: receipt.signatureAlgorithm, signingKeyId: receipt.signingKeyId };
    return verify(null, Buffer.from(`invock-receipt-signature-v2\0${canonicalize(signedMetadata)}`, "utf8"), publicKeyPem, Buffer.from(receipt.signature, "base64url"));
  } catch { return false; }
}

function chainHeadPayload(head: Omit<SignedChainHead, "signature">): string {
  return canonicalize(head);
}

export function signChainHead(input: Omit<SignedChainHead, "signature">, signing: SigningMaterial): SignedChainHead {
  if (input.keyId !== signing.signingKeyId) throw new Error("Chain head key id does not match signing material");
  const signature = sign(null, Buffer.from(`invock-chain-head-v1\0${chainHeadPayload(input)}`, "utf8"), signing.privateKeyPem);
  return { ...input, signature: signature.toString("base64url") };
}

export function verifyChainHead(head: SignedChainHead, publicKeyPem: string): boolean {
  try {
    const { signature, ...payload } = head;
    return verify(null, Buffer.from(`invock-chain-head-v1\0${chainHeadPayload(payload)}`, "utf8"), publicKeyPem, Buffer.from(signature, "base64url"));
  } catch { return false; }
}

export function makeReceiptPayload(input: { instanceId: string; sequence: number; envelope: ActionEnvelope; decision: PolicyDecision; upstreamForwarded: boolean; previousReceiptHash: string | null; upstreamResultDigest?: string; approvalId?: string; now: Date } & ReceiptMetadata): ReceiptPayload {
  assertReceiptMetadata(input);
  return {
    receiptVersion: "1.0", receiptId: newId("rcpt"), instanceId: input.instanceId, sequence: input.sequence, createdAt: input.now.toISOString(), invocationId: input.envelope.invocationId, sessionId: input.envelope.sessionId,
    principalId: input.envelope.subject.principalId, serverId: input.envelope.target.serverId, toolName: input.envelope.target.toolName, argumentsDigest: input.envelope.integrity.argumentsDigest,
    envelopeDigest: createHash("sha256").update(canonicalize(input.envelope)).digest("base64url"), policyDigest: input.decision.policyDigest, toolSchemaDigest: input.envelope.target.toolSchemaDigest,
    lineageDigest: digestJson(input.envelope.lineage), lineageReferences: input.envelope.lineage.map(reference => ({ sourceInvocationId: reference.sourceInvocationId, labels: [...reference.labels], matchedFingerprintIds: [...reference.matchedFingerprintIds], matchKinds: [...reference.matchKinds], fingerprintProofDigest: reference.fingerprintProofDigest, ...(reference.taintRecordId ? { taintRecordId: reference.taintRecordId } : {}), ...(reference.expiresAt ? { expiresAt: reference.expiresAt } : {}) })),
    verdict: input.decision.verdict, matchedRuleIds: [...input.decision.matchedRuleIds], reasonCodes: [...input.decision.reasonCodes], upstreamForwarded: input.upstreamForwarded,
    ...(input.upstreamResultDigest ? { upstreamResultDigest: input.upstreamResultDigest } : {}), ...(input.approvalId ? { approvalId: input.approvalId } : {}),
    ...(input.intentCapsuleDigest ? { intentCapsuleDigest: input.intentCapsuleDigest } : {}), ...(input.capabilityLeaseChainDigest ? { capabilityLeaseChainDigest: input.capabilityLeaseChainDigest } : {}), ...(input.effectiveAuthorityDigest ? { effectiveAuthorityDigest: input.effectiveAuthorityDigest } : {}), ...(input.authorityBindingDigest ? { authorityBindingDigest: input.authorityBindingDigest } : {}), ...(input.containmentRunId ? { containmentRunId: input.containmentRunId } : {}), ...(input.containmentRequestDigest ? { containmentRequestDigest: input.containmentRequestDigest } : {}), ...(input.containmentProfileDigest ? { containmentProfileDigest: input.containmentProfileDigest } : {}), ...(input.arenaRunId ? { arenaRunId: input.arenaRunId } : {}), ...(input.policyDraftDigest ? { policyDraftDigest: input.policyDraftDigest } : {}), ...(input.protocolProfileId ? { protocolProfileId: input.protocolProfileId } : {}), previousReceiptHash: input.previousReceiptHash,
    ...(input.identityDigest ? { identityDigest: input.identityDigest } : {}), ...(input.sessionDigest ? { sessionDigest: input.sessionDigest } : {}), ...(input.projectDigest ? { projectDigest: input.projectDigest } : {}), ...(input.agentDigest ? { agentDigest: input.agentDigest } : {}), ...(input.identityBindingDigest ? { identityBindingDigest: input.identityBindingDigest } : {}),
    ...(input.attestationDigest ? { attestationDigest: input.attestationDigest } : {}),
  };
}

function canonicalDigest(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error(`${name} must be a canonical SHA-256 digest`);
}

export function assertReceiptMetadata(metadata: ReceiptMetadata): void {
  const authority = [metadata.intentCapsuleDigest, metadata.capabilityLeaseChainDigest, metadata.effectiveAuthorityDigest].filter(value => value !== undefined);
  if (authority.length !== 0 && authority.length !== 3) throw new Error("INCOMPLETE_AUTHORITY_BINDING");
  if (metadata.authorityBindingDigest !== undefined && authority.length !== 3) throw new Error("INCOMPLETE_AUTHORITY_BINDING");
  for (const [name, value] of Object.entries({ intentCapsuleDigest: metadata.intentCapsuleDigest, capabilityLeaseChainDigest: metadata.capabilityLeaseChainDigest, effectiveAuthorityDigest: metadata.effectiveAuthorityDigest, authorityBindingDigest: metadata.authorityBindingDigest, identityDigest: metadata.identityDigest, sessionDigest: metadata.sessionDigest, projectDigest: metadata.projectDigest, agentDigest: metadata.agentDigest, identityBindingDigest: metadata.identityBindingDigest, attestationDigest: metadata.attestationDigest, containmentRequestDigest: metadata.containmentRequestDigest, containmentProfileDigest: metadata.containmentProfileDigest })) {
    if (value !== undefined) canonicalDigest(value, name);
  }
  if (metadata.containmentRunId !== undefined && (typeof metadata.containmentRunId !== "string" || metadata.containmentRunId.length === 0 || metadata.containmentRunId.length > 256)) throw new Error("INVALID_CONTAINMENT_BINDING");
  if (metadata.containmentRunId === undefined && (metadata.containmentRequestDigest !== undefined || metadata.containmentProfileDigest !== undefined)) throw new Error("INVALID_CONTAINMENT_BINDING");
  if (metadata.containmentRunId !== undefined && (metadata.containmentRequestDigest === undefined || metadata.containmentProfileDigest === undefined)) throw new Error("INCOMPLETE_CONTAINMENT_BINDING");
  const identity = [metadata.identityDigest, metadata.sessionDigest, metadata.projectDigest, metadata.agentDigest, metadata.identityBindingDigest].filter(value => value !== undefined);
  if (identity.length !== 0 && identity.length !== 5) throw new Error("INCOMPLETE_IDENTITY_BINDING");
  if (identity.length === 5) assertIdentityEvidenceBinding({ identityDigest: metadata.identityDigest!, sessionDigest: metadata.sessionDigest!, projectDigest: metadata.projectDigest!, agentDigest: metadata.agentDigest!, bindingDigest: metadata.identityBindingDigest! } satisfies IdentityEvidenceBinding);
}
