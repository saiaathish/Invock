import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalize, newId } from "../core/canonical.js";
import type { ActionEnvelope, PolicyDecision, Verdict } from "../core/types.js";

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
  verdict: Verdict;
  matchedRuleIds: string[];
  reasonCodes: string[];
  upstreamForwarded: boolean;
  upstreamResultDigest?: string;
  approvalId?: string;
  previousReceiptHash: string | null;
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
  const signature = sign(null, Buffer.concat([Buffer.from("invock-receipt-signature-v1\0"), hash]), signing.privateKeyPem);
  return { payload, canonicalization: "RFC8785-JCS", hashAlgorithm: "SHA-256", receiptHash: hash.toString("base64url"), signatureAlgorithm: "Ed25519", signingKeyId: signing.signingKeyId, signature: signature.toString("base64url") };
}

export function verifyReceipt(receipt: SignedReceipt, publicKeyPem: string, expectedPrevious: string | null): boolean {
  if (receipt.payload.previousReceiptHash !== expectedPrevious) return false;
  const hash = receiptHash(receipt.payload);
  if (hash.toString("base64url") !== receipt.receiptHash) return false;
  return verify(null, Buffer.concat([Buffer.from("invock-receipt-signature-v1\0"), hash]), publicKeyPem, Buffer.from(receipt.signature, "base64url"));
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

export function makeReceiptPayload(input: { instanceId: string; sequence: number; envelope: ActionEnvelope; decision: PolicyDecision; upstreamForwarded: boolean; previousReceiptHash: string | null; upstreamResultDigest?: string; approvalId?: string; now: Date }): ReceiptPayload {
  return {
    receiptVersion: "1.0", receiptId: newId("rcpt"), instanceId: input.instanceId, sequence: input.sequence, createdAt: input.now.toISOString(), invocationId: input.envelope.invocationId, sessionId: input.envelope.sessionId,
    principalId: input.envelope.subject.principalId, serverId: input.envelope.target.serverId, toolName: input.envelope.target.toolName, argumentsDigest: input.envelope.integrity.argumentsDigest,
    envelopeDigest: createHash("sha256").update(canonicalize(input.envelope)).digest("base64url"), policyDigest: input.decision.policyDigest, toolSchemaDigest: input.envelope.target.toolSchemaDigest,
    verdict: input.decision.verdict, matchedRuleIds: [...input.decision.matchedRuleIds], reasonCodes: [...input.decision.reasonCodes], upstreamForwarded: input.upstreamForwarded,
    ...(input.upstreamResultDigest ? { upstreamResultDigest: input.upstreamResultDigest } : {}), ...(input.approvalId ? { approvalId: input.approvalId } : {}), previousReceiptHash: input.previousReceiptHash,
  };
}