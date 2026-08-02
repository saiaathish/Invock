import { sign, verify } from "node:crypto";
import type { InvockStore } from "../storage/store.js";
import { verifyChainHead, verifyReceipt, type ReceiptPayload, type SignedChainHead, type SignedReceipt } from "../storage/receipts.js";
import { canonicalize, digestJson } from "../core/canonical.js";
import type { LineageReference } from "../core/types.js";
import { fingerprintProofDigest } from "../core/lineage.js";
import type { DetachedFingerprintProof, FingerprintKind } from "../core/lineage.js";
import { isValidContainmentTelemetry, unavailableTelemetry } from "../containment/types.js";
import { verifyContainmentRun, type ContainmentRunRecord } from "../containment/lifecycle.js";

export type EvidenceFormat = "json" | "ndjson" | "markdown";

export interface RedactedLineageReference {
  sourceInvocationId: string;
  labels: string[];
  matchedFingerprintIds: string[];
  matchKinds: string[];
  taintRecordId?: string;
  expiresAt?: string;
  fingerprintProofDigest?: string;
}

export interface RedactedReceipt {
  receiptId: string;
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
  lineageReferences: RedactedLineageReference[];
  verdict: string;
  matchedRuleIds: string[];
  reasonCodes: string[];
  upstreamForwarded: boolean;
  previousReceiptHash: string | null;
  receiptHash: string;
  signingKeyId: string;
  signature: string;
  containmentRunId?: string;
  containmentRequestDigest?: string;
  containmentProfileDigest?: string;
}

export interface EvidenceReceipt extends RedactedReceipt { signedReceipt: SignedReceipt; }

export interface LineageProof {
  taintRecordId: string;
  sourceInvocationId: string;
  sessionId: string;
  labels: string[];
  expiresAt: string;
  fingerprintProofDigest: string;
  fingerprints: DetachedFingerprintProof[];
}

export interface ContainmentEvidenceRecord {
  formatVersion: "invock/containment-evidence/v1";
  runId: string;
  invocationId: string;
  sessionId: string;
  requestDigest: string;
  profileDigest: string;
  command: string;
  recordDigest: string;
  containmentIntegrity: { algorithm: "Ed25519"; keyId: string; publicKeyPem: string; signature: string };
  result: {
    status: ContainmentRunRecord["result"]["status"];
    reasonCodes: string[];
    durationMs: number;
    stdoutDigest: string;
    stderrDigest: string;
    stdoutBytes: number;
    stderrBytes: number;
    cleanup?: ContainmentRunRecord["result"]["cleanup"];
    exitCode?: number;
    signal?: string;
    capabilities: ContainmentRunRecord["result"]["capabilities"];
    telemetry: NonNullable<ContainmentRunRecord["result"]["telemetry"]>;
  };
  signingKeyId: string;
  signature: string;
}

export interface EvidenceBundle {
  formatVersion: "invock/evidence-bundle/v1";
  sessionId?: string;
  publicVerificationKey: string;
  publicVerificationKeys: Array<{ keyId: string; publicKeyPem: string }>;
  chainHead: Pick<SignedChainHead, "chainId" | "receiptCount" | "lastSequence" | "lastReceiptHash" | "keyId" | "updatedAt" | "signature"> | null;
  receipts: EvidenceReceipt[];
  lineageProofs: LineageProof[];
  containmentRuns: ContainmentEvidenceRecord[];
  digests: { policy: string[]; intent: string[]; lease: string[]; toolSchema: string[]; policyDraft: string[]; lineage: string[] };
  verificationInstructions: string[];
  unsupportedIntegrations: string[];
}

const unsupportedIntegrations = ["enterprise-cloud-control-plane", "SSO/SCIM", "remote-evidence-anchoring"];

function safeString(value: unknown): string {
  return String(value).replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gu, "[REDACTED_PRIVATE_KEY]").replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/giu, "Bearer [REDACTED_TOKEN]");
}

function uniqueSorted(values: readonly string[]): string[] { return [...new Set(values)].sort(); }

function redactReceipt(receipt: SignedReceipt): RedactedReceipt {
  const payload = receipt.payload;
  return {
    receiptId: safeString(payload.receiptId), sequence: payload.sequence, createdAt: safeString(payload.createdAt), invocationId: safeString(payload.invocationId), sessionId: safeString(payload.sessionId),
    principalId: safeString(payload.principalId), serverId: safeString(payload.serverId), toolName: safeString(payload.toolName), argumentsDigest: safeString(payload.argumentsDigest), envelopeDigest: safeString(payload.envelopeDigest),
    policyDigest: safeString(payload.policyDigest), toolSchemaDigest: safeString(payload.toolSchemaDigest), lineageDigest: safeString(payload.lineageDigest), lineageReferences: payload.lineageReferences.map(reference => ({ sourceInvocationId: safeString(reference.sourceInvocationId), labels: reference.labels.map(safeString), matchedFingerprintIds: reference.matchedFingerprintIds.map(safeString), matchKinds: reference.matchKinds.map(safeString) as LineageReference["matchKinds"], ...(reference.taintRecordId ? { taintRecordId: safeString(reference.taintRecordId) } : {}), ...(reference.expiresAt ? { expiresAt: safeString(reference.expiresAt) } : {}), ...(reference.fingerprintProofDigest ? { fingerprintProofDigest: safeString(reference.fingerprintProofDigest) } : {}) })), verdict: safeString(payload.verdict), matchedRuleIds: payload.matchedRuleIds.map(safeString), reasonCodes: payload.reasonCodes.map(safeString), upstreamForwarded: payload.upstreamForwarded,
    previousReceiptHash: payload.previousReceiptHash ? safeString(payload.previousReceiptHash) : null, receiptHash: safeString(receipt.receiptHash), signingKeyId: safeString(receipt.signingKeyId), signature: safeString(receipt.signature),
    ...(payload.containmentRunId ? { containmentRunId: safeString(payload.containmentRunId) } : {}),
    ...(payload.containmentRequestDigest ? { containmentRequestDigest: safeString(payload.containmentRequestDigest) } : {}),
    ...(payload.containmentProfileDigest ? { containmentProfileDigest: safeString(payload.containmentProfileDigest) } : {}),
  };
}

function evidenceReceipt(receipt: SignedReceipt): EvidenceReceipt {
  return { ...redactReceipt(receipt), signedReceipt: receipt };
}

function chainHeadForExport(head: SignedChainHead | null): EvidenceBundle["chainHead"] {
  if (!head) return null;
  return { chainId: safeString(head.chainId), receiptCount: head.receiptCount, lastSequence: head.lastSequence, lastReceiptHash: head.lastReceiptHash ? safeString(head.lastReceiptHash) : null, keyId: safeString(head.keyId), updatedAt: safeString(head.updatedAt), signature: safeString(head.signature) };
}

function containmentEvidenceForExport(store: InvockStore, record: ContainmentRunRecord): ContainmentEvidenceRecord {
  const result = {
    status: record.result.status,
    reasonCodes: record.result.reasonCodes.map(safeString),
    durationMs: record.result.durationMs,
    stdoutDigest: digestJson(record.result.stdout),
    stderrDigest: digestJson(record.result.stderr),
    stdoutBytes: Buffer.byteLength(record.result.stdout, "utf8"),
    stderrBytes: Buffer.byteLength(record.result.stderr, "utf8"),
    ...(record.result.cleanup !== undefined ? { cleanup: record.result.cleanup } : {}),
    ...(record.result.exitCode !== undefined ? { exitCode: record.result.exitCode } : {}),
    ...(record.result.signal !== undefined ? { signal: safeString(record.result.signal) } : {}),
    capabilities: record.result.capabilities,
    telemetry: record.result.telemetry ?? unavailableTelemetry("legacy_record"),
  } satisfies ContainmentEvidenceRecord["result"];
  const unsigned = {
    formatVersion: "invock/containment-evidence/v1" as const,
    runId: safeString(record.runId), invocationId: safeString(record.invocationId), sessionId: safeString(record.sessionId), requestDigest: safeString(record.requestDigest), profileDigest: safeString(record.profileDigest), command: safeString(record.command), recordDigest: safeString(record.integrity.recordDigest),
    containmentIntegrity: { algorithm: "Ed25519" as const, keyId: safeString(record.integrity.keyId), publicKeyPem: record.integrity.publicKeyPem, signature: safeString(record.integrity.signature) }, result,
    signingKeyId: store.signing.signingKeyId,
  } satisfies Omit<ContainmentEvidenceRecord, "signature">;
  const signature = sign(null, Buffer.from(`invock-containment-evidence-v1\0${canonicalize(unsigned)}`, "utf8"), store.signing.privateKeyPem).toString("base64url");
  return { ...unsigned, signature };
}

export function buildEvidenceBundle(store: InvockStore, sessionId?: string): EvidenceBundle {
  if (sessionId !== undefined && (typeof sessionId !== "string" || sessionId.length === 0 || sessionId.length > 256)) throw new Error("sessionId must be a bounded non-empty string");
  const receipts = store.listReceipts().filter(item => sessionId === undefined || item.payload.sessionId === sessionId).sort((a, b) => a.payload.sequence - b.payload.sequence).map(evidenceReceipt);
  const allReceipts = receipts;
  const expansionRecords = store.listExpansionRecords();
  const intent = expansionRecords.filter(item => item.recordType === "intent_capsule").map(item => item.digest);
  const lease = expansionRecords.filter(item => item.recordType === "capability_lease").map(item => item.digest);
  const policyDraft = expansionRecords.filter(item => item.recordType === "policy_draft").map(item => item.digest);
  const containmentIds = new Set(receipts.flatMap(item => item.signedReceipt.payload.containmentRunId ? [item.signedReceipt.payload.containmentRunId] : []));
  const boundContainmentRuns: ContainmentRunRecord[] = [...containmentIds].map(runId => {
    const stored = store.getExpansionRecord(runId);
    if (!stored || stored.recordType !== "containment_run" || stored.payload === null || typeof stored.payload !== "object" || !verifyContainmentRun(stored.payload as ContainmentRunRecord, store.trustedContainmentKeys)) throw new Error("CONTAINMENT_EVIDENCE_MISSING");
    const record = stored.payload as ContainmentRunRecord;
    if (record.runId !== runId || record.invocationId === undefined || record.sessionId === undefined || record.profileDigest === undefined || /PRIVATE KEY|Bearer\s+[^\s]+|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/iu.test(JSON.stringify(record))) throw new Error("CONTAINMENT_EVIDENCE_UNSAFE");
    return record;
  });
  const containmentRuns = boundContainmentRuns.map(record => containmentEvidenceForExport(store, record));
  const lineageReferences = receipts.flatMap(item => item.signedReceipt.payload.lineageReferences);
  const referencedTaintRecords = new Set<string>();
  for (const reference of lineageReferences) {
    if (!reference.taintRecordId) continue;
    referencedTaintRecords.add(reference.taintRecordId);
  }
  const lineageProofs: LineageProof[] = store.listLineageEvidence(sessionId).flatMap(record => {
    if (!referencedTaintRecords.has(record.taintRecordId)) return [];
    const rows = store.db.prepare("SELECT fingerprint_id, kind, digest, source_length FROM taint_fingerprints WHERE taint_record_id = ? ORDER BY fingerprint_id").all(record.taintRecordId) as Array<{ fingerprint_id: string; kind: FingerprintKind; digest: Uint8Array; source_length: number }>;
    const fingerprints = rows.map(row => ({ fingerprintId: safeString(row.fingerprint_id), kind: row.kind, digest: Buffer.from(row.digest).toString("base64url"), sourceLength: row.source_length } satisfies DetachedFingerprintProof));
    if (fingerprints.length === 0 || fingerprints.length > 256 || fingerprints.some(item => item.digest.length !== 43 || !Number.isSafeInteger(item.sourceLength) || item.sourceLength < 1 || item.sourceLength > 4096)) throw new Error("LINEAGE_EVIDENCE_INVALID");
    return [{ taintRecordId: record.taintRecordId, sourceInvocationId: record.sourceInvocationId, sessionId: record.sessionId, labels: record.labels.map(safeString), expiresAt: safeString(record.expiresAt), fingerprintProofDigest: fingerprintProofDigest(fingerprints), fingerprints }];
  });
  if (lineageProofs.length !== referencedTaintRecords.size || lineageProofs.some(proof => proof.fingerprints.length === 0)) throw new Error("LINEAGE_EVIDENCE_MISSING");
  return {
    formatVersion: "invock/evidence-bundle/v1",
    ...(sessionId !== undefined ? { sessionId } : {}),
    publicVerificationKey: store.signing.publicKeyPem,
    publicVerificationKeys: store.listSigningPublicKeys().map(item => ({ keyId: safeString(item.keyId), publicKeyPem: item.publicKeyPem })),
    chainHead: chainHeadForExport(store.receiptChainStatus().chainHead),
    receipts: allReceipts,
    lineageProofs,
    containmentRuns,
    digests: {
      policy: uniqueSorted(allReceipts.map(item => item.policyDigest)),
      intent: uniqueSorted([...intent]),
      lease: uniqueSorted([...lease]),
      toolSchema: uniqueSorted(allReceipts.map(item => item.toolSchemaDigest)),
      policyDraft: uniqueSorted([...policyDraft]),
      lineage: uniqueSorted(allReceipts.map(item => item.lineageDigest)),
    },
    verificationInstructions: [
      "Keep this bundle with the source database and key directory metadata; the bundle contains public verification material only.",
      "Run `invock receipts verify --database <database> --key-directory <key-directory>` against the source store.",
      "Verify each receipt signature with the public key whose keyId matches the receipt signingKeyId and verify the previousReceiptHash chain order.",
      "Verify every lineage reference against its keyed, redacted lineage proof and its source receipt before relying on a decision.",
      "Containment entries are signed metadata proofs; raw stdout and stderr are intentionally omitted from this export.",
      "Compare policy, intent, lease, tool-schema, and lineage digests with the approved local records before relying on a decision.",
    ],
    unsupportedIntegrations: [...unsupportedIntegrations],
  };
}

function json(value: unknown): string { return JSON.stringify(value, null, 2); }

export function renderEvidenceBundle(bundle: EvidenceBundle, format: EvidenceFormat): string {
  if (format === "json") return `${json(bundle)}\n`;
  if (format === "ndjson") {
    const lines: unknown[] = [
      { type: "bundle", formatVersion: bundle.formatVersion, ...(bundle.sessionId !== undefined ? { sessionId: bundle.sessionId } : {}) },
      { type: "verification", publicVerificationKey: bundle.publicVerificationKey, publicVerificationKeys: bundle.publicVerificationKeys, chainHead: bundle.chainHead, instructions: bundle.verificationInstructions },
      { type: "digests", ...bundle.digests },
      { type: "lineage-proofs", items: bundle.lineageProofs },
      { type: "containment-runs", items: bundle.containmentRuns },
      { type: "unsupported-integrations", items: bundle.unsupportedIntegrations },
      ...bundle.receipts.map(receipt => ({ type: "receipt", receipt })),
    ];
    return `${lines.map(line => JSON.stringify(line)).join("\n")}\n`;
  }
  if (format === "markdown") {
    const session = bundle.sessionId ? ` for session \`${bundle.sessionId}\`` : "";
    const receiptRows = bundle.receipts.length === 0 ? "| _none_ | | | |\n" : bundle.receipts.map(item => `| ${item.sequence} | ${item.verdict} | ${item.toolName} | ${item.receiptHash} |`).join("\n") + "\n";
    return `# Invock evidence bundle\n\nFormat: \`${bundle.formatVersion}\`\n\nScope${session}. This export is local evidence, not a cloud or enterprise control-plane record.\n\n## Chain\n\n- Chain ID: \`${bundle.chainHead?.chainId ?? "not available"}\`\n- Receipt count: ${bundle.chainHead?.receiptCount ?? 0}\n- Last sequence: ${bundle.chainHead?.lastSequence ?? 0}\n- Signing key ID: \`${bundle.chainHead?.keyId ?? "not available"}\`\n- Verification keys: ${bundle.publicVerificationKeys.length}\n- Containment runs: ${bundle.containmentRuns.length}\n\n## Receipts\n\n| Sequence | Verdict | Tool | Receipt hash |\n| ---: | --- | --- | --- |\n${receiptRows}\n## Digests\n\n- Policy: ${bundle.digests.policy.join(", ") || "none"}\n- Intent: ${bundle.digests.intent.join(", ") || "none"}\n- Lease: ${bundle.digests.lease.join(", ") || "none"}\n- Tool schema: ${bundle.digests.toolSchema.join(", ") || "none"}\n- Policy draft: ${bundle.digests.policyDraft.join(", ") || "none"}\n- Lineage: ${bundle.digests.lineage.join(", ") || "none"}\n\n## Verification\n\n${bundle.verificationInstructions.map(item => `- ${item}`).join("\n")}\n\n## Explicit limits\n\n${bundle.unsupportedIntegrations.map(item => `- ${item}: unsupported in this local-first build`).join("\n")}\n\nThe private signing key, raw invocation arguments, and secret values are intentionally excluded.\n`;
  }
  throw new Error(`unsupported evidence format: ${format}`);
}

const digest = /^[A-Za-z0-9_-]{43}$/u;
const base64Url = /^[A-Za-z0-9_-]+$/u;
const receiptKeys = new Set(["receiptVersion", "receiptId", "instanceId", "sequence", "createdAt", "invocationId", "sessionId", "principalId", "serverId", "toolName", "argumentsDigest", "envelopeDigest", "policyDigest", "toolSchemaDigest", "lineageDigest", "lineageReferences", "verdict", "matchedRuleIds", "reasonCodes", "upstreamForwarded", "upstreamResultDigest", "approvalId", "intentCapsuleDigest", "capabilityLeaseChainDigest", "effectiveAuthorityDigest", "authorityBindingDigest", "identityDigest", "sessionDigest", "projectDigest", "agentDigest", "identityBindingDigest", "attestationDigest", "containmentRunId", "containmentRequestDigest", "containmentProfileDigest", "arenaRunId", "policyDraftDigest", "protocolProfileId", "previousReceiptHash"]);
const lineageReferenceKeys = new Set(["sourceInvocationId", "labels", "matchedFingerprintIds", "matchKinds", "taintRecordId", "expiresAt", "fingerprintProofDigest"]);
const matchKindValues = new Set<FingerprintKind>(["exact", "base64", "base64url", "urlencoded", "hex", "gzip", "deflate", "brotli", "sha256", "sha1", "md5", "hmac_sha256", "reversed", "rot13"]);
const redactedReceiptKeys = new Set(["receiptId", "sequence", "createdAt", "invocationId", "sessionId", "principalId", "serverId", "toolName", "argumentsDigest", "envelopeDigest", "policyDigest", "toolSchemaDigest", "lineageDigest", "lineageReferences", "verdict", "matchedRuleIds", "reasonCodes", "upstreamForwarded", "previousReceiptHash", "receiptHash", "signingKeyId", "signature", "containmentRunId", "containmentRequestDigest", "containmentProfileDigest", "signedReceipt"]);

function exactObject(value: unknown, keys: Set<string>): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every(key => keys.has(key));
}

function validLineageReference(value: unknown): value is LineageReference {
  if (!exactObject(value, lineageReferenceKeys)) return false;
  const reference = value as Record<string, unknown>;
  if (typeof reference.sourceInvocationId !== "string" || reference.sourceInvocationId.length === 0 || reference.sourceInvocationId.length > 256) return false;
  if (!Array.isArray(reference.labels) || reference.labels.length === 0 || !reference.labels.every(item => typeof item === "string" && item.length > 0 && item.length <= 128)) return false;
  if (!Array.isArray(reference.matchedFingerprintIds) || reference.matchedFingerprintIds.length === 0 || !reference.matchedFingerprintIds.every(item => typeof item === "string" && item.length > 0 && item.length <= 256)) return false;
  if (new Set(reference.matchedFingerprintIds as string[]).size !== (reference.matchedFingerprintIds as string[]).length) return false;
  if (!Array.isArray(reference.matchKinds) || reference.matchKinds.length === 0 || !reference.matchKinds.every(item => typeof item === "string" && matchKindValues.has(item as FingerprintKind))) return false;
  if (new Set(reference.matchKinds as string[]).size !== (reference.matchKinds as string[]).length) return false;
  if (reference.fingerprintProofDigest !== undefined && (typeof reference.fingerprintProofDigest !== "string" || !digest.test(reference.fingerprintProofDigest))) return false;
  // Real gateway lineage is only detached-verifiable when its persisted taint
  // record and retention boundary are included in the signed reference.
  if (typeof reference.taintRecordId !== "string" || reference.taintRecordId.length === 0 || reference.taintRecordId.length > 256) return false;
  if (typeof reference.expiresAt !== "string" || !Number.isFinite(Date.parse(reference.expiresAt))) return false;
  return true;
}

function validPayload(value: unknown): value is ReceiptPayload {
  if (!exactObject(value, receiptKeys)) return false;
  const p = value as Record<string, unknown>;
  if (p.receiptVersion !== "1.0" || !Number.isSafeInteger(p.sequence) || (p.sequence as number) < 1 || typeof p.receiptId !== "string" || typeof p.instanceId !== "string" || typeof p.createdAt !== "string" || !Number.isFinite(Date.parse(p.createdAt as string)) || typeof p.invocationId !== "string" || typeof p.sessionId !== "string" || typeof p.principalId !== "string" || typeof p.serverId !== "string" || typeof p.toolName !== "string" || typeof p.verdict !== "string" || typeof p.upstreamForwarded !== "boolean" || !Array.isArray(p.matchedRuleIds) || !p.matchedRuleIds.every(item => typeof item === "string") || !Array.isArray(p.reasonCodes) || !p.reasonCodes.every(item => typeof item === "string") || (p.previousReceiptHash !== null && typeof p.previousReceiptHash !== "string")) return false;
  for (const key of ["argumentsDigest", "envelopeDigest", "policyDigest", "toolSchemaDigest"]) if (typeof p[key] !== "string") return false;
  if (typeof p.lineageDigest !== "string" || !digest.test(p.lineageDigest) || !Array.isArray(p.lineageReferences) || !p.lineageReferences.every(validLineageReference) || digestJson(p.lineageReferences) !== p.lineageDigest) return false;
  for (const key of ["upstreamResultDigest", "intentCapsuleDigest", "capabilityLeaseChainDigest", "effectiveAuthorityDigest", "authorityBindingDigest", "identityDigest", "sessionDigest", "projectDigest", "agentDigest", "identityBindingDigest", "attestationDigest", "containmentRequestDigest", "containmentProfileDigest", "policyDraftDigest"]) if (p[key] !== undefined && (typeof p[key] !== "string" || !digest.test(p[key]))) return false;
  if (p.containmentRunId !== undefined && (typeof p.containmentRunId !== "string" || p.containmentRunId.length === 0 || p.containmentRunId.length > 256)) return false;
  return true;
}

function validPublicVerificationKeys(value: unknown, current: string): Map<string, string> | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const result = new Map<string, string>();
  for (const item of value) {
    if (!exactObject(item, new Set(["keyId", "publicKeyPem"]))) return undefined;
    const entry = item as Record<string, unknown>;
    if (typeof entry.keyId !== "string" || entry.keyId.length === 0 || entry.keyId.length > 256 || typeof entry.publicKeyPem !== "string" || !entry.publicKeyPem.includes("PUBLIC KEY") || result.has(entry.keyId)) return undefined;
    result.set(entry.keyId, entry.publicKeyPem);
  }
  if (![...result.values()].includes(current)) return undefined;
  return result;
}

function validLineageProof(value: unknown): value is LineageProof {
  if (!exactObject(value, new Set(["taintRecordId", "sourceInvocationId", "sessionId", "labels", "expiresAt", "fingerprintProofDigest", "fingerprints"]))) return false;
  const proof = value as Record<string, unknown>;
  if (typeof proof.taintRecordId !== "string" || proof.taintRecordId.length === 0 || proof.taintRecordId.length > 256 || typeof proof.sourceInvocationId !== "string" || proof.sourceInvocationId.length === 0 || proof.sourceInvocationId.length > 256 || typeof proof.sessionId !== "string" || proof.sessionId.length === 0 || proof.sessionId.length > 256 || typeof proof.expiresAt !== "string" || !Number.isFinite(Date.parse(proof.expiresAt)) || typeof proof.fingerprintProofDigest !== "string" || !digest.test(proof.fingerprintProofDigest)) return false;
  if (!Array.isArray(proof.labels) || proof.labels.length === 0 || !proof.labels.every(item => typeof item === "string" && item.length > 0 && item.length <= 128)) return false;
  if (!Array.isArray(proof.fingerprints) || proof.fingerprints.length === 0 || proof.fingerprints.length > 256) return false;
  const seen = new Set<string>();
  for (const item of proof.fingerprints) {
    if (!exactObject(item, new Set(["fingerprintId", "kind", "digest", "sourceLength"]))) return false;
    const fingerprint = item as Record<string, unknown>;
    if (typeof fingerprint.fingerprintId !== "string" || fingerprint.fingerprintId.length === 0 || fingerprint.fingerprintId.length > 256 || typeof fingerprint.kind !== "string" || !matchKindValues.has(fingerprint.kind as FingerprintKind) || typeof fingerprint.digest !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(fingerprint.digest) || !Number.isSafeInteger(fingerprint.sourceLength) || (fingerprint.sourceLength as number) < 1 || (fingerprint.sourceLength as number) > 4096 || seen.has(fingerprint.fingerprintId)) return false;
    seen.add(fingerprint.fingerprintId);
  }
  return fingerprintProofDigest(proof.fingerprints as DetachedFingerprintProof[]) === proof.fingerprintProofDigest;
}

function validContainmentEvidence(value: unknown): value is ContainmentEvidenceRecord {
  const keys = new Set(["formatVersion", "runId", "invocationId", "sessionId", "requestDigest", "profileDigest", "command", "recordDigest", "containmentIntegrity", "result", "signingKeyId", "signature"]);
  if (!exactObject(value, keys)) return false;
  const record = value as Record<string, unknown>;
  if (record.formatVersion !== "invock/containment-evidence/v1" || typeof record.runId !== "string" || record.runId.length === 0 || typeof record.invocationId !== "string" || record.invocationId.length === 0 || typeof record.sessionId !== "string" || record.sessionId.length === 0 || typeof record.requestDigest !== "string" || !digest.test(record.requestDigest) || typeof record.profileDigest !== "string" || !digest.test(record.profileDigest) || typeof record.command !== "string" || record.command.length === 0 || typeof record.recordDigest !== "string" || !digest.test(record.recordDigest) || typeof record.signingKeyId !== "string" || record.signingKeyId.length === 0 || typeof record.signature !== "string" || !base64Url.test(record.signature)) return false;
  if (!exactObject(record.containmentIntegrity, new Set(["algorithm", "keyId", "publicKeyPem", "signature"]))) return false;
  const integrity = record.containmentIntegrity as Record<string, unknown>;
  if (integrity.algorithm !== "Ed25519" || typeof integrity.keyId !== "string" || integrity.keyId.length === 0 || typeof integrity.publicKeyPem !== "string" || !integrity.publicKeyPem.includes("PUBLIC KEY") || integrity.publicKeyPem.includes("PRIVATE KEY") || typeof integrity.signature !== "string" || !base64Url.test(integrity.signature) || integrity.keyId !== record.containmentIntegrity.keyId || record.recordDigest.length !== 43) return false;
  if (!exactObject(record.result, new Set(["status", "reasonCodes", "durationMs", "stdoutDigest", "stderrDigest", "stdoutBytes", "stderrBytes", "cleanup", "exitCode", "signal", "capabilities", "telemetry"]))) return false;
  const result = record.result as Record<string, unknown>;
  if (typeof result.status !== "string" || !["completed", "failed", "timed_out", "denied", "unsupported"].includes(result.status) || !Array.isArray(result.reasonCodes) || !result.reasonCodes.every(item => typeof item === "string") || typeof result.durationMs !== "number" || !Number.isFinite(result.durationMs) || result.durationMs < 0 || typeof result.stdoutDigest !== "string" || !digest.test(result.stdoutDigest) || typeof result.stderrDigest !== "string" || !digest.test(result.stderrDigest) || !Number.isSafeInteger(result.stdoutBytes) || (result.stdoutBytes as number) < 0 || !Number.isSafeInteger(result.stderrBytes) || (result.stderrBytes as number) < 0 || (result.cleanup !== undefined && !["completed", "failed", "not_run"].includes(result.cleanup as string)) || (result.exitCode !== undefined && !Number.isSafeInteger(result.exitCode)) || (result.signal !== undefined && typeof result.signal !== "string")) return false;
  if (!exactObject(result.capabilities, new Set(["sandbox", "network", "readOnlyRoot", "nonRoot", "noNewPrivileges"]))) return false;
  const capabilities = result.capabilities as Record<string, unknown>;
  return ["available", "unavailable", "not_requested"].includes(String(capabilities.sandbox)) && ["denied", "unknown"].includes(String(capabilities.network)) && typeof capabilities.readOnlyRoot === "boolean" && typeof capabilities.nonRoot === "boolean" && typeof capabilities.noNewPrivileges === "boolean" && isValidContainmentTelemetry(result.telemetry);
}

/** Detached, fail-closed verification. Filtered bundles verify their scoped links, while the global head remains informational. */
export function verifyEvidenceBundle(bundle: unknown): boolean {
  try {
    if (!exactObject(bundle, new Set(["formatVersion", "sessionId", "publicVerificationKey", "publicVerificationKeys", "chainHead", "receipts", "lineageProofs", "containmentRuns", "digests", "verificationInstructions", "unsupportedIntegrations"]))) return false;
    const b = bundle as Record<string, unknown>;
    if (b.formatVersion !== "invock/evidence-bundle/v1" || typeof b.publicVerificationKey !== "string" || !Array.isArray(b.receipts) || !Array.isArray(b.lineageProofs) || !b.lineageProofs.every(validLineageProof) || !Array.isArray(b.containmentRuns) || !b.containmentRuns.every(validContainmentEvidence) || !Array.isArray(b.verificationInstructions) || !b.verificationInstructions.every(item => typeof item === "string") || !Array.isArray(b.unsupportedIntegrations) || !b.unsupportedIntegrations.every(item => typeof item === "string")) return false;
    const publicKeys = validPublicVerificationKeys(b.publicVerificationKeys, b.publicVerificationKey);
    if (!publicKeys) return false;
    const filtered = b.sessionId !== undefined;
    if (filtered && (typeof b.sessionId !== "string" || b.sessionId.length === 0 || b.sessionId.length > 256)) return false;
    const d = b.digests;
    if (!exactObject(d, new Set(["policy", "intent", "lease", "toolSchema", "policyDraft", "lineage"]))) return false;
    for (const key of ["policy", "intent", "lease", "toolSchema", "policyDraft", "lineage"]) if (!Array.isArray((d as Record<string, unknown>)[key]) || !((d as Record<string, unknown>)[key] as unknown[]).every(item => typeof item === "string" && item.length > 0)) return false;
    const receipts = b.receipts as unknown[];
    const lineageProofs = b.lineageProofs as LineageProof[];
    const containmentRuns = b.containmentRuns as ContainmentEvidenceRecord[];
    const containmentById = new Map(containmentRuns.map(record => [record.runId, record]));
    if (containmentById.size !== containmentRuns.length) return false;
    for (const run of containmentRuns) {
      const key = publicKeys.get(run.signingKeyId);
      const { signature: _signature, ...unsigned } = run;
      if (!key || !verify(null, Buffer.from(`invock-containment-evidence-v1\0${canonicalize(unsigned)}`, "utf8"), key, Buffer.from(run.signature, "base64url"))) return false;
    }
    const proofById = new Map(lineageProofs.map(proof => [proof.taintRecordId, proof]));
    if (proofById.size !== lineageProofs.length) return false;
    let previous: string | null = null;
    const seen = new Set<number>();
    const signedReceipts: SignedReceipt[] = [];
    for (const item of receipts) {
      if (!exactObject(item, redactedReceiptKeys)) return false;
      const signed = (item as Record<string, unknown>).signedReceipt;
      if (!exactObject(signed, new Set(["payload", "canonicalization", "hashAlgorithm", "receiptHash", "signatureAlgorithm", "signingKeyId", "signature"])) || !validPayload((signed as Record<string, unknown>).payload) || typeof (signed as Record<string, unknown>).receiptHash !== "string" || typeof (signed as Record<string, unknown>).signingKeyId !== "string" || typeof (signed as Record<string, unknown>).signature !== "string" || !base64Url.test((signed as Record<string, unknown>).signature as string)) return false;
      const signedReceipt = signed as unknown as SignedReceipt;
      const payload = signedReceipt.payload;
      const { signedReceipt: _nestedSignedReceipt, ...projection } = item as Record<string, unknown>;
      if (digestJson(projection) !== digestJson(redactReceipt(signedReceipt))) return false;
      if (filtered && payload.sessionId !== b.sessionId) return false;
      if (seen.has(payload.sequence) || (!filtered && payload.sequence !== seen.size + 1)) return false;
      const receiptKey = publicKeys.get(signedReceipt.signingKeyId);
      if (!receiptKey || !verifyReceipt(signedReceipt, receiptKey, filtered && seen.size === 0 ? payload.previousReceiptHash : previous, signedReceipt.signingKeyId)) return false;
      if (payload.containmentRunId !== undefined) {
        const run = containmentById.get(payload.containmentRunId);
        if (!run || run.invocationId !== payload.invocationId || run.sessionId !== payload.sessionId || run.requestDigest !== payload.containmentRequestDigest || run.profileDigest !== payload.containmentProfileDigest || run.result.status !== "completed") return false;
      }
      seen.add(payload.sequence); previous = signedReceipt.receiptHash; signedReceipts.push(signedReceipt);
      if (!((d as Record<string, unknown>).policy as string[]).includes(payload.policyDigest) || !((d as Record<string, unknown>).toolSchema as string[]).includes(payload.toolSchemaDigest) || !((d as Record<string, unknown>).lineage as string[]).includes(payload.lineageDigest)) return false;
      for (const [key, digestKey] of [["intentCapsuleDigest", "intent"], ["capabilityLeaseChainDigest", "lease"], ["policyDraftDigest", "policyDraft"]] as const) if (payload[key] !== undefined && !((d as Record<string, unknown>)[digestKey] as string[]).includes(payload[key]!)) return false;
    }
    const receiptByInvocation = new Map(signedReceipts.map(receipt => [receipt.payload.invocationId, receipt]));
    for (const receipt of signedReceipts) {
      const reconstructedLineage = receipt.payload.lineageReferences.map(reference => {
        if (!reference.taintRecordId) return reference;
        const proof = proofById.get(reference.taintRecordId);
        if (!proof) throw new Error("LINEAGE_PROOF_MISSING");
        if (reference.fingerprintProofDigest !== undefined && reference.fingerprintProofDigest !== proof.fingerprintProofDigest) throw new Error("LINEAGE_PROOF_DIGEST_MISMATCH");
        return { ...reference, fingerprintProofDigest: proof.fingerprintProofDigest };
      });
      if (digestJson(reconstructedLineage) !== receipt.payload.lineageDigest) return false;
    }
    const usedFingerprintIds = new Map<string, Set<string>>();
    for (const receipt of signedReceipts) {
      for (const reference of receipt.payload.lineageReferences) {
        const proof = proofById.get(reference.taintRecordId!);
        if (!proof || proof.sourceInvocationId !== reference.sourceInvocationId || proof.sessionId !== receipt.payload.sessionId || digestJson(proof.labels) !== digestJson(reference.labels) || proof.expiresAt !== reference.expiresAt) return false;
        const source = receiptByInvocation.get(reference.sourceInvocationId);
        if (!source || source.payload.sessionId !== receipt.payload.sessionId || !source.payload.upstreamForwarded || Date.parse(source.payload.createdAt) > Date.parse(receipt.payload.createdAt) || Date.parse(receipt.payload.createdAt) > Date.parse(reference.expiresAt!)) return false;
        const fingerprintKinds = new Map(proof.fingerprints.map(item => [item.fingerprintId, item.kind]));
        const kinds = new Set<FingerprintKind>();
        const ids = usedFingerprintIds.get(reference.taintRecordId!) ?? new Set<string>();
        for (const fingerprintId of reference.matchedFingerprintIds) {
          const kind = fingerprintKinds.get(fingerprintId);
          if (!kind) return false;
          kinds.add(kind); ids.add(fingerprintId);
        }
        usedFingerprintIds.set(reference.taintRecordId!, ids);
        if (digestJson([...kinds].sort()) !== digestJson([...reference.matchKinds].sort())) return false;
      }
    }
    if (usedFingerprintIds.size !== proofById.size) return false;
    for (const proof of lineageProofs) {
      const expected = usedFingerprintIds.get(proof.taintRecordId);
      if (!expected || expected.size === 0 || [...expected].some(fingerprintId => !proof.fingerprints.some(item => item.fingerprintId === fingerprintId))) return false;
    }
    const referencedContainmentIds = new Set(signedReceipts.flatMap(receipt => receipt.payload.containmentRunId ? [receipt.payload.containmentRunId] : []));
    if (referencedContainmentIds.size !== containmentById.size || [...containmentById.keys()].some(runId => !referencedContainmentIds.has(runId))) return false;
    const head = b.chainHead;
    if (!exactObject(head, new Set(["chainId", "receiptCount", "lastSequence", "lastReceiptHash", "keyId", "updatedAt", "signature"]))) return false;
    const headKey = head ? publicKeys.get(String(head.keyId)) : undefined;
    if (!head || !headKey || !verifyChainHead(head as unknown as SignedChainHead, headKey)) return false;
    if (!filtered) return head.receiptCount === receipts.length && head.lastSequence === (receipts.length ? (receipts.at(-1) as Record<string, unknown>).sequence : 0) && head.lastReceiptHash === (receipts.length ? ((receipts.at(-1) as Record<string, unknown>).signedReceipt as unknown as SignedReceipt).receiptHash : null);
    return true;
  } catch { return false; }
}
