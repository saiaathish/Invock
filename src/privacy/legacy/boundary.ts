import { sign, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { digestJson } from "../../core/canonical.js";
import type { PrivacyProtectionBoundary, LocalLegacyState, LegacySourceType } from "./types.js";
import { loadProviderHistoryRecords } from "./provider-history.js";

export interface EnforcementStartEvidence {
  startedAt?: string;
  sourceType:
    | "SIGNED_PRIVACY_RECEIPT"
    | "SIGNED_ACTIVATION_EVENT"
    | "SIGNED_ZDR_RECEIPT"
    | "TRUSTED_AUDIT_EVENT"
    | "NOT_PROVABLE";
  sourceId?: string;
  sourceDigest?: string;
  verified: boolean;
  reasonCodes: string[];
}

export async function resolveEnforcementStart(
  privacyDir: string,
  publicKeyPem: string
): Promise<EnforcementStartEvidence> {
  const dbPath = join(privacyDir, "db.sqlite");
  if (existsSync(dbPath)) {
    let db: any = null;
    try {
      const { DatabaseSync } = await import("node:sqlite");
      db = new DatabaseSync(dbPath);
      const rows = db.prepare("SELECT receipt_json FROM receipts ORDER BY sequence ASC").all() as any[];
      if (rows && rows.length > 0) {
        for (const row of rows) {
          const receipt = JSON.parse(row.receipt_json);
          const signedMetadata = {
            receiptHash: receipt.receiptHash,
            canonicalization: receipt.canonicalization,
            hashAlgorithm: receipt.hashAlgorithm,
            signatureAlgorithm: receipt.signatureAlgorithm,
            signingKeyId: receipt.signingKeyId
          };
          const { canonicalize } = await import("../../core/canonical.js");
          const isValid = verify(
            null,
            Buffer.from(`invock-receipt-signature-v2\0${canonicalize(signedMetadata)}`, "utf8"),
            publicKeyPem,
            Buffer.from(receipt.signature, "base64url")
          );
          if (isValid) {
            return {
              startedAt: receipt.payload.createdAt,
              sourceType: "SIGNED_PRIVACY_RECEIPT",
              sourceId: receipt.receiptId,
              sourceDigest: receipt.receiptHash,
              verified: true,
              reasonCodes: ["VALID_RECEIPT_FOUND"]
            };
          }
        }
      }
    } catch {
      // Ignore
    } finally {
      if (db) {
        try { db.close(); } catch {}
      }
    }
  }

  const configPath = join(privacyDir, "privacy.json");
  if (existsSync(configPath)) {
    try {
      const config = JSON.parse(readFileSync(configPath, "utf8"));
      if (config.contract && config.contract.signature) {
        const unsigned = {
          id: config.contract.id,
          version: config.contract.version,
          mode: config.contract.mode,
          metadataTtlSeconds: config.contract.metadataTtlSeconds,
          createdAt: config.contract.createdAt,
          notBefore: config.contract.notBefore
        };
        const expectedDigest = digestJson(unsigned);
        const isValid = config.contract.digest === expectedDigest && verify(
          null,
          Buffer.from(`invock-privacy-contract-v1\0${expectedDigest}`, "utf8"),
          config.contract.publicKeyPem,
          Buffer.from(config.contract.signature, "base64url")
        );
        if (isValid) {
          return {
            startedAt: config.contract.createdAt,
            sourceType: "SIGNED_ACTIVATION_EVENT",
            sourceId: config.contract.id,
            sourceDigest: config.contract.digest,
            verified: true,
            reasonCodes: ["VALID_CONTRACT_FOUND"]
          };
        }
      }
    } catch {
      // Ignore
    }
  }

  return { sourceType: "NOT_PROVABLE", verified: false, reasonCodes: ["NO_VALID_EVIDENCE"] };
}

export function createProtectionBoundary(
  installationId: string,
  activePrivacyMode: "LOCAL_ZDR" | "END_TO_END_ZDR",
  localLegacyState: LocalLegacyState,
  selectedLocalScopes: LegacySourceType[],
  findingCounts: { total: number; resolved: number; unresolved: number },
  providerHistory: Array<{ providerId: string; productId: string; state: any; evidenceReference?: string; evidenceDigest?: string; checkedAt?: string }>,
  evidence: EnforcementStartEvidence,
  zdrCertificationDigest: string | undefined,
  metadataDigests?: { scanDigest?: string; remediationPlanDigest?: string; cleanupReceiptDigest?: string }
): Omit<PrivacyProtectionBoundary, "digest" | "keyId" | "signature"> {
  const claimLimitations = [
    "Invock Privacy Onboarding audits supported local legacy artifacts, helps the user remove selected local records, identifies unresolved provider-held history, and creates a signed boundary showing when Invock protection became active.",
    "It does not prove that third parties deleted historical data, and it cannot guarantee physical erasure from storage media."
  ];

  let verdict: "COMPLETE_FOR_SELECTED_LOCAL_SCOPE" | "PARTIAL" | "NOT_VERIFIED" = "NOT_VERIFIED";

  const allLocalResolved = localLegacyState === "VERIFIED_CLEAN_FOR_SELECTED_SCOPE" && findingCounts.unresolved === 0;
  const hasLocalScope = selectedLocalScopes.length > 0;

  if (localLegacyState === "NOT_SCANNED") {
    verdict = "NOT_VERIFIED";
  } else if (localLegacyState === "UNRESOLVED") {
    verdict = "NOT_VERIFIED";
  } else if (hasLocalScope && allLocalResolved && evidence.verified && zdrCertificationDigest) {
    verdict = "COMPLETE_FOR_SELECTED_LOCAL_SCOPE";
  } else {
    verdict = "PARTIAL";
  }

  const boundary: any = {
    id: `boundary_${Date.now()}`,
    version: 1,
    invockInstallationId: installationId,
    enforcementEvidenceType: evidence.sourceType,
    legacyAuditCompletedAt: new Date().toISOString(),
    selectedLocalScopes,
    localLegacyState,
    localFindingsTotal: findingCounts.total,
    localFindingsResolved: findingCounts.resolved,
    localFindingsUnresolved: findingCounts.unresolved,
    providerHistory: providerHistory.map(ph => {
      const phObj: any = {
        providerId: ph.providerId,
        productId: ph.productId,
        state: ph.state,
        checkedAt: ph.checkedAt || new Date().toISOString()
      };
      if (ph.evidenceReference !== undefined) phObj.evidenceReference = ph.evidenceReference;
      if (ph.evidenceDigest !== undefined) phObj.evidenceDigest = ph.evidenceDigest;
      return phObj;
    }),
    activePrivacyMode,
    verdict,
    claimLimitations,
    createdAt: new Date().toISOString()
  };

  if (evidence.startedAt !== undefined) boundary.enforcementStartedAt = evidence.startedAt;
  if (evidence.sourceDigest !== undefined) boundary.enforcementEvidenceDigest = evidence.sourceDigest;
  if (zdrCertificationDigest !== undefined) boundary.zdrCertificationDigest = zdrCertificationDigest;
  if (metadataDigests?.scanDigest !== undefined) boundary.scanDigest = metadataDigests.scanDigest;
  if (metadataDigests?.remediationPlanDigest !== undefined) boundary.remediationPlanDigest = metadataDigests.remediationPlanDigest;
  if (metadataDigests?.cleanupReceiptDigest !== undefined) boundary.cleanupReceiptDigest = metadataDigests.cleanupReceiptDigest;

  return boundary;
}

export function signProtectionBoundary(
  unsignedBoundary: Omit<PrivacyProtectionBoundary, "digest" | "keyId" | "signature">,
  privateKeyPem: string,
  keyId: string
): PrivacyProtectionBoundary {
  const digest = digestJson(unsignedBoundary);
  const signature = sign(
    null,
    Buffer.from(`invock-privacy-boundary-v1\0${digest}`, "utf8"),
    privateKeyPem
  ).toString("base64url");

  return {
    ...unsignedBoundary,
    digest,
    keyId,
    signature
  };
}

export function verifyProtectionBoundary(
  boundary: PrivacyProtectionBoundary,
  publicKeyPem: string
): boolean {
  try {
    const unsignedBoundary: any = {
      id: boundary.id,
      version: boundary.version,
      invockInstallationId: boundary.invockInstallationId,
      enforcementEvidenceType: boundary.enforcementEvidenceType,
      legacyAuditCompletedAt: boundary.legacyAuditCompletedAt,
      selectedLocalScopes: boundary.selectedLocalScopes,
      localLegacyState: boundary.localLegacyState,
      localFindingsTotal: boundary.localFindingsTotal,
      localFindingsResolved: boundary.localFindingsResolved,
      localFindingsUnresolved: boundary.localFindingsUnresolved,
      providerHistory: boundary.providerHistory.map(ph => {
        const phObj: any = {
          providerId: ph.providerId,
          productId: ph.productId,
          state: ph.state,
          checkedAt: ph.checkedAt
        };
        if (ph.evidenceReference !== undefined) phObj.evidenceReference = ph.evidenceReference;
        if (ph.evidenceDigest !== undefined) phObj.evidenceDigest = ph.evidenceDigest;
        return phObj;
      }),
      activePrivacyMode: boundary.activePrivacyMode,
      verdict: boundary.verdict,
      claimLimitations: boundary.claimLimitations,
      createdAt: boundary.createdAt
    };

    if (boundary.enforcementStartedAt !== undefined) unsignedBoundary.enforcementStartedAt = boundary.enforcementStartedAt;
    if (boundary.enforcementEvidenceDigest !== undefined) unsignedBoundary.enforcementEvidenceDigest = boundary.enforcementEvidenceDigest;
    if (boundary.zdrCertificationDigest !== undefined) unsignedBoundary.zdrCertificationDigest = boundary.zdrCertificationDigest;
    if (boundary.scanDigest !== undefined) unsignedBoundary.scanDigest = boundary.scanDigest;
    if (boundary.remediationPlanDigest !== undefined) unsignedBoundary.remediationPlanDigest = boundary.remediationPlanDigest;
    if (boundary.cleanupReceiptDigest !== undefined) unsignedBoundary.cleanupReceiptDigest = boundary.cleanupReceiptDigest;

    const expectedDigest = digestJson(unsignedBoundary);
    if (boundary.digest !== expectedDigest) {
      return false;
    }

    // Time verification: startedAt cannot be in the future, nor after createdAt
    if (boundary.enforcementStartedAt) {
      const startMs = new Date(boundary.enforcementStartedAt).getTime();
      const createdMs = new Date(boundary.createdAt).getTime();
      const nowMs = Date.now();
      if (startMs > nowMs + 60000 || startMs > createdMs + 60000) {
        return false;
      }
    }

    // Honest verdict checks
    if (boundary.verdict === "COMPLETE_FOR_SELECTED_LOCAL_SCOPE") {
      if (boundary.localFindingsUnresolved > 0) return false;
      if (boundary.localLegacyState !== "VERIFIED_CLEAN_FOR_SELECTED_SCOPE") return false;
      if (!boundary.enforcementStartedAt) return false;
      if (!boundary.zdrCertificationDigest) return false;
    }

    return verify(
      null,
      Buffer.from(`invock-privacy-boundary-v1\0${boundary.digest}`, "utf8"),
      publicKeyPem,
      Buffer.from(boundary.signature, "base64url")
    );
  } catch {
    return false;
  }
}
