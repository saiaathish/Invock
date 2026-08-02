export type LegacySourceType =
  | "INVOCK_LEGACY"
  | "CLAUDE_LOCAL"
  | "CODEX_LOCAL"
  | "MCP_LOCAL"
  | "WORKSPACE"
  | "CUSTOM_ROOT"
  | "PROVIDER_HISTORY";

export type LegacyArtifactFormat =
  | "TEXT"
  | "JSON"
  | "JSONL"
  | "YAML"
  | "SQLITE"
  | "SQLITE_WAL"
  | "SQLITE_SHM"
  | "LOG"
  | "TRACE"
  | "CRASH_REPORT"
  | "BROWSER_STORAGE_EXPORT"
  | "ARCHIVE"
  | "BINARY"
  | "UNKNOWN";

export type LegacyFindingCategory =
  | "AGENT_CONVERSATION"
  | "PROMPT_HISTORY"
  | "RESPONSE_HISTORY"
  | "TOOL_ARGUMENT_HISTORY"
  | "TOOL_RESULT_HISTORY"
  | "PERSONAL_DATA"
  | "HEALTH_DATA"
  | "FINANCIAL_DATA"
  | "LEGAL_DATA"
  | "SOURCE_CODE"
  | "CREDENTIAL"
  | "SECRET"
  | "CONTENT_BEARING_LOG"
  | "CONTENT_BEARING_TRACE"
  | "CONTENT_BEARING_DATABASE"
  | "CONTENT_BEARING_BACKUP"
  | "PROVIDER_HISTORY_UNKNOWN"
  | "UNKNOWN_SENSITIVE_CONTENT";

export type LegacyFindingSeverity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type ProviderHistoryState =
  | "NOT_APPLICABLE"
  | "NOT_CHECKED"
  | "USER_ACTION_REQUIRED"
  | "DELETION_REQUESTED"
  | "PROVIDER_CONFIRMED"
  | "UNVERIFIED"
  | "RETAINED_BY_USER_CHOICE";

export type LocalLegacyState =
  | "NOT_SCANNED"
  | "SCAN_COMPLETE"
  | "REVIEW_REQUIRED"
  | "PARTIALLY_REMEDIATED"
  | "VERIFIED_CLEAN_FOR_SELECTED_SCOPE"
  | "UNRESOLVED";

export type LegacyRemediationAction =
  | "DELETE_DISPOSABLE_ARTIFACT"
  | "MANUAL_REDACTION_REQUIRED"
  | "ROTATE_SECRET_REQUIRED"
  | "PROVIDER_ACTION_REQUIRED"
  | "RESTRICT_PERMISSIONS"
  | "IGNORE_WITH_REASON";

export interface DiscoveredLegacyArtifact {
  absolutePath: string;
  authorizedRoot: string;

  sourceType: LegacySourceType;
  format: LegacyArtifactFormat;

  sizeBytes: number;
  modifiedAt?: string;

  isSymlink: boolean;
  realPath: string;

  fingerprint: string;

  recognizedDisposable: boolean;
  autoDeleteEligible: boolean;
}

export interface LegacyFindingRecord {
  id: string;
  scanId: string;

  sourceType: LegacySourceType;
  sourceRootId: string;

  pathHmac: string;
  artifactFingerprint: string;

  format: LegacyArtifactFormat;

  categories: LegacyFindingCategory[];
  severity: LegacyFindingSeverity;

  matchCount: number;
  sizeBytes: number;

  recognizedDisposable: boolean;
  autoDeleteEligible: boolean;

  recommendedActions: LegacyRemediationAction[];

  detectedAt: string;
}

export interface LegacyScanSummary {
  scanId: string;

  startedAt: string;
  completedAt: string;

  selectedScopes: LegacySourceType[];

  rootsScanned: number;
  filesExamined: number;
  filesSkipped: number;
  bytesExamined: number;

  findings: number;

  findingsByCategory: Record<LegacyFindingCategory, number>;
  findingsBySeverity: Record<LegacyFindingSeverity, number>;

  disposableArtifacts: number;
  manualActions: number;
  providerActions: number;

  cancelled: boolean;
  errors: number;

  scanDigest: string;
}

export interface LegacyRemediationPlanItem {
  findingId: string;

  sourceType: LegacySourceType;
  sourceRootId: string;

  pathHmac: string;
  expectedArtifactFingerprint: string;

  action: LegacyRemediationAction;

  reasonCode: string;

  userConfirmed: boolean;
}

export interface LegacyRemediationPlan {
  id: string;
  scanId: string;
  scanDigest: string;

  createdAt: string;

  items: LegacyRemediationPlanItem[];

  selectedDeleteCount: number;
  manualActionCount: number;
  providerActionCount: number;
  ignoredCount: number;

  digest: string;
  keyId: string;
  signature: string;
}

export type ProtectionBoundaryVerdict =
  | "COMPLETE_FOR_SELECTED_LOCAL_SCOPE"
  | "PARTIAL"
  | "NOT_VERIFIED";

export interface PrivacyProtectionBoundary {
  id: string;
  version: number;

  invockInstallationId: string;

  enforcementStartedAt?: string;
  enforcementEvidenceType: string;
  enforcementEvidenceDigest?: string;

  legacyAuditCompletedAt?: string;
  selectedLocalScopes: LegacySourceType[];

  localLegacyState: LocalLegacyState;

  localFindingsTotal: number;
  localFindingsResolved: number;
  localFindingsUnresolved: number;

  providerHistory: Array<{
    providerId: string;
    productId: string;
    state: ProviderHistoryState;
    evidenceReference?: string;
    evidenceDigest?: string;
    checkedAt?: string;
  }>;

  activePrivacyMode: "LOCAL_ZDR" | "END_TO_END_ZDR";

  zdrCertificationDigest?: string;

  verdict: ProtectionBoundaryVerdict;

  claimLimitations: string[];

  scanDigest?: string;
  remediationPlanDigest?: string;
  cleanupReceiptDigest?: string;

  createdAt: string;

  digest: string;
  keyId: string;
  signature: string;
}

export interface ProviderHistoryGuidance {
  providerId: string;
  productId: string;

  displayName: string;

  possibleHistoryCategories: string[];
  userActions: string[];

  automatedDeletionSupported: boolean;
  automatedDeletionImplemented: false;

  officialSources: Array<{
    title: string;
    url: string;
    accessedAt: string;
  }>;

  limitations: string[];
}

export interface ProviderHistoryRecord {
  providerId: string;
  productId: string;

  state: ProviderHistoryState;

  possibleHistoryCategories: string[];

  evidenceReference?: string;
  evidenceDigest?: string;

  userReviewedAt?: string;
  providerConfirmedAt?: string;

  reasonCodes: string[];

  createdAt: string;
  updatedAt: string;
}
