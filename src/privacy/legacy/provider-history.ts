import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ProviderHistoryGuidance, ProviderHistoryRecord, ProviderHistoryState } from "./types.js";

export const PROVIDER_GUIDANCE = {
  CLAUDE: {
    providerId: "CLAUDE",
    productId: "Claude",
    displayName: "Anthropic / Claude",
    possibleHistoryCategories: ["conversation history", "uploaded files", "provider-side request or service data"],
    userActions: [
      "Follow current official provider data controls.",
      "Review and remove applicable history.",
      "Return to Invock and record the result."
    ],
    automatedDeletionSupported: false,
    automatedDeletionImplemented: false as const,
    officialSources: [
      {
        title: "Anthropic Privacy Policy",
        url: "https://www.anthropic.com/legal/privacy",
        accessedAt: "2026-08-02T12:00:00Z"
      }
    ],
    limitations: [
      "Cannot guarantee physical media erasure.",
      "Historical data deletion requests can take time to propagate.",
      "Service logs may be retained for security monitoring."
    ]
  },
  CODEX: {
    providerId: "CODEX",
    productId: "Codex",
    displayName: "Codex / OpenAI",
    possibleHistoryCategories: ["conversation or task history", "uploaded files", "provider-side request or service data"],
    userActions: [
      "Follow current official provider data controls.",
      "Review and remove applicable history.",
      "Return to Invock and record the result."
    ],
    automatedDeletionSupported: false,
    automatedDeletionImplemented: false as const,
    officialSources: [
      {
        title: "OpenAI Privacy Policy",
        url: "https://openai.com/legal/privacy-policy",
        accessedAt: "2026-08-02T12:00:00Z"
      }
    ],
    limitations: [
      "Deletion from active databases does not immediately affect backups.",
      "Custom models trained on history cannot be retroactively fully un-trained easily.",
      "Compliance audit logs are retained separately."
    ]
  },
  CUSTOM: {
    providerId: "CUSTOM",
    productId: "Custom Provider",
    displayName: "Custom Model Provider",
    possibleHistoryCategories: ["api request logs", "custom weights checkpoints", "cached prompt outputs"],
    userActions: [
      "Locate the custom hosting provider console.",
      "Clear custom endpoints or logging databases."
    ],
    automatedDeletionSupported: false,
    automatedDeletionImplemented: false as const,
    officialSources: [
      {
        title: "Generic Host Data Agreement",
        url: "https://example.com/privacy",
        accessedAt: "2026-08-02T12:00:00Z"
      }
    ],
    limitations: ["Self-hosted histories must be verified via administrative logs."]
  },
  REMOTE_MCP: {
    providerId: "REMOTE_MCP",
    productId: "Remote MCP Server",
    displayName: "Remote MCP Server",
    possibleHistoryCategories: ["mcp tool execution logs", "connection history", "cached contexts"],
    userActions: [
      "Contact MCP server administrator.",
      "Locate local logs for remote service endpoint calls."
    ],
    automatedDeletionSupported: false,
    automatedDeletionImplemented: false as const,
    officialSources: [
      {
        title: "Model Context Protocol Specification",
        url: "https://modelcontextprotocol.io",
        accessedAt: "2026-08-02T12:00:00Z"
      }
    ],
    limitations: ["MCP does not define a standard deletion API for remote hosts."]
  },
  UNKNOWN: {
    providerId: "UNKNOWN",
    productId: "Unknown Processor",
    displayName: "Unknown Processor",
    possibleHistoryCategories: ["untracked content logs", "historical metadata"],
    userActions: ["Audit external network egress registries."],
    automatedDeletionSupported: false,
    automatedDeletionImplemented: false as const,
    officialSources: [] as Array<{ title: string; url: string; accessedAt: string }>,
    limitations: ["No information available for unknown processors."]
  }
};

export function validateEvidenceReference(ref: string): boolean {
  if (ref.length > 512) return false;
  // Reject keys, bearer tokens, passwords
  if (/sk-(?:proj-)?[a-zA-Z0-9]{20,}/.test(ref)) return false; // OpenAI API keys
  if (/bearer\s+/i.test(ref)) return false;
  if (/ghp_[a-zA-Z0-9]{30,}/.test(ref)) return false; // GitHub tokens
  if (/secret|private|token|key|password/i.test(ref) && /[a-zA-Z0-9+/=]{16,}/.test(ref)) return false;
  return true;
}

export function getProviderGuidance(providerId: string): ProviderHistoryGuidance {
  const key = providerId.toUpperCase();
  if (key === "CLAUDE") return PROVIDER_GUIDANCE.CLAUDE;
  if (key === "CODEX") return PROVIDER_GUIDANCE.CODEX;
  if (key === "CUSTOM") return PROVIDER_GUIDANCE.CUSTOM;
  if (key === "REMOTE_MCP") return PROVIDER_GUIDANCE.REMOTE_MCP;
  return PROVIDER_GUIDANCE.UNKNOWN;
}

export function loadProviderHistoryRecords(privacyDir: string): ProviderHistoryRecord[] {
  const file = join(privacyDir, "provider-history-records.json");
  if (!existsSync(file)) {
    // Return empty default records for CLAUDE and CODEX
    const now = new Date().toISOString();
    return [
      {
        providerId: "CLAUDE",
        productId: "Claude",
        state: "USER_ACTION_REQUIRED",
        possibleHistoryCategories: PROVIDER_GUIDANCE.CLAUDE.possibleHistoryCategories,
        reasonCodes: ["INITIAL_ONBOARDING_REQUIRED"],
        createdAt: now,
        updatedAt: now
      },
      {
        providerId: "CODEX",
        productId: "Codex",
        state: "USER_ACTION_REQUIRED",
        possibleHistoryCategories: PROVIDER_GUIDANCE.CODEX.possibleHistoryCategories,
        reasonCodes: ["INITIAL_ONBOARDING_REQUIRED"],
        createdAt: now,
        updatedAt: now
      }
    ];
  }
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

export function saveProviderHistoryRecords(privacyDir: string, records: ProviderHistoryRecord[]): void {
  const file = join(privacyDir, "provider-history-records.json");
  writeFileSync(file, JSON.stringify(records, null, 2), { mode: 0o600 });
}

export function updateProviderState(
  privacyDir: string,
  providerId: string,
  state: ProviderHistoryState,
  evidenceReference?: string
): ProviderHistoryRecord {
  const records = loadProviderHistoryRecords(privacyDir);
  const now = new Date().toISOString();
  let record = records.find(r => r.providerId.toUpperCase() === providerId.toUpperCase());

  if (evidenceReference && !validateEvidenceReference(evidenceReference)) {
    throw new Error("INVALID_EVIDENCE_REFERENCE");
  }

  const evidenceDigest = evidenceReference
    ? createHash("sha256").update(evidenceReference).digest("hex")
    : undefined;

  const guidance = getProviderGuidance(providerId);

  if (!record) {
    record = {
      providerId: providerId.toUpperCase(),
      productId: guidance.productId,
      state,
      possibleHistoryCategories: guidance.possibleHistoryCategories,
      reasonCodes: [],
      createdAt: now,
      updatedAt: now
    };
    records.push(record);
  } else {
    record.state = state;
    record.updatedAt = now;
  }

  if (evidenceReference !== undefined) {
    record.evidenceReference = evidenceReference;
  } else {
    delete record.evidenceReference;
  }

  if (evidenceDigest !== undefined) {
    record.evidenceDigest = evidenceDigest;
  } else {
    delete record.evidenceDigest;
  }

  if (state === "PROVIDER_CONFIRMED") {
    if (!evidenceReference) {
      throw new Error("PROVIDER_CONFIRMED_REQUIRES_EVIDENCE");
    }
    record.providerConfirmedAt = now;
    record.userReviewedAt = now;
  } else if (state === "UNVERIFIED") {
    record.userReviewedAt = now;
  }

  saveProviderHistoryRecords(privacyDir, records);
  return record;
}
