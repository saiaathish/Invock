export interface ActivityRecord {
  readonly invocationId: string;
  readonly toolName: string;
  readonly verdict: "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED";
  readonly status: string;
  readonly createdAt: string;
  readonly receiptId?: string;
  readonly [key: string]: unknown;
}

export interface RedactedActivityViewModel {
  readonly invocationId: string;
  readonly toolName: string;
  readonly verdict: ActivityRecord["verdict"];
  readonly status: string;
  readonly createdAt: string;
  readonly receiptId: string | null;
}

export interface RedactedReportViewModel {
  readonly items: readonly RedactedActivityViewModel[];
  readonly total: number;
}

const SECRET_VALUE = /(?:bearer\s+|sk-[a-z0-9]|-----begin|password\s*[=:]|token\s*[=:])/iu;

function safeText(value: unknown, fallback: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || SECRET_VALUE.test(value)) return fallback;
  return value;
}

function redactRecord(record: ActivityRecord): RedactedActivityViewModel {
  return {
    invocationId: safeText(record.invocationId, "redacted"),
    toolName: safeText(record.toolName, "redacted"),
    verdict: record.verdict,
    status: safeText(record.status, "redacted"),
    createdAt: safeText(record.createdAt, "redacted"),
    receiptId: record.receiptId === undefined ? null : safeText(record.receiptId, "redacted"),
  };
}

/** Project records onto the deliberately small, non-sensitive report contract. */
export function redactActivity(records: readonly ActivityRecord[]): readonly RedactedActivityViewModel[] {
  return Object.freeze(records.map(redactRecord));
}

export function buildReportViewModel(records: readonly ActivityRecord[]): RedactedReportViewModel {
  const items = redactActivity(records);
  return Object.freeze({ items, total: items.length });
}
