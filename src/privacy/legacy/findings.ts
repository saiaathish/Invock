import { type LegacyFindingRecord } from "./types.js";

export function loadFindingsSummary(findings: LegacyFindingRecord[]) {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === "CRITICAL").length,
    high: findings.filter(f => f.severity === "HIGH").length,
    medium: findings.filter(f => f.severity === "MEDIUM").length,
    low: findings.filter(f => f.severity === "LOW").length,
  };
}
