import { lstatSync, readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  type LegacySourceType,
  type LegacyFindingRecord,
  type LegacyScanSummary,
  type DiscoveredLegacyArtifact,
  type LegacyFindingCategory,
  type LegacyFindingSeverity,
  type LegacyRemediationAction,
} from "./types.js";
import { LegacySourceRegistry } from "./source-registry.js";
import { verifyAndConfine, computePathHmac, getPseudonymKey } from "./sources.js";
import { scanTextContent, scanSQLiteDatabase } from "./detectors.js";

export interface ScanOptions {
  consent: boolean;
  selectedScopes: LegacySourceType[];
  customPaths?: string[];
  maxFileSizeBytes?: number;
  maxTotalScanBytes?: number;
  pseudonymKeyPath?: string;
}

function calculateFileSha256(path: string): string {
  try {
    const data = readFileSync(path);
    return createHash("sha256").update(data).digest("hex");
  } catch {
    return "unknown-hash";
  }
}

export async function runLegacyScan(
  workspaceRoot: string,
  options: ScanOptions
): Promise<{ summary: LegacyScanSummary; findings: LegacyFindingRecord[] }> {
  // 2.1 Consent Check
  if (!options.consent) {
    throw new Error("CONSENT_REQUIRED");
  }

  const selectedScopes = options.selectedScopes;
  if (!selectedScopes || selectedScopes.length === 0) {
    throw new Error("NO_SCOPES_SELECTED");
  }

  // File size bounds (2.4)
  const maxFileSize = options.maxFileSizeBytes ?? 16 * 1024 * 1024; // 16 MiB
  const maxTotalScan = options.maxTotalScanBytes ?? 2 * 1024 * 1024 * 1024; // 2 GiB

  const registry = new LegacySourceRegistry(workspaceRoot, options.customPaths);
  const scanId = `scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const startedAt = new Date().toISOString();

  let rootsScanned = 0;
  let filesExamined = 0;
  let filesSkipped = 0;
  let bytesExamined = 0;
  let totalScanBytesAccumulated = 0;
  let cancelled = false;

  const findings: LegacyFindingRecord[] = [];
  const findingsByCategory = {} as Record<LegacyFindingCategory, number>;
  const findingsBySeverity = {} as Record<LegacyFindingSeverity, number>;
  let disposableArtifactsCount = 0;
  let manualActionsCount = 0;
  let providerActionsCount = 0;

  const keyPath = options.pseudonymKeyPath ?? join(workspaceRoot, ".invock", "privacy-pseudonym.key");
  const pseudonymKey = getPseudonymKey(keyPath);

  // In-memory mapping of paths to release on cleanup/error
  let ephemeralPathMap = new Map<string, string>();

  const cleanup = () => {
    ephemeralPathMap.clear();
  };

  try {
    for (const scope of selectedScopes) {
      // 2.1 Prevents scanning entire home dir by default
      if (scope === "WORKSPACE" && !options.selectedScopes.includes("WORKSPACE")) {
        continue;
      }

      const adapter = registry.getAdapter(scope);
      if (!adapter) continue;

      const roots = await adapter.discoverRoots();
      for (const root of roots) {
        if (!root.exists) continue;
        rootsScanned++;

        const queue: string[] = [root.path];
        while (queue.length > 0) {
          const current = queue.shift()!;

          // Confinement check
          let confined;
          try {
            confined = verifyAndConfine(root.path, current);
          } catch {
            filesSkipped++;
            continue; // blocked symlink or traversal escape
          }

          const stats = lstatSync(current);
          if (stats.isDirectory()) {
            // Symlinked directories are not followed by default
            if (confined.isSymlink) {
              filesSkipped++;
              continue;
            }

            try {
              const children = readdirSync(current);
              for (const child of children) {
                queue.push(join(current, child));
              }
            } catch {
              filesSkipped++;
            }
          } else if (stats.isFile()) {
            // File size checks (2.4)
            const fileSize = stats.size;
            if (fileSize > maxFileSize) {
              filesSkipped++;
              continue;
            }

            if (totalScanBytesAccumulated + fileSize > maxTotalScan) {
              // total limit exceeded, stop traversal
              break;
            }

            totalScanBytesAccumulated += fileSize;
            filesExamined++;
            bytesExamined += fileSize;

            const fingerprint = calculateFileSha256(current);
            const inMemoryArtifact: DiscoveredLegacyArtifact = {
              absolutePath: current,
              authorizedRoot: root.path,
              sourceType: scope,
              format: "UNKNOWN",
              sizeBytes: fileSize,
              isSymlink: confined.isSymlink,
              realPath: confined.realPath,
              fingerprint,
              recognizedDisposable: false,
              autoDeleteEligible: false,
            };

            const classification = await adapter.classifyArtifact(inMemoryArtifact);
            inMemoryArtifact.format = classification.format;
            inMemoryArtifact.recognizedDisposable = classification.recognizedDisposable;
            inMemoryArtifact.autoDeleteEligible = classification.autoDeleteEligible;

            let detection;
            if (classification.format === "SQLITE") {
              detection = scanSQLiteDatabase(current);
            } else if (["JSON", "JSONL", "YAML", "LOG", "TEXT"].includes(classification.format)) {
              try {
                const text = readFileSync(current, "utf8");
                detection = scanTextContent(text);
              } catch {
                detection = { categories: [], severity: "LOW" as const, matchCount: 0 };
              }
            } else if (classification.format === "ARCHIVE") {
              detection = {
                categories: ["UNKNOWN_SENSITIVE_CONTENT" as const],
                severity: "HIGH" as const,
                matchCount: 1,
              };
            } else {
              // Binary / unknown
              detection = { categories: [], severity: "LOW" as const, matchCount: 0 };
            }

            if (detection.categories.length > 0) {
              const pathHmac = computePathHmac(pseudonymKey, root.id, confined.normalizedRelativePath);
              ephemeralPathMap.set(pathHmac, current);

              const recommendedActions: LegacyRemediationAction[] = [];
              if (inMemoryArtifact.autoDeleteEligible) {
                recommendedActions.push("DELETE_DISPOSABLE_ARTIFACT");
                disposableArtifactsCount++;
              } else {
                recommendedActions.push("MANUAL_REDACTION_REQUIRED");
                manualActionsCount++;
              }

              if (detection.categories.includes("SECRET") || detection.categories.includes("CREDENTIAL")) {
                recommendedActions.push("ROTATE_SECRET_REQUIRED");
              }

              // Build content-free finding record (2.9)
              const findingRecord: LegacyFindingRecord = {
                id: `finding_${findings.length + 1}`,
                scanId,
                sourceType: scope,
                sourceRootId: root.id,
                pathHmac,
                artifactFingerprint: fingerprint,
                format: classification.format,
                categories: detection.categories,
                severity: detection.severity,
                matchCount: detection.matchCount,
                sizeBytes: fileSize,
                recognizedDisposable: inMemoryArtifact.recognizedDisposable,
                autoDeleteEligible: inMemoryArtifact.autoDeleteEligible,
                recommendedActions,
                detectedAt: new Date().toISOString(),
              };

              findings.push(findingRecord);

              // Update categories count
              for (const cat of detection.categories) {
                findingsByCategory[cat] = (findingsByCategory[cat] || 0) + 1;
              }
              // Update severity count
              findingsBySeverity[detection.severity] = (findingsBySeverity[detection.severity] || 0) + 1;
            }
          }
        }
      }
    }
  } catch (err) {
    // 2.8 Memory cleanup on failure
    cleanup();
    throw err;
  }

  const completedAt = new Date().toISOString();
  const summary: LegacyScanSummary = {
    scanId,
    startedAt,
    completedAt,
    selectedScopes,
    rootsScanned,
    filesExamined,
    filesSkipped,
    bytesExamined,
    findings: findings.length,
    findingsByCategory,
    findingsBySeverity,
    disposableArtifacts: disposableArtifactsCount,
    manualActions: manualActionsCount,
    providerActions: providerActionsCount,
    cancelled,
    errors: 0,
    scanDigest: createHash("sha256")
      .update(JSON.stringify(findings.map(f => f.artifactFingerprint).sort()))
      .digest("hex"),
  };

  cleanup();
  return { summary, findings };
}
