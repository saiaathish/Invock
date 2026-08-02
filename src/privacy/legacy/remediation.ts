import { existsSync, lstatSync, readFileSync, unlinkSync, chmodSync, readdirSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { createHash, sign } from "node:crypto";
import { digestJson } from "../../core/canonical.js";
import {
  type LegacyRemediationPlan,
  type LegacyRemediationPlanItem,
  type LegacyRemediationAction,
  type LegacyFindingRecord,
  type LegacySourceType,
} from "./types.js";
import { verifyAndConfine, computePathHmac, getPseudonymKey } from "./sources.js";
import { LegacySourceRegistry } from "./source-registry.js";

export interface RemediationExecutionResult {
  receipt: any;
  results: Array<{
    findingId: string;
    action: LegacyRemediationAction;
    status: "SUCCESS" | "STALE_ARTIFACT" | "MISSING_ARTIFACT" | "BYPASSED_SAFETY" | "FAILED";
    error?: string;
  }>;
}

function calculateFileSha256(path: string): string {
  try {
    const data = readFileSync(path);
    return createHash("sha256").update(data).digest("hex");
  } catch {
    return "unknown-hash";
  }
}

// B12 Ignore with reason check
export function validateIgnoreReason(reason: string): boolean {
  if (reason.length < 3 || reason.length > 200) {
    return false;
  }
  const secretPatterns = [
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----/i,
    /bearer\s+[A-Za-z0-9_\-\.\~]+/i,
    /sk-[a-zA-Z0-9]{32,}/i,
    /(AIzaSy[A-Za-z0-9_\-]{33})/i,
  ];
  for (const pattern of secretPatterns) {
    if (pattern.test(reason)) {
      return false;
    }
  }
  return true;
}

export async function applyRemediationPlan(
  workspaceRoot: string,
  plan: LegacyRemediationPlan,
  findings: LegacyFindingRecord[],
  privateKeyPem: string,
  keyId: string,
  options: { dryRun?: boolean; ignoreReasons?: Record<string, string> } = {}
): Promise<RemediationExecutionResult> {
  const dryRun = options.dryRun ?? false;
  const results: RemediationExecutionResult["results"] = [];

  let deleteAttempted = 0;
  let deleteCompleted = 0;
  let deleteFailed = 0;
  let permissionChanged = 0;
  let manualActionCount = 0;
  let secretRotationCount = 0;
  let ignoredCount = 0;
  let staleCount = 0;
  let missingCount = 0;

  const keyPath = join(workspaceRoot, ".invock", "privacy-pseudonym.key");
  const pseudonymKey = getPseudonymKey(keyPath);
  const registry = new LegacySourceRegistry(workspaceRoot);

  // Discover candidate files to resolve HMAC paths back to raw paths (B4)
  const candidateFiles: Array<{
    absolutePath: string;
    rootId: string;
    rootPath: string;
    sourceType: LegacySourceType;
  }> = [];

  for (const adapter of registry.getAdapters()) {
    const roots = await adapter.discoverRoots();
    for (const root of roots) {
      if (!root.exists) continue;
      const queue = [root.path];
      while (queue.length > 0) {
        const current = queue.shift()!;
        let confined;
        try {
          confined = verifyAndConfine(root.path, current);
        } catch {
          continue; // skip
        }

        const stats = lstatSync(current);
        if (stats.isDirectory()) {
          if (!confined.isSymlink) {
            try {
              const children = readdirSync(current);
              for (const child of children) {
                queue.push(join(current, child));
              }
            } catch {}
          }
        } else if (stats.isFile()) {
          candidateFiles.push({
            absolutePath: current,
            rootId: root.id,
            rootPath: root.path,
            sourceType: adapter.sourceType,
          });
        }
      }
    }
  }

  // Helper to find raw path from HMAC
  const resolveRawPath = (sourceRootId: string, pathHmac: string): string | null => {
    for (const cand of candidateFiles) {
      if (cand.rootId === sourceRootId) {
        let confined;
        try {
          confined = verifyAndConfine(cand.rootPath, cand.absolutePath);
        } catch {
          continue;
        }
        const hmac = computePathHmac(pseudonymKey, cand.rootId, confined.normalizedRelativePath);
        if (hmac === pathHmac) {
          return cand.absolutePath;
        }
      }
    }
    return null;
  };

  for (const item of plan.items) {
    const rawPath = resolveRawPath(item.sourceRootId, item.pathHmac);
    if (!rawPath) {
      missingCount++;
      results.push({
        findingId: item.findingId,
        action: item.action,
        status: "MISSING_ARTIFACT",
      });
      continue;
    }

    if (item.action === "DELETE_DISPOSABLE_ARTIFACT") {
      deleteAttempted++;

      // B7/B8 safety protections: check if changed or symlink
      if (!existsSync(rawPath)) {
        deleteFailed++;
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "MISSING_ARTIFACT",
        });
        continue;
      }

      const stats = lstatSync(rawPath);
      if (stats.isSymbolicLink()) {
        deleteFailed++;
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "BYPASSED_SAFETY",
          error: "SYMLINK_DETECTION",
        });
        continue;
      }

      const currentFingerprint = calculateFileSha256(rawPath);
      if (currentFingerprint !== item.expectedArtifactFingerprint) {
        staleCount++;
        deleteFailed++;
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "STALE_ARTIFACT",
        });
        continue;
      }

      // Safety rule B7: check forbidden filenames
      const filename = rawPath.split("/").pop() || "";
      if (
        filename === ".env" ||
        filename.startsWith(".env.") ||
        rawPath.includes("/.git/") ||
        filename.endsWith(".ts") ||
        filename.endsWith(".js")
      ) {
        deleteFailed++;
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "BYPASSED_SAFETY",
          error: "FORBIDDEN_FILE_TYPE",
        });
        continue;
      }

      if (!dryRun) {
        try {
          unlinkSync(rawPath);
          deleteCompleted++;
          results.push({
            findingId: item.findingId,
            action: item.action,
            status: "SUCCESS",
          });
        } catch (err: any) {
          deleteFailed++;
          results.push({
            findingId: item.findingId,
            action: item.action,
            status: "FAILED",
            error: err.message,
          });
        }
      } else {
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "SUCCESS",
        });
      }
    } else if (item.action === "RESTRICT_PERMISSIONS") {
      if (!dryRun) {
        try {
          chmodSync(rawPath, 0o600);
          permissionChanged++;
          results.push({
            findingId: item.findingId,
            action: item.action,
            status: "SUCCESS",
          });
        } catch (err: any) {
          results.push({
            findingId: item.findingId,
            action: item.action,
            status: "FAILED",
            error: err.message,
          });
        }
      } else {
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "SUCCESS",
        });
      }
    } else if (item.action === "ROTATE_SECRET_REQUIRED") {
      secretRotationCount++;
      results.push({
        findingId: item.findingId,
        action: item.action,
        status: "SUCCESS",
      });
    } else if (item.action === "IGNORE_WITH_REASON") {
      const reason = options.ignoreReasons?.[item.findingId] || "";
      if (!validateIgnoreReason(reason)) {
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "FAILED",
          error: "INVALID_IGNORE_REASON",
        });
      } else {
        ignoredCount++;
        results.push({
          findingId: item.findingId,
          action: item.action,
          status: "SUCCESS",
        });
      }
    } else if (item.action === "MANUAL_REDACTION_REQUIRED") {
      manualActionCount++;
      results.push({
        findingId: item.findingId,
        action: item.action,
        status: "SUCCESS",
      });
    }
  }

  // Try B9 directory deletion
  const selectedScopes = Array.from(new Set(plan.items.map(item => item.sourceType)));
  if (!dryRun) {
    for (const scope of selectedScopes) {
      const adapter = registry.getAdapter(scope);
      if (!adapter) continue;
      const roots = await adapter.discoverRoots();
      for (const root of roots) {
        if (!root.exists) continue;
        const queue = [root.path];
        while (queue.length > 0) {
          const current = queue.shift()!;
          const stats = lstatSync(current);
          if (stats.isDirectory()) {
            // Traverse kids first
            try {
              const children = readdirSync(current);
              if (children.length === 0) {
                // If it is inside the root, and empty, we can clean up recognized empty directories safely
                if (current !== root.path) {
                  rmdirSync(current);
                }
              } else {
                for (const child of children) {
                  queue.push(join(current, child));
                }
              }
            } catch {}
          }
        }
      }
    }
  }

  // B13 signed content-free cleanup receipt
  const unsignedReceipt = {
    planId: plan.id,
    planDigest: plan.digest,
    scanId: plan.scanId,
    scanDigest: plan.scanDigest,
    selectedScopes,
    deleteAttempted,
    deleteCompleted,
    deleteFailed,
    permissionChanged,
    manualActionCount,
    secretRotationCount,
    ignoredCount,
    staleCount,
    missingCount,
    unresolvedCount: findings.length - deleteCompleted - ignoredCount,
    completionTimestamp: new Date().toISOString(),
  };

  const receiptDigest = digestJson(unsignedReceipt);
  const signature = sign(
    null,
    Buffer.from(`invock-cleanup-receipt-v1\0${receiptDigest}`, "utf8"),
    privateKeyPem
  ).toString("base64url");

  const receipt = {
    ...unsignedReceipt,
    digest: receiptDigest,
    keyId,
    signature,
  };

  return {
    receipt,
    results,
  };
}
