import { digestJson } from "../core/canonical.js";
import type { PolicyDiff } from "../forge/index.js";

export interface GuardFinding {
  code: "PRIVILEGE_EXPANSION" | "UNSAFE_WORKFLOW_PERMISSION" | "UNSAFE_TRIGGER" | "INVALID_WORKFLOW";
  severity: "BLOCK";
  message: string;
  path: string;
  digest: string;
}

export type WorkflowInput = string | { source: string; path?: string };

const writePermission = /(^|\b)(write|write-all)($|\b)/i;
const unsafePermission = /\b(id-token|actions|attestations|checks|contents|deployments|discussions|issues|packages|pages|pull-requests|security-events)\s*:\s*(write|write-all)\b/i;

function finding(code: GuardFinding["code"], message: string, path: string): GuardFinding {
  return { code, severity: "BLOCK", message, path, digest: digestJson({ code, message, path }) };
}

/** Inspects workflow text only. It never fetches or resolves GitHub state. */
export function inspectWorkflow(input: WorkflowInput): GuardFinding[] {
  const source = typeof input === "string" ? input : input.source;
  const sourcePath = typeof input === "string" ? "workflow" : input.path ?? "workflow";
  if (typeof source !== "string" || source.length === 0) throw new Error("workflow source is required");
  if (source.length > 1_048_576) throw new Error("workflow exceeds 1 MiB limit");
  const findings: GuardFinding[] = [];
  const lines = source.split(/\r?\n/);
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    const linePath = `${sourcePath}:${index + 1}`;
    if (/^permissions\s*:\s*write-all\s*$/i.test(trimmed) || /^permissions\s*:\s*\{?\s*write-all/i.test(trimmed)) findings.push(finding("UNSAFE_WORKFLOW_PERMISSION", "Workflow grants write-all permissions.", linePath));
    else if (/^permissions\s*:/i.test(trimmed) && writePermission.test(trimmed)) findings.push(finding("UNSAFE_WORKFLOW_PERMISSION", "Workflow-level write permission is not least privilege.", linePath));
    else if (unsafePermission.test(trimmed)) findings.push(finding("UNSAFE_WORKFLOW_PERMISSION", "Workflow requests a write permission; review as a privilege expansion.", linePath));
    if (/^pull_request_target\s*:/i.test(trimmed)) findings.push(finding("UNSAFE_TRIGGER", "pull_request_target requires a privileged-trigger review.", linePath));
    if (/uses:\s*[^\s]+@(?:main|master|latest)\b/i.test(trimmed)) findings.push(finding("INVALID_WORKFLOW", "Mutable action reference is not deterministic.", linePath));
  });
  const unique = [...new Map(findings.map(item => [item.digest, item])).values()];
  return unique;
}

/** Converts a forge diff into a fail-closed guard finding when it expands authority. */
export function inspectPolicyDiff(diff: PolicyDiff): GuardFinding[] {
  return diff.privilegeExpansion ? [finding("PRIVILEGE_EXPANSION", "Policy diff adds observed authority and requires explicit review.", `policy:${diff.toDigest}`)] : [];
}
