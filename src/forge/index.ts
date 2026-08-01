import { canonicalize, digestJson } from "../core/canonical.js";

export interface PolicyObservation {
  tool: string;
  capabilities?: readonly string[];
  effects?: readonly string[];
  paths?: readonly string[];
  domains?: readonly string[];
  recipients?: readonly string[];
}

export interface PolicyDraft {
  apiVersion: "invock.dev/forge/v1";
  kind: "PolicyDraft";
  metadata: { name: string };
  tools: string[];
  capabilities: string[];
  effects: string[];
  resources: { paths: string[]; domains: string[]; recipients: string[] };
  digest: string;
  status: "DRAFT" | "ACTIVE";
}

export interface PolicyDiff {
  fromDigest: string;
  toDigest: string;
  additions: {
    tools: string[];
    capabilities: string[];
    effects: string[];
    paths: string[];
    domains: string[];
    recipients: string[];
  };
  removals: {
    tools: string[];
    capabilities: string[];
    effects: string[];
    paths: string[];
    domains: string[];
    recipients: string[];
  };
  privilegeExpansion: boolean;
}

export interface HumanApproval {
  approvedBy: string;
  approvalId: string;
  approvedAt: string;
  statement: string;
}

export interface ActivatedPolicyDraft extends PolicyDraft {
  status: "ACTIVE";
  activatedBy: string;
  approvalId: string;
  activatedAt: string;
}

const sorted = (values: readonly string[] | undefined): string[] => [...new Set(values ?? [])].sort();
const additions = (left: readonly string[], right: readonly string[]): string[] => right.filter(value => !left.includes(value));
const removals = (left: readonly string[], right: readonly string[]): string[] => left.filter(value => !right.includes(value));

function digestable(draft: Omit<PolicyDraft, "digest">): Omit<PolicyDraft, "digest"> {
  return draft;
}

/** Creates a least-privilege draft from local observations. No filesystem or network access occurs. */
export function forgePolicy(observations: readonly PolicyObservation[], name = "observed-policy"): PolicyDraft {
  if (!Array.isArray(observations)) throw new Error("observations must be an array");
  if (observations.length > 10000) throw new Error("observations exceed the 10000-entry limit");
  if (typeof name !== "string" || name.length === 0) throw new Error("policy name is required");
  const draftWithoutDigest = {
    apiVersion: "invock.dev/forge/v1" as const,
    kind: "PolicyDraft" as const,
    metadata: { name },
    tools: sorted(observations.map(item => item.tool)),
    capabilities: sorted(observations.flatMap(item => item.capabilities ?? [])),
    effects: sorted(observations.flatMap(item => item.effects ?? [])),
    resources: {
      paths: sorted(observations.flatMap(item => item.paths ?? [])),
      domains: sorted(observations.flatMap(item => item.domains ?? [])),
      recipients: sorted(observations.flatMap(item => item.recipients ?? [])),
    },
    status: "DRAFT" as const,
  };
  return { ...draftWithoutDigest, digest: digestJson(digestable(draftWithoutDigest)) };
}

export function diffPolicies(from: PolicyDraft, to: PolicyDraft): PolicyDiff {
  const fields = {
    tools: [from.tools, to.tools], capabilities: [from.capabilities, to.capabilities], effects: [from.effects, to.effects],
    paths: [from.resources.paths, to.resources.paths], domains: [from.resources.domains, to.resources.domains], recipients: [from.resources.recipients, to.resources.recipients],
  } as const;
  const added = Object.fromEntries(Object.entries(fields).map(([key, [left, right]]) => [key, additions(left, right)])) as PolicyDiff["additions"];
  const removed = Object.fromEntries(Object.entries(fields).map(([key, [left, right]]) => [key, removals(left, right)])) as PolicyDiff["removals"];
  return { fromDigest: from.digest, toDigest: to.digest, additions: added, removals: removed, privilegeExpansion: Object.values(added).some(values => values.length > 0) };
}

/** Activation is deliberately impossible without a non-empty, attributable human approval record. */
export function activateDraft(draft: PolicyDraft, approval: HumanApproval): ActivatedPolicyDraft {
  if (!approval || typeof approval.approvedBy !== "string" || approval.approvedBy.trim() === "") throw new Error("explicit human approval is required");
  if (typeof approval.approvalId !== "string" || approval.approvalId.trim() === "") throw new Error("approvalId is required");
  if (typeof approval.approvedAt !== "string" || Number.isNaN(Date.parse(approval.approvedAt))) throw new Error("approvedAt must be an ISO date");
  if (typeof approval.statement !== "string" || !/\bapprove\b/i.test(approval.statement)) throw new Error("approval statement must explicitly approve the draft");
  return { ...draft, status: "ACTIVE", activatedBy: approval.approvedBy, approvalId: approval.approvalId, activatedAt: approval.approvedAt };
}

export { canonicalize };
