import { parseDocument } from "yaml";
import { canonicalize, digestJson, stableUnique } from "./canonical.js";
import type { ActionEnvelope, DataLabel, PolicyDecision, Verdict } from "./types.js";

export interface PolicyRule {
  id: string;
  description?: string;
  enabled?: boolean;
  decision: Verdict;
  reasonCodes: string[];
  when: Condition;
  unless?: Condition;
  approval?: { ttlSeconds: number };
}

export interface InvocationPolicy {
  apiVersion: "invock.dev/v1";
  kind: "InvocationPolicy";
  metadata: { name: string; description?: string };
  defaults: { decision: Verdict; unknownCapability?: Verdict; unknownEffect?: Verdict; unresolvedPath?: Verdict; taintToExternalSink?: Verdict };
  variables?: Record<string, string | string[]>;
  rules: PolicyRule[];
}

export type Condition = Record<string, unknown>;
export interface CompiledPolicy { policy: InvocationPolicy; policyVersionId: string; policyDigest: string; }

const verdictRank: Record<Verdict, number> = { ALLOW: 1, APPROVAL_REQUIRED: 2, BLOCK: 3 };
const maxVerdict = (values: Verdict[]): Verdict => values.reduce((current, value) => verdictRank[value] > verdictRank[current] ? value : current, "ALLOW");

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a mapping`);
  return value as Record<string, unknown>;
}
function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some(item => typeof item !== "string")) throw new Error(`${label} must be a string array`);
  return value;
}
function verdict(value: unknown, label: string): Verdict {
  if (value !== "ALLOW" && value !== "BLOCK" && value !== "APPROVAL_REQUIRED") throw new Error(`${label} must be ALLOW, BLOCK, or APPROVAL_REQUIRED`);
  return value;
}
function substitute(value: unknown, variables: Record<string, string | string[]>): unknown {
  if (typeof value === "string") return value.replace(/\$\{([A-Z0-9_]+)\}/g, (_, key: string) => {
    const found = variables[key];
    if (typeof found !== "string") throw new Error(`Variable ${key} is not a string`);
    return found;
  });
  if (Array.isArray(value)) return value.map(item => substitute(item, variables));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, nested]) => [key, substitute(nested, variables)]));
  return value;
}

/** Parses a bounded policy document, rejecting aliases/tags and unknown top-level shapes. */
export function parsePolicyYaml(source: string): InvocationPolicy {
  if (Buffer.byteLength(source) > 1_048_576) throw new Error("Policy exceeds 1 MiB limit");
  const document = parseDocument(source, { uniqueKeys: true, prettyErrors: false });
  if (document.errors.length > 0) throw new Error(`Policy YAML invalid: ${document.errors[0]?.message ?? "unknown error"}`);
  if (document.warnings.length > 0) throw new Error(`Policy YAML warning rejected: ${document.warnings[0]?.message ?? "unknown warning"}`);
  if (document.contents?.tag) throw new Error("Custom YAML tags are prohibited");
  return validatePolicy(document.toJS({ maxAliasCount: 0 }));
}

export function validatePolicy(input: unknown): InvocationPolicy {
  const policy = object(input, "policy");
  const allowed = new Set(["apiVersion", "kind", "metadata", "defaults", "variables", "rules"]);
  for (const key of Object.keys(policy)) if (!allowed.has(key)) throw new Error(`Unknown policy field: ${key}`);
  if (policy.apiVersion !== "invock.dev/v1" || policy.kind !== "InvocationPolicy") throw new Error("Unsupported policy apiVersion or kind");
  const metadata = object(policy.metadata, "metadata");
  if (typeof metadata.name !== "string" || metadata.name.length === 0) throw new Error("metadata.name is required");
  const defaultsValue = object(policy.defaults, "defaults");
  const variables = policy.variables === undefined ? {} : object(policy.variables, "variables");
  for (const [key, value] of Object.entries(variables)) if (typeof value !== "string" && (!Array.isArray(value) || value.some(item => typeof item !== "string"))) throw new Error(`variables.${key} must be a string or string array`);
  const rulesInput = policy.rules;
  if (!Array.isArray(rulesInput) || rulesInput.length === 0 || rulesInput.length > 1000) throw new Error("rules must contain 1–1000 entries");
  const ids = new Set<string>();
  const rules = rulesInput.map((value, index): PolicyRule => {
    const rule = object(substitute(value, variables as Record<string, string | string[]>), `rules[${index}]`);
    if (typeof rule.id !== "string" || !/^[a-z0-9][a-z0-9-]{0,127}$/.test(rule.id)) throw new Error(`rules[${index}].id is invalid`);
    if (ids.has(rule.id)) throw new Error(`Duplicate rule id: ${rule.id}`); ids.add(rule.id);
    if (typeof rule.description !== "undefined" && typeof rule.description !== "string") throw new Error(`rules[${index}].description must be a string`);
    if (typeof rule.enabled !== "undefined" && typeof rule.enabled !== "boolean") throw new Error(`rules[${index}].enabled must be boolean`);
    const reasonCodes = strings(rule.reasonCodes, `rules[${index}].reasonCodes`);
    if (!rule.when || typeof rule.when !== "object") throw new Error(`rules[${index}].when is required`);
    if (rule.unless !== undefined && (rule.unless === null || typeof rule.unless !== "object")) throw new Error(`rules[${index}].unless must be mapping`);
    let approval: { ttlSeconds: number } | undefined;
    if (rule.approval !== undefined) {
      const candidate = object(rule.approval, `rules[${index}].approval`);
      if (!Number.isInteger(candidate.ttlSeconds) || (candidate.ttlSeconds as number) < 1 || (candidate.ttlSeconds as number) > 3600) throw new Error(`rules[${index}].approval.ttlSeconds must be 1–3600`);
      approval = { ttlSeconds: candidate.ttlSeconds as number };
    }
    return { id: rule.id, ...(typeof rule.description === "string" ? { description: rule.description } : {}), ...(typeof rule.enabled === "boolean" ? { enabled: rule.enabled } : {}), decision: verdict(rule.decision, `rules[${index}].decision`), reasonCodes, when: rule.when as Condition, ...(rule.unless ? { unless: rule.unless as Condition } : {}), ...(approval ? { approval } : {}) };
  });
  return {
    apiVersion: "invock.dev/v1", kind: "InvocationPolicy", metadata: { name: metadata.name, ...(typeof metadata.description === "string" ? { description: metadata.description } : {}) },
    defaults: { decision: verdict(defaultsValue.decision, "defaults.decision"), ...(defaultsValue.unknownCapability ? { unknownCapability: verdict(defaultsValue.unknownCapability, "defaults.unknownCapability") } : {}), ...(defaultsValue.unknownEffect ? { unknownEffect: verdict(defaultsValue.unknownEffect, "defaults.unknownEffect") } : {}), ...(defaultsValue.unresolvedPath ? { unresolvedPath: verdict(defaultsValue.unresolvedPath, "defaults.unresolvedPath") } : {}), ...(defaultsValue.taintToExternalSink ? { taintToExternalSink: verdict(defaultsValue.taintToExternalSink, "defaults.taintToExternalSink") } : {}) },
    ...(Object.keys(variables).length ? { variables: variables as Record<string, string | string[]> } : {}), rules,
  };
}

export function compilePolicy(policy: InvocationPolicy): CompiledPolicy {
  const serialized = canonicalize(policy);
  return { policy, policyVersionId: `pol_${digestJson(serialized).slice(0, 16)}`, policyDigest: digestJson(policy) };
}

function setMatch(actual: readonly string[], condition: unknown): boolean {
  const predicate = object(condition, "set predicate");
  if (predicate.any !== undefined && !strings(predicate.any, "any").some(item => actual.includes(item))) return false;
  if (predicate.all !== undefined && !strings(predicate.all, "all").every(item => actual.includes(item))) return false;
  if (predicate.none !== undefined && strings(predicate.none, "none").some(item => actual.includes(item))) return false;
  return true;
}
function inside(candidate: string, root: string): boolean {
  const relative = candidate === root ? "" : candidate.startsWith(`${root}${pathSeparator(root)}`) ? candidate.slice(root.length + 1) : "..";
  return relative === "" || (!relative.startsWith("..") && !relative.includes(`${pathSeparator(root)}..${pathSeparator(root)}`));
}
function pathSeparator(root: string): string { return root.includes("\\") ? "\\" : "/"; }
function everyOrSome<T>(values: T[], config: Record<string, unknown>, predicate: (value: T) => boolean): boolean {
  return config.every === true ? values.length > 0 && values.every(predicate) : values.some(predicate);
}

function evalCondition(condition: Condition, envelope: ActionEnvelope, traces: PolicyDecision["traces"]): boolean {
  const keys = Object.keys(condition);
  if (keys.length !== 1) throw new Error("Every condition must contain exactly one predicate");
  const key = keys[0]!; const value = condition[key];
  const add = (matched: boolean, observed: unknown, expected: unknown): boolean => { traces.push({ predicate: key, matched, observed, expected }); return matched; };
  if (key === "all") { const conditions = Array.isArray(value) ? value : []; return add(conditions.every(item => evalCondition(object(item, "all item"), envelope, traces)), "all", value); }
  if (key === "any") { const conditions = Array.isArray(value) ? value : []; return add(conditions.some(item => evalCondition(object(item, "any item"), envelope, traces)), "any", value); }
  if (key === "not") return add(!evalCondition(object(value, "not"), envelope, traces), "not", value);
  if (key === "capabilities") return add(setMatch(envelope.capabilities, value), envelope.capabilities, value);
  if (key === "effects") return add(setMatch(envelope.effects, value), envelope.effects, value);
  if (key === "labels") return add(setMatch(envelope.labels, value), envelope.labels, value);
  if (key === "riskSignals") return add(setMatch(envelope.riskSignals, value), envelope.riskSignals, value);
  if (key === "uncertainty") { const config = object(value, "uncertainty"); const matched = (config.empty === true && envelope.uncertainty.length === 0) || (config.nonempty === true && envelope.uncertainty.length > 0) || (typeof config.contains === "string" && envelope.uncertainty.includes(config.contains)); return add(matched, envelope.uncertainty, value); }
  if (key === "lineage") { const config = object(value, "lineage"); const sourceLabels = config.sourceLabels ? strings(object(config.sourceLabels, "sourceLabels").any, "sourceLabels.any") : []; const matched = envelope.lineage.some(reference => sourceLabels.some(label => reference.labels.includes(label as DataLabel))); return add(matched, envelope.lineage.map(item => item.labels), value); }
  if (key === "resources") {
    const config = object(value, "resources");
    if (config.paths) { const pathConfig = object(config.paths, "resources.paths"); const paths = envelope.resources.filter(resource => resource.kind === "path"); const matched = everyOrSome(paths, pathConfig, resource => {
      if (pathConfig.labels && !setMatch(resource.labels, pathConfig.labels)) return false;
      if (typeof pathConfig.inside === "string" && !inside(resource.realPath ?? resource.absolutePath, pathConfig.inside)) return false;
      if (typeof pathConfig.outside === "string" && inside(resource.realPath ?? resource.absolutePath, pathConfig.outside)) return false;
      return true;
    }); return add(matched, paths.map(item => item.realPath ?? item.absolutePath), value); }
    if (config.urls) { const urlConfig = object(config.urls, "resources.urls"); const urls = envelope.resources.filter(resource => resource.kind === "url"); const matched = everyOrSome(urls, urlConfig, resource => {
      if (typeof urlConfig.addressClass === "string" && resource.addressClass !== urlConfig.addressClass) return false;
      if (typeof urlConfig.hostname === "string" && resource.hostname !== urlConfig.hostname) return false;
      if (typeof urlConfig.domain === "string" && !(resource.hostname === urlConfig.domain || resource.hostname.endsWith(`.${urlConfig.domain}`))) return false;
      return true;
    }); return add(matched, urls.map(item => item.hostname), value); }
    if (config.commands) { const commandConfig = object(config.commands, "resources.commands"); const commands = envelope.resources.filter(resource => resource.kind === "command"); const matched = everyOrSome(commands, commandConfig, resource => commandConfig.opaqueShell === undefined || resource.opaqueShell === commandConfig.opaqueShell); return add(matched, commands.map(item => item.executable), value); }
    if (config.recipients) { const recipientConfig = object(config.recipients, "resources.recipients"); const recipients = envelope.resources.filter(resource => resource.kind === "recipient"); const matched = everyOrSome(recipients, recipientConfig, resource => recipientConfig.external === undefined || resource.external === recipientConfig.external); return add(matched, recipients.map(item => item.normalized), value); }
    throw new Error("resources requires paths, urls, commands, or recipients");
  }
  throw new Error(`Unsupported policy predicate: ${key}`);
}

/** Pure, bounded, deterministic deny-overrides evaluation. Callers supply the display timestamp. */
export function evaluatePolicy(compiled: CompiledPolicy, envelope: ActionEnvelope, now = new Date()): PolicyDecision {
  const traces: PolicyDecision["traces"] = [];
  const matched: PolicyRule[] = [];
  for (const rule of compiled.policy.rules) {
    if (rule.enabled === false) continue;
    const localTraces: PolicyDecision["traces"] = [];
    const when = evalCondition(rule.when, envelope, localTraces);
    const unless = rule.unless ? evalCondition(rule.unless, envelope, localTraces) : false;
    if (when && !unless) { matched.push(rule); traces.push(...localTraces); }
  }
  const protectiveDefaults: Verdict[] = [];
  if (envelope.capabilities.includes("unknown") && compiled.policy.defaults.unknownCapability) protectiveDefaults.push(compiled.policy.defaults.unknownCapability);
  if (envelope.effects.includes("unknown") && compiled.policy.defaults.unknownEffect) protectiveDefaults.push(compiled.policy.defaults.unknownEffect);
  if (envelope.uncertainty.some(item => item.startsWith("PATH_")) && compiled.policy.defaults.unresolvedPath) protectiveDefaults.push(compiled.policy.defaults.unresolvedPath);
  if (envelope.lineage.length > 0 && envelope.effects.some(effect => effect === "external.disclosure" || effect === "external.communication") && compiled.policy.defaults.taintToExternalSink) protectiveDefaults.push(compiled.policy.defaults.taintToExternalSink);
  const verdicts = matched.length ? matched.map(rule => rule.decision) : [compiled.policy.defaults.decision];
  const decision = maxVerdict([...verdicts, ...protectiveDefaults]);
  const reasons = stableUnique([...matched.flatMap(rule => rule.reasonCodes), ...protectiveDefaults.map(item => `DEFAULT_${item}`)]).sort();
  const approval = matched.filter(rule => rule.decision === "APPROVAL_REQUIRED").map(rule => rule.approval?.ttlSeconds ?? 300).sort((a, b) => a - b)[0];
  return {
    contractVersion: "1.0", decisionId: `dec_${digestJson({ invocationId: envelope.invocationId, policyDigest: compiled.policyDigest, verdict: decision, matched: matched.map(rule => rule.id).sort(), reasons }).slice(0, 26)}`, invocationId: envelope.invocationId, verdict: decision,
    policyVersionId: compiled.policyVersionId, policyDigest: compiled.policyDigest, matchedRuleIds: matched.map(rule => rule.id).sort(), reasonCodes: reasons,
    traces, obligations: decision === "APPROVAL_REQUIRED" ? [{ type: "approval", ttlSeconds: approval ?? 300 }] : [], retryable: decision === "APPROVAL_REQUIRED", evaluatedAt: now.toISOString(),
  };
}