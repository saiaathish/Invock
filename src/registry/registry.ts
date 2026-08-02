import { digestJson } from "../core/canonical.js";
import type { NormalizationDescriptor } from "../core/normalize.js";
import type { DescriptorRegistry } from "../gateway/engine.js";
import { InvockStore, type ToolRegistryRecord } from "../storage/store.js";

export type DriftSeverity = "info" | "medium" | "high" | "critical";
export interface ToolDescriptor { name: string; title?: string; description?: string; inputSchema: unknown; outputSchema?: unknown; annotations?: Record<string, unknown>; execution?: Record<string, unknown>; }
export interface ToolTrustInventory {
  serverIdentity?: string;
  sourceType?: "local" | "npm" | "oci" | "git" | "unknown";
  packageName?: string;
  packageVersion?: string;
  image?: string;
  imageDigest?: string;
  signature?: { status: "verified" | "unverified" | "unknown"; keyId?: string };
  sbomReference?: string;
  dependencyEvidence?: { status: "current" | "drifted" | "unknown"; digest?: string };
  containerEvidence?: { status: "current" | "drifted" | "unknown"; digest?: string };
  outputSchemaDigest?: string;
  review?: { state: "none" | "requested" | "released" | "rejected"; reviewer?: string; reviewedAt?: string };
}
export interface RegisteredTool { toolVersionId: string; serverId: string; descriptor: ToolDescriptor; schemaDigest: string; inputSchemaDigest: string; outputSchemaDigest?: string; descriptorDigest: string; normalizerDigest: string; trust: ToolTrustInventory; status: "active" | "quarantined" | "superseded"; }
export interface SchemaDrift { pointer: string; kind: "added" | "removed" | "type_changed" | "required_changed" | "constraint_broadened" | "unknown"; severity: DriftSeverity; }
export interface DriftReport { changed: boolean; severity: DriftSeverity; entries: SchemaDrift[]; }

const order: Record<DriftSeverity, number> = { info: 1, medium: 2, high: 3, critical: 4 };
function strongest(values: DriftSeverity[]): DriftSeverity { return values.reduce((a, b) => order[a] > order[b] ? a : b, "info"); }
function record(value: unknown): Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function objectRecord(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function required(schema: unknown): Set<string> { const value = record(schema).required; return new Set(Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []); }
function validDigest(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value); }
function boundedString(value: unknown, maximum = 256): value is string { return typeof value === "string" && value.length > 0 && value.length <= maximum; }
function normalizerError(value: unknown): string | undefined {
  if (!objectRecord(value)) return "MALFORMED_NORMALIZER_METADATA";
  const allowed = new Set(["fields", "declaredCapabilities", "declaredEffects", "declaredLabels", "inputSchema"]);
  if (Object.keys(value).some(key => !allowed.has(key)) || !Array.isArray(value.fields)) return "UNKNOWN_NORMALIZER_METADATA";
  const fields = value.fields as unknown[];
  const fieldTypes = new Set(["path", "url", "command", "command-argv", "recipient", "data"]);
  const accesses = new Set(["read", "write", "delete"]);
  for (const field of fields) {
    if (!objectRecord(field) || Object.keys(field).some(key => !["pointer", "type", "access", "methodPointer"].includes(key)) || typeof field.pointer !== "string" || !field.pointer.startsWith("/") || typeof field.type !== "string" || !fieldTypes.has(field.type) || (field.access !== undefined && (typeof field.access !== "string" || !accesses.has(field.access))) || (field.methodPointer !== undefined && (typeof field.methodPointer !== "string" || !field.methodPointer.startsWith("/")))) return "MALFORMED_NORMALIZER_METADATA";
  }
  for (const [key, values, allowedValues] of [["declaredCapabilities", value.declaredCapabilities, new Set(["fs.read", "fs.write", "fs.delete", "net.read", "net.send", "process.execute", "process.shell", "message.send", "secret.read"])], ["declaredEffects", value.declaredEffects, new Set(["data.observe", "data.modify", "data.delete", "external.read", "external.disclosure", "external.communication", "process.spawn", "command.interpretation", "persistent.change", "irreversible.action"])], ["declaredLabels", value.declaredLabels, new Set(["public", "internal", "secret", "credential", "private_key", "personal", "financial", "health", "source_code", "regulated", "unknown", "untrusted_content"])]] as const) {
    if (values !== undefined && (!Array.isArray(values) || values.some(item => typeof item !== "string" || !allowedValues.has(item)))) return `UNKNOWN_NORMALIZER_${key.toUpperCase()}`;
  }
  const declaredCapabilities = Array.isArray(value.declaredCapabilities) ? value.declaredCapabilities : [];
  const declaredEffects = Array.isArray(value.declaredEffects) ? value.declaredEffects : [];
  if (fields.length === 0 && !(declaredCapabilities.length || declaredEffects.length)) return "UNKNOWN_NORMALIZER_AUTHORITY";
  return undefined;
}
function validateTrust(trust: unknown, descriptor: ToolDescriptor): string | undefined {
  if (!objectRecord(trust)) return "INVALID_TRUST_METADATA";
  const allowed = new Set(["serverIdentity", "sourceType", "packageName", "packageVersion", "image", "imageDigest", "signature", "sbomReference", "dependencyEvidence", "containerEvidence", "outputSchemaDigest", "review"]);
  if (Object.keys(trust).some(key => !allowed.has(key))) return "INVALID_TRUST_METADATA";
  for (const key of ["serverIdentity", "packageName", "packageVersion", "image"] as const) if (trust[key] !== undefined && !boundedString(trust[key])) return "INVALID_TRUST_METADATA";
  if (trust.sourceType !== undefined && !new Set(["local", "npm", "oci", "git", "unknown"]).has(trust.sourceType as string)) return "INVALID_TRUST_METADATA";
  if (trust.imageDigest !== undefined && (typeof trust.imageDigest !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(trust.imageDigest))) return "INVALID_IMAGE_DIGEST";
  if (trust.sbomReference !== undefined && !boundedString(trust.sbomReference, 1024)) return "INVALID_TRUST_METADATA";
  if (trust.signature !== undefined) {
    if (!objectRecord(trust.signature) || Object.keys(trust.signature).some(key => !new Set(["status", "keyId"]).has(key)) || !new Set(["verified", "unverified", "unknown"]).has(trust.signature.status as string) || (trust.signature.keyId !== undefined && !boundedString(trust.signature.keyId))) return "INVALID_TRUST_METADATA";
    if (trust.signature.status === "verified" && !trust.signature.keyId) return "VERIFIED_SIGNATURE_MISSING_KEY_ID";
  }
  for (const key of ["dependencyEvidence", "containerEvidence"] as const) if (trust[key] !== undefined) {
    const evidence = trust[key];
    if (!objectRecord(evidence) || Object.keys(evidence).some(field => !new Set(["status", "digest"]).has(field)) || !new Set(["current", "drifted", "unknown"]).has(evidence.status as string) || (evidence.digest !== undefined && !validDigest(evidence.digest))) return "INVALID_TRUST_METADATA";
    if (evidence.status === "drifted" && !evidence.digest) return key === "dependencyEvidence" ? "DEPENDENCY_DRIFT_UNSUPPORTED" : "CONTAINER_DRIFT_UNSUPPORTED";
  }
  if (trust.outputSchemaDigest !== undefined && (!descriptor.outputSchema || !validDigest(trust.outputSchemaDigest) || trust.outputSchemaDigest !== digestJson(descriptor.outputSchema))) return "OUTPUT_SCHEMA_DIGEST_MISMATCH";
  if (trust.review !== undefined && (!objectRecord(trust.review) || Object.keys(trust.review).some(key => !new Set(["state", "reviewer", "reviewedAt"]).has(key)) || !new Set(["none", "requested", "released", "rejected"]).has(trust.review.state as string) || (trust.review.reviewer !== undefined && !boundedString(trust.review.reviewer)) || (trust.review.reviewedAt !== undefined && !boundedString(trust.review.reviewedAt)))) return "INVALID_TRUST_METADATA";
  return undefined;
}
function storedDescriptor(value: string): { descriptor: ToolDescriptor; trust: ToolTrustInventory } {
  const parsed = JSON.parse(value) as Record<string, unknown>;
  if (record(parsed.descriptor).name) return { descriptor: parsed.descriptor as ToolDescriptor, trust: record(parsed.trust) as ToolTrustInventory };
  return { descriptor: parsed as unknown as ToolDescriptor, trust: {} };
}
function persistedDescriptor(descriptor: ToolDescriptor, trust: ToolTrustInventory): string { return JSON.stringify({ descriptor, trust }); }

/** Bounded structural JSON-Schema comparison. Unknown semantics are intentionally high risk. */
export function compareSchema(before: unknown, after: unknown, pointer = "", depth = 0): SchemaDrift[] {
  if (depth > 32) return [{ pointer, kind: "unknown", severity: "high" }];
  const a = record(before); const b = record(after); const entries: SchemaDrift[] = [];
  if (a.type !== b.type) entries.push({ pointer, kind: "type_changed", severity: "high" });
  const aRequired = required(before); const bRequired = required(after);
  for (const name of bRequired) if (!aRequired.has(name)) entries.push({ pointer: `${pointer}/required/${name}`, kind: "required_changed", severity: "high" });
  const aProperties = record(a.properties); const bProperties = record(b.properties);
  for (const name of new Set([...Object.keys(aProperties), ...Object.keys(bProperties)])) {
    const next = `${pointer}/properties/${name}`;
    if (!(name in aProperties)) entries.push({ pointer: next, kind: "added", severity: "high" });
    else if (!(name in bProperties)) entries.push({ pointer: next, kind: "removed", severity: "high" });
    else entries.push(...compareSchema(aProperties[name], bProperties[name], next, depth + 1));
  }
  for (const key of ["additionalProperties", "patternProperties", "oneOf", "anyOf", "allOf", "$ref"]) if (digestJson(a[key] ?? null) !== digestJson(b[key] ?? null)) entries.push({ pointer: `${pointer}/${key}`, kind: key === "additionalProperties" ? "constraint_broadened" : "unknown", severity: key === "additionalProperties" ? "high" : "high" });
  return entries;
}

export function detectDrift(previous: RegisteredTool | undefined, descriptor: ToolDescriptor, normalizer: NormalizationDescriptor): DriftReport {
  if (!previous) return { changed: false, severity: "info", entries: [] };
  const entries = [...compareSchema(previous.descriptor.inputSchema, descriptor.inputSchema), ...compareSchema(previous.descriptor.outputSchema ?? null, descriptor.outputSchema ?? null, "/outputSchema")];
  const normalizedDigest = digestJson(normalizer);
  if (previous.normalizerDigest !== normalizedDigest) entries.push({ pointer: "/normalizer", kind: "unknown", severity: "critical" });
  if (previous.descriptor.name !== descriptor.name) entries.push({ pointer: "/name", kind: "type_changed", severity: "critical" });
  if (previous.descriptorDigest !== digestJson(descriptor)) entries.push({ pointer: "/descriptor", kind: "unknown", severity: "high" });
  return { changed: entries.length > 0, severity: strongest(entries.map(item => item.severity)), entries };
}

/** In-memory registry boundary. A production adapter persists versions/drifts in the storage package. */
export class ToolRegistry {
  private readonly tools = new Map<string, RegisteredTool>();
  discover(serverId: string, descriptor: ToolDescriptor, normalizer: NormalizationDescriptor): { tool: RegisteredTool; drift: DriftReport } {
    const key = `${serverId}/${descriptor.name}`; const previous = this.tools.get(key); const drift = detectDrift(previous, descriptor, normalizer);
    const inputSchemaDigest = digestJson(descriptor.inputSchema); const outputSchemaDigest = descriptor.outputSchema === undefined ? undefined : digestJson(descriptor.outputSchema);
    const tool: RegisteredTool = { toolVersionId: `tool_${digestJson({ serverId, descriptor, normalizer }).slice(0, 24)}`, serverId, descriptor, schemaDigest: digestJson({ inputSchema: descriptor.inputSchema, outputSchema: descriptor.outputSchema ?? null }), inputSchemaDigest, ...(outputSchemaDigest ? { outputSchemaDigest } : {}), descriptorDigest: digestJson(descriptor), normalizerDigest: digestJson(normalizer), trust: {}, status: drift.changed ? "quarantined" : "active" };
    this.tools.set(key, tool); return { tool, drift };
  }
  get(serverId: string, name: string): RegisteredTool | undefined { return this.tools.get(`${serverId}/${name}`); }
}

/** Durable live registry used by the invocation gate after `tools/list` discovery. */
export class PersistentToolRegistry implements DescriptorRegistry {
  constructor(private readonly store: InvockStore, readonly serverId: string) {}

  discover(descriptor: ToolDescriptor, normalizer: NormalizationDescriptor, now = new Date()): { tool: RegisteredTool; drift: DriftReport } {
    const normalized = { ...normalizer, inputSchema: descriptor.inputSchema };
    const stored = this.store.getToolRegistry(this.serverId, descriptor.name);
    const previous: RegisteredTool | undefined = stored ? {
      toolVersionId: stored.registryVersion,
      serverId: stored.serverId,
      descriptor: storedDescriptor(stored.descriptorJson).descriptor,
      schemaDigest: stored.inputSchemaDigest,
      inputSchemaDigest: stored.inputSchemaDigest,
      ...(storedDescriptor(stored.descriptorJson).descriptor.outputSchema ? { outputSchemaDigest: digestJson(storedDescriptor(stored.descriptorJson).descriptor.outputSchema) } : {}),
      descriptorDigest: stored.descriptorDigest,
      normalizerDigest: digestJson(JSON.parse(stored.normalizerJson)),
      trust: storedDescriptor(stored.descriptorJson).trust,
      status: stored.trustState === "quarantined" ? "quarantined" : "active",
    } : undefined;
    const drift = detectDrift(previous, descriptor, normalized);
    const suppliedRaw = record(descriptor.annotations)["io.invock/trust"];
    const suppliedTrust = objectRecord(suppliedRaw) ? suppliedRaw as ToolTrustInventory : {};
    const trust = { ...storedDescriptor(stored?.descriptorJson ?? JSON.stringify({})).trust, ...suppliedTrust };
    const trustError = suppliedRaw !== undefined && !objectRecord(suppliedRaw) ? "INVALID_TRUST_METADATA" : validateTrust(trust, descriptor);
    const normalizerIssue = normalizerError(normalized);
    const quarantined = stored?.trustState === "quarantined" || drift.changed || trustError !== undefined || normalizerIssue !== undefined;
    const schemaDigest = digestJson(descriptor.inputSchema); const outputSchemaDigest = descriptor.outputSchema === undefined ? undefined : digestJson(descriptor.outputSchema);
    const descriptorDigest = digestJson(descriptor);
    const registryVersion = `registry_${digestJson({ serverId: this.serverId, descriptorDigest, schemaDigest, normalizer: normalized }).slice(0, 24)}`;
    const tool: RegisteredTool = { toolVersionId: registryVersion, serverId: this.serverId, descriptor, schemaDigest, inputSchemaDigest: schemaDigest, ...(outputSchemaDigest ? { outputSchemaDigest } : {}), descriptorDigest, normalizerDigest: digestJson(normalized), trust, status: quarantined ? "quarantined" : "active" };
    const registryRecord: ToolRegistryRecord = {
      serverId: this.serverId, toolName: descriptor.name, descriptorDigest, inputSchemaDigest: schemaDigest,
      normalizedSchemaVersion: "1.0", capabilities: normalizer.declaredCapabilities ?? [], effects: normalizer.declaredEffects ?? [],
      trustState: quarantined ? "quarantined" : (stored?.trustState === "reviewed" ? "reviewed" : "trusted"), ...(quarantined ? { quarantineReason: trustError ?? normalizerIssue ?? stored?.quarantineReason ?? `SCHEMA_DRIFT_${drift.severity.toUpperCase()}` } : {}),
      firstSeenAt: stored?.firstSeenAt ?? now.toISOString(), lastSeenAt: now.toISOString(), registryVersion,
      descriptorJson: persistedDescriptor(descriptor, trust), normalizerJson: JSON.stringify(normalized),
    };
    this.store.saveToolRegistry(registryRecord);
    if (quarantined) this.store.invalidateToolApprovals(this.serverId, descriptor.name);
    return { tool, drift };
  }

  get(toolName: string): NormalizationDescriptor | undefined {
    const record = this.store.getToolRegistry(this.serverId, toolName);
    return record ? JSON.parse(record.normalizerJson) as NormalizationDescriptor : undefined;
  }
  schemaDigest(toolName: string): string { return this.store.getToolRegistry(this.serverId, toolName)?.inputSchemaDigest ?? digestJson({ unknown: toolName }); }
  descriptorDigest(toolName: string): string { return this.store.getToolRegistry(this.serverId, toolName)?.descriptorDigest ?? digestJson({ unknown: toolName }); }
  registryVersion(toolName: string): string { return this.store.getToolRegistry(this.serverId, toolName)?.registryVersion ?? "registry_unknown"; }
  isQuarantined(toolName: string): boolean { return this.store.getToolRegistry(this.serverId, toolName)?.trustState === "quarantined"; }
  trustInventory(toolName: string): ToolTrustInventory | undefined { const record = this.store.getToolRegistry(this.serverId, toolName); return record ? storedDescriptor(record.descriptorJson).trust : undefined; }
  reviewQuarantine(toolName: string, decision: "release" | "reject", reviewer: string, now = new Date()): boolean {
    const stored = this.store.getToolRegistry(this.serverId, toolName);
    if (!stored || stored.trustState !== "quarantined" || reviewer.trim() === "") return false;
    const current = storedDescriptor(stored.descriptorJson);
    if (decision === "release" && validateTrust(current.trust, current.descriptor) !== undefined) return false;
    const review: NonNullable<ToolTrustInventory["review"]> = { state: decision === "release" ? "released" : "rejected", reviewer, reviewedAt: now.toISOString() };
    const trust: ToolTrustInventory = { ...current.trust, review };
    this.store.saveToolRegistry({ ...stored, trustState: decision === "release" ? "reviewed" : "quarantined", ...(decision === "release" ? {} : { quarantineReason: stored.quarantineReason ?? "REVIEW_REJECTED" }), descriptorJson: persistedDescriptor(current.descriptor, trust), lastSeenAt: now.toISOString() });
    if (decision === "release") this.store.invalidateToolApprovals(this.serverId, toolName);
    return true;
  }
  private quarantine(toolName: string, reason: string, now: Date): void {
    const stored = this.store.getToolRegistry(this.serverId, toolName);
    if (!stored || stored.trustState === "quarantined" && stored.quarantineReason === reason) return;
    this.store.saveToolRegistry({ ...stored, trustState: "quarantined", quarantineReason: reason, lastSeenAt: now.toISOString() });
    this.store.invalidateToolApprovals(this.serverId, toolName);
  }

  observeToolsList(value: unknown): void {
    const result = record(value);
    const now = new Date();
    const tools = result.tools;
    if (!Array.isArray(tools)) {
      for (const stored of this.store.listToolRegistry().filter(item => item.serverId === this.serverId)) this.quarantine(stored.toolName, "MALFORMED_TOOLS_LIST", now);
      return;
    }
    const seen = new Set<string>();
    for (const item of tools) {
      const descriptor = record(item) as unknown as ToolDescriptor;
      if (typeof descriptor.name !== "string" || descriptor.name.length === 0) continue;
      seen.add(descriptor.name);
      if (Object.keys(descriptor).some(key => !["name", "title", "description", "inputSchema", "outputSchema", "annotations", "execution"].includes(key))) { this.quarantine(descriptor.name, "MALFORMED_TOOL_DESCRIPTOR", now); continue; }
      if (!record(descriptor.inputSchema)) { this.quarantine(descriptor.name, "MALFORMED_TOOL_DESCRIPTOR", now); continue; }
      const annotations = record(descriptor.annotations);
      const supplied = annotations["io.invock/normalizer"];
      if (!record(supplied) || !Array.isArray(record(supplied).fields)) { this.quarantine(descriptor.name, "MALFORMED_NORMALIZER_METADATA", now); continue; }
      const issue = normalizerError({ ...(supplied as Record<string, unknown>), inputSchema: descriptor.inputSchema });
      if (issue) { this.quarantine(descriptor.name, issue, now); continue; }
      const normalizer = supplied as NormalizationDescriptor;
      this.discover(descriptor, { ...normalizer, inputSchema: descriptor.inputSchema }, now);
    }
    for (const stored of this.store.listToolRegistry().filter(item => item.serverId === this.serverId && !seen.has(item.toolName))) this.quarantine(stored.toolName, "TOOL_REMOVED_FROM_DISCOVERY", now);
  }
}
