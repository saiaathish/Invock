import { digestJson } from "../core/canonical.js";
import type { NormalizationDescriptor } from "../core/normalize.js";
import type { DescriptorRegistry } from "../gateway/engine.js";
import { InvockStore, type ToolRegistryRecord } from "../storage/store.js";

export type DriftSeverity = "info" | "medium" | "high" | "critical";
export interface ToolDescriptor { name: string; title?: string; description?: string; inputSchema: unknown; outputSchema?: unknown; annotations?: Record<string, unknown>; execution?: Record<string, unknown>; }
export interface RegisteredTool { toolVersionId: string; serverId: string; descriptor: ToolDescriptor; schemaDigest: string; descriptorDigest: string; normalizerDigest: string; status: "active" | "quarantined" | "superseded"; }
export interface SchemaDrift { pointer: string; kind: "added" | "removed" | "type_changed" | "required_changed" | "constraint_broadened" | "unknown"; severity: DriftSeverity; }
export interface DriftReport { changed: boolean; severity: DriftSeverity; entries: SchemaDrift[]; }

const order: Record<DriftSeverity, number> = { info: 1, medium: 2, high: 3, critical: 4 };
function strongest(values: DriftSeverity[]): DriftSeverity { return values.reduce((a, b) => order[a] > order[b] ? a : b, "info"); }
function record(value: unknown): Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function required(schema: unknown): Set<string> { const value = record(schema).required; return new Set(Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []); }

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
    if (!(name in aProperties)) entries.push({ pointer: next, kind: "added", severity: bRequired.has(name) || /(?:command|path|url|uri|recipient|email|to|sql|query|credential|token|secret|payload|body)/iu.test(name) ? "high" : "medium" });
    else if (!(name in bProperties)) entries.push({ pointer: next, kind: "removed", severity: "medium" });
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
  return { changed: entries.length > 0, severity: strongest(entries.map(item => item.severity)), entries };
}

/** In-memory registry boundary. A production adapter persists versions/drifts in the storage package. */
export class ToolRegistry {
  private readonly tools = new Map<string, RegisteredTool>();
  discover(serverId: string, descriptor: ToolDescriptor, normalizer: NormalizationDescriptor): { tool: RegisteredTool; drift: DriftReport } {
    const key = `${serverId}/${descriptor.name}`; const previous = this.tools.get(key); const drift = detectDrift(previous, descriptor, normalizer);
    const tool: RegisteredTool = { toolVersionId: `tool_${digestJson({ serverId, descriptor, normalizer }).slice(0, 24)}`, serverId, descriptor, schemaDigest: digestJson({ inputSchema: descriptor.inputSchema, outputSchema: descriptor.outputSchema ?? null }), descriptorDigest: digestJson(descriptor), normalizerDigest: digestJson(normalizer), status: drift.severity === "high" || drift.severity === "critical" ? "quarantined" : "active" };
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
      descriptor: JSON.parse(stored.descriptorJson) as ToolDescriptor,
      schemaDigest: stored.inputSchemaDigest,
      descriptorDigest: stored.descriptorDigest,
      normalizerDigest: digestJson(JSON.parse(stored.normalizerJson)),
      status: stored.trustState === "quarantined" ? "quarantined" : "active",
    } : undefined;
    const drift = detectDrift(previous, descriptor, normalized);
    const quarantined = stored?.trustState === "quarantined" || drift.severity === "high" || drift.severity === "critical";
    const schemaDigest = digestJson(descriptor.inputSchema);
    const descriptorDigest = digestJson(descriptor);
    const registryVersion = `registry_${digestJson({ serverId: this.serverId, descriptorDigest, schemaDigest, normalizer: normalized }).slice(0, 24)}`;
    const tool: RegisteredTool = { toolVersionId: registryVersion, serverId: this.serverId, descriptor, schemaDigest, descriptorDigest, normalizerDigest: digestJson(normalized), status: quarantined ? "quarantined" : "active" };
    const record: ToolRegistryRecord = {
      serverId: this.serverId, toolName: descriptor.name, descriptorDigest, inputSchemaDigest: schemaDigest,
      normalizedSchemaVersion: "1.0", capabilities: normalizer.declaredCapabilities ?? [], effects: normalizer.declaredEffects ?? [],
      trustState: quarantined ? "quarantined" : "trusted", ...(quarantined ? { quarantineReason: stored?.quarantineReason ?? `SCHEMA_DRIFT_${drift.severity.toUpperCase()}` } : {}),
      firstSeenAt: stored?.firstSeenAt ?? now.toISOString(), lastSeenAt: now.toISOString(), registryVersion,
      descriptorJson: JSON.stringify(descriptor), normalizerJson: JSON.stringify(normalized),
    };
    this.store.saveToolRegistry(record);
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
  observeToolsList(value: unknown): void {
    const result = record(value);
    const tools = Array.isArray(result.tools) ? result.tools : [];
    for (const item of tools) {
      const descriptor = item as ToolDescriptor;
      if (typeof descriptor.name !== "string" || !record(descriptor.inputSchema)) continue;
      const annotations = record(descriptor.annotations);
      const supplied = annotations["io.invock/normalizer"];
      if (!record(supplied) || !Array.isArray(record(supplied).fields)) continue;
      const normalizer = supplied as NormalizationDescriptor;
      this.discover(descriptor, { ...normalizer, inputSchema: descriptor.inputSchema });
    }
  }
}