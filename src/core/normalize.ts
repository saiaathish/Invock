import { realpathSync } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { digestJson, newId, sha256, stableUnique } from "./canonical.js";
import type { ActionEnvelope, Capability, CommandResource, DataLabel, Effect, LineageReference, PathResource, Principal, RecipientResource, Resource, ToolCallRequest, UrlResource } from "./types.js";

export type FieldKind = "path" | "url" | "command" | "command-argv" | "recipient" | "data";
export interface NormalizationDescriptor {
  fields: Array<{ pointer: string; type: FieldKind; access?: "read" | "write" | "delete"; methodPointer?: string }>;
  declaredCapabilities?: Capability[];
  declaredEffects?: Effect[];
  declaredLabels?: DataLabel[];
  inputSchema?: unknown;
}

const FIELD_KINDS = new Set<FieldKind>(["path", "url", "command", "command-argv", "recipient", "data"]);
const CAPABILITIES = new Set<Capability>(["fs.read", "fs.write", "fs.delete", "net.read", "net.send", "process.execute", "process.shell", "message.send", "secret.read"]);
const EFFECTS = new Set<Effect>(["data.observe", "data.modify", "data.delete", "external.read", "external.disclosure", "external.communication", "process.spawn", "command.interpretation", "persistent.change", "irreversible.action"]);
const DATA_LABELS = new Set<DataLabel>(["public", "internal", "secret", "credential", "private_key", "personal", "financial", "health", "source_code", "regulated", "unknown", "untrusted_content"]);

/** Validate the security metadata before any resource normalization occurs. */
function assertDescriptorSafe(descriptor: NormalizationDescriptor): void {
  if (!Array.isArray(descriptor.fields)) throw new Error("UNKNOWN_NORMALIZER_FIELDS");
  for (const field of descriptor.fields) {
    if (field === null || typeof field !== "object" || typeof field.pointer !== "string" || !field.pointer.startsWith("/") || !FIELD_KINDS.has(field.type)) {
      throw new Error("UNKNOWN_NORMALIZER_FIELD_TYPE");
    }
    if (field.methodPointer !== undefined && (typeof field.methodPointer !== "string" || !field.methodPointer.startsWith("/"))) throw new Error("INVALID_NORMALIZER_METHOD_POINTER");
    if (field.type === "path" && field.access !== undefined && !["read", "write", "delete"].includes(field.access)) throw new Error("INVALID_NORMALIZER_ACCESS");
  }
  for (const capability of descriptor.declaredCapabilities ?? []) if (!CAPABILITIES.has(capability)) throw new Error("UNKNOWN_NORMALIZER_CAPABILITY");
  for (const effect of descriptor.declaredEffects ?? []) if (!EFFECTS.has(effect)) throw new Error("UNKNOWN_NORMALIZER_EFFECT");
  for (const label of descriptor.declaredLabels ?? []) if (!DATA_LABELS.has(label)) throw new Error("UNKNOWN_NORMALIZER_LABEL");
  // A no-argument tool must declare its authority explicitly. Empty metadata is
  // not a harmless default: it would make an unknown side effect look benign.
  if (descriptor.fields.length === 0 && !(descriptor.declaredCapabilities?.length || descriptor.declaredEffects?.length)) throw new Error("UNKNOWN_NORMALIZER_AUTHORITY");
}

export interface NormalizationContext {
  cwd: string;
  projectRoot: string;
  organizationDomains: string[];
  protectedPathPatterns?: RegExp[];
  policyVersionId: string;
  schemaDigest: string;
  descriptorDigest: string;
  sessionId: string;
  serverId?: string;
  registryVersion?: string;
  protocolEra?: string;
  privacyBlocked?: boolean;
  privacyMetadata?: { privacyMode: "LOCAL_ZDR" | "END_TO_END_ZDR"; privacyContractDigest: string; privacyChainDigest: string; privacyProcessorProfileDigests: string[] };
  principal: Principal;
  lineage: LineageReference[];
  now?: () => Date;
}

const DEFAULT_PROTECTED_PATH = /(^|\/)(\.env(?:\.[^/]*)?|\.ssh|\.aws|credentials?|id_(rsa|ed25519)|.*private[-_]?key.*)(\/|$)/i;
const SHELL_META = ["|", ";", "&", "$", "`", ">", "<", "*", "?", "(", ")"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && !Array.isArray(value) && typeof value === "object";
}

function atPointer(root: Record<string, unknown>, pointer: string): unknown {
  if (!pointer.startsWith("/")) throw new Error(`Descriptor pointer must begin with '/': ${pointer}`);
  let value: unknown = root;
  for (const segment of pointer.slice(1).split("/")) {
    if (!isRecord(value)) return undefined;
    value = value[segment.replaceAll("~1", "/").replaceAll("~0", "~")];
  }
  return value;
}

function schemaRecord(value: unknown, pointer: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${pointer}: schema must be an object`);
  return value;
}

function validateSchema(value: unknown, schema: unknown, pointer: string): void {
  const candidate = schemaRecord(schema, `${pointer} schema`);
  if (candidate.const !== undefined && digestJson(value) !== digestJson(candidate.const)) throw new Error(`${pointer}: value does not match const`);
  if (Array.isArray(candidate.enum) && !candidate.enum.some(item => digestJson(item) === digestJson(value))) throw new Error(`${pointer}: value is not in enum`);
  if (candidate.type !== undefined) {
    const type = candidate.type;
    const matches = type === "object" ? isRecord(value) : type === "array" ? Array.isArray(value) : type === "string" ? typeof value === "string" : type === "number" ? typeof value === "number" && Number.isFinite(value) : type === "integer" ? typeof value === "number" && Number.isInteger(value) : type === "boolean" ? typeof value === "boolean" : type === "null" ? value === null : false;
    if (!matches) throw new Error(`${pointer}: expected ${String(type)}`);
  }
  if (Array.isArray(candidate.oneOf) || Array.isArray(candidate.anyOf)) {
    const branches = (candidate.oneOf ?? candidate.anyOf) as unknown[];
    const valid = branches.some(branch => { try { validateSchema(value, branch, pointer); return true; } catch { return false; } });
    if (!valid) throw new Error(`${pointer}: value does not match schema union`);
  }
  if (isRecord(value)) {
    const properties = isRecord(candidate.properties) ? candidate.properties : {};
    const required = Array.isArray(candidate.required) ? candidate.required.filter((item): item is string => typeof item === "string") : [];
    for (const key of required) if (!(key in value)) throw new Error(`${pointer}/${key}: required property missing`);
    const additional = candidate.additionalProperties;
    for (const [key, nested] of Object.entries(value)) {
      if (key in properties) validateSchema(nested, properties[key], `${pointer}/${key}`);
      else if (additional === false) throw new Error(`${pointer}/${key}: unknown property`);
      else if (additional !== true && additional !== undefined) validateSchema(nested, additional, `${pointer}/${key}`);
      else if (additional === undefined) throw new Error(`${pointer}/${key}: unmodeled argument`);
    }
  }
  if (Array.isArray(value)) {
    if (typeof candidate.minItems === "number" && value.length < candidate.minItems) throw new Error(`${pointer}: too few items`);
    if (typeof candidate.maxItems === "number" && value.length > candidate.maxItems) throw new Error(`${pointer}: too many items`);
    if (candidate.items !== undefined) value.forEach((item, index) => validateSchema(item, candidate.items, `${pointer}/${index}`));
    else if (candidate.items === undefined && value.length > 0) throw new Error(`${pointer}: unmodeled array items`);
  }
  if (typeof value === "string") {
    if (typeof candidate.maxLength === "number" && value.length > candidate.maxLength) throw new Error(`${pointer}: string too long`);
    if (typeof candidate.pattern === "string" && !new RegExp(candidate.pattern, "u").test(value)) throw new Error(`${pointer}: string pattern mismatch`);
  }
}

function assertModeledTree(value: unknown, pointer: string, descriptor: NormalizationDescriptor): void {
  const fields = descriptor.fields.flatMap(field => [field.pointer, field.methodPointer].filter((item): item is string => item !== undefined));
  const covered = fields.some(field => pointer === field || pointer.startsWith(`${field}/`));
  if (value === null || typeof value !== "object") {
    if (!covered) throw new Error(`UNMODELED_ARGUMENT: ${pointer}`);
    return;
  }
  if (Array.isArray(value)) { value.forEach((item, index) => assertModeledTree(item, `${pointer}/${index}`, descriptor)); return; }
  for (const [key, nested] of Object.entries(value)) assertModeledTree(nested, `${pointer}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`, descriptor);
}

function assertSafeText(value: string, pointer: string): void {
  if (value.length > 16_384) throw new Error(`${pointer}: string exceeds 16 KiB limit`);
  if (/\0|[\u0001-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) throw new Error(`${pointer}: unsafe control character`);
}

async function nearestRealAncestor(absolute: string): Promise<{ real?: string; ancestor?: string; exists: boolean; symlink: boolean; uncertainty: string[] }> {
  try {
    const stat = await lstat(absolute);
    return { real: await realpath(absolute), ancestor: await realpath(absolute), exists: true, symlink: stat.isSymbolicLink(), uncertainty: [] };
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") return { exists: false, symlink: false, uncertainty: ["PATH_RESOLUTION_FAILED"] };
  }
  const suffix: string[] = [];
  let current = absolute;
  while (true) {
    const parent = path.dirname(current);
    suffix.unshift(path.basename(current));
    try {
      const ancestor = await realpath(parent);
      return { real: path.join(ancestor, ...suffix), ancestor, exists: false, symlink: false, uncertainty: [] };
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT" || parent === current) return { exists: false, symlink: false, uncertainty: ["PATH_ANCESTOR_UNRESOLVED"] };
      current = parent;
    }
  }
}

function labelsForPath(candidate: string, context: NormalizationContext): DataLabel[] {
  const protectedPatterns = context.protectedPathPatterns ?? [DEFAULT_PROTECTED_PATH];
  const lower = candidate.toLowerCase();
  const labels: DataLabel[] = [];
  if (protectedPatterns.some(pattern => pattern.test(candidate))) labels.push("secret", "credential");
  if (/(?:private[-_]?key|id_(?:rsa|ed25519)|\.pem$|\.p12$|\.pfx$)/iu.test(candidate)) labels.push("private_key");
  if (/(?:personal|profile|contact|address|phone|ssn|social[-_]?security|identity)/iu.test(lower)) labels.push("personal");
  if (/(?:financial|finance|bank|billing|payment|invoice|tax|salary|payroll|credit[-_]?card)/iu.test(lower)) labels.push("financial", "regulated");
  if (/(?:health|medical|patient|diagnos|prescription|clinic|therapy)/iu.test(lower)) labels.push("health", "regulated");
  if (/(?:regulated|compliance|hipaa|gdpr|pci[-_]?dss|sox)/iu.test(lower)) labels.push("regulated");
  if (/(?:upload|download|attachment|untrusted|external[-_]?content|inbox)/iu.test(lower)) labels.push("untrusted_content");
  try {
    const configuredRoot = path.resolve(context.projectRoot);
    const root = (() => { try { return realpathSync(configuredRoot); } catch { return configuredRoot; } })();
    const relativePath = path.relative(root, candidate);
    const insideProject = relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
    if (insideProject) {
      labels.push("internal");
      if (/\.(?:c|cc|cpp|cs|go|java|js|jsx|mjs|py|rb|rs|sh|sql|swift|ts|tsx|vue)$/iu.test(lower)) labels.push("source_code");
    }
  } catch {
    labels.push("unknown");
  }
  return stableUnique(labels.length > 0 ? labels : ["unknown"]);
}

export async function normalizePath(raw: string, pointer: string, access: "read" | "write" | "delete", context: NormalizationContext): Promise<PathResource> {
  assertSafeText(raw, pointer);
  let local = raw;
  try {
    if (raw.startsWith("file:")) local = fileURLToPath(new URL(raw));
  } catch { throw new Error(`${pointer}: invalid file URI`); }
  const absolutePath = path.resolve(context.cwd, local);
  const resolution = await nearestRealAncestor(absolutePath);
  const canonical = resolution.real ?? absolutePath;
  return {
    kind: "path", argumentPointer: pointer, rawDigest: sha256(raw), absolutePath,
    ...(resolution.real ? { realPath: resolution.real } : {}), ...(resolution.ancestor ? { nearestRealAncestor: resolution.ancestor } : {}), exists: resolution.exists, isSymlink: resolution.symlink,
    access: [access], labels: labelsForPath(canonical, context), uncertainty: resolution.uncertainty,
  };
}

function classifyIp(hostname: string): UrlResource["addressClass"] {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "::1" || host.startsWith("127.")) return "loopback";
  if (host.startsWith("169.254.") || host.startsWith("fe80:" )) return "link_local";
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host.startsWith("fc") || host.startsWith("fd")) return "private";
  if (/^(0\.|224\.|240\.)/.test(host)) return "reserved";
  return /^[\d.:[\]]+$/.test(host) ? "unknown" : "public";
}

export function normalizeUrl(raw: string, pointer: string, method: string | undefined): UrlResource {
  assertSafeText(raw, pointer);
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error(`${pointer}: must be an absolute URL`); }
  if (!["https:", "http:"].includes(url.protocol)) throw new Error(`${pointer}: URL scheme is not allowed`);
  if (url.username || url.password) throw new Error(`${pointer}: URL credentials are prohibited`);
  const hostname = url.hostname.replace(/\.$/, "").toLowerCase();
  const addressClass = classifyIp(hostname);
  const port = url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
  const uncertainty = addressClass === "unknown" ? ["DNS_RESOLUTION_REQUIRED"] : [];
  return { kind: "url", argumentPointer: pointer, rawDigest: sha256(raw), canonicalUrl: url.toString(), scheme: url.protocol.slice(0, -1), hostname, port, ...(method ? { method: method.toUpperCase() } : {}), addressClass, labels: [], uncertainty };
}

export function normalizeCommand(raw: string | Record<string, unknown>, pointer: string): CommandResource {
  if (typeof raw === "string") {
    assertSafeText(raw, pointer);
    return { kind: "command", argumentPointer: pointer, rawDigest: sha256(raw), representation: "shell-string", argv: [], opaqueShell: true, metacharacters: SHELL_META.filter(char => raw.includes(char)), labels: [], uncertainty: ["OPAQUE_SHELL"] };
  }
  if (!isRecord(raw) || typeof raw.command !== "string" || (raw.args !== undefined && (!Array.isArray(raw.args) || raw.args.some(arg => typeof arg !== "string")))) throw new Error(`${pointer}: command must be a shell string or { command, args[] }`);
  for (const key of Object.keys(raw)) if (key !== "command" && key !== "args") throw new Error(`UNMODELED_ARGUMENT: ${pointer}/${key}`);
  assertSafeText(raw.command, pointer);
  const args = (raw.args as string[] | undefined) ?? [];
  return { kind: "command", argumentPointer: pointer, rawDigest: digestJson(raw), representation: "argv", executable: raw.command, argv: [raw.command, ...args], opaqueShell: false, metacharacters: [], labels: [], uncertainty: [] };
}

export function normalizeRecipient(raw: string, pointer: string, organizationDomains: string[]): RecipientResource {
  assertSafeText(raw, pointer);
  const match = /^([^@\s]+)@([^@\s]+)$/u.exec(raw);
  if (!match || !match[2]) throw new Error(`${pointer}: only bare email recipients are supported`);
  const domain = match[2].toLowerCase();
  return { kind: "recipient", argumentPointer: pointer, rawDigest: sha256(raw), normalized: `${match[1]}@${domain}`, domain, external: !organizationDomains.map(item => item.toLowerCase()).includes(domain), labels: [], uncertainty: [] };
}

function infer(resources: Resource[], descriptor: NormalizationDescriptor): { capabilities: Capability[]; effects: Effect[]; signals: string[] } {
  const capabilities = [...(descriptor.declaredCapabilities ?? [])];
  const effects = [...(descriptor.declaredEffects ?? [])];
  const signals: string[] = [];
  for (const resource of resources) {
    if (resource.kind === "path") {
      if (resource.access.includes("read")) { capabilities.push("fs.read"); effects.push("data.observe"); }
      if (resource.access.includes("write")) { capabilities.push("fs.write"); effects.push("data.modify", "persistent.change"); }
      if (resource.access.includes("delete")) { capabilities.push("fs.delete"); effects.push("data.delete", "irreversible.action"); }
      if (resource.labels.includes("secret") || resource.labels.includes("credential")) capabilities.push("secret.read");
    }
    if (resource.kind === "url") {
      if (resource.method && ["POST", "PUT", "PATCH", "DELETE"].includes(resource.method)) { capabilities.push("net.send"); effects.push("external.disclosure"); }
      else { capabilities.push("net.read"); effects.push("external.read"); }
      if (resource.addressClass !== "public") signals.push(`URL_${resource.addressClass.toUpperCase()}`);
    }
    if (resource.kind === "command") {
      capabilities.push(resource.opaqueShell ? "process.shell" : "process.execute"); effects.push("process.spawn");
      if (resource.opaqueShell) effects.push("command.interpretation");
      if (resource.argv.some(value => /(^|\s)rm\s+-rf\b/.test(value))) effects.push("data.delete", "irreversible.action");
    }
    if (resource.kind === "recipient" && resource.external) { capabilities.push("message.send"); effects.push("external.communication", "external.disclosure"); }
  }
  return { capabilities: stableUnique(capabilities), effects: stableUnique(effects), signals: stableUnique(signals) };
}

export async function normalizeInvocation(request: ToolCallRequest, descriptor: NormalizationDescriptor, context: NormalizationContext): Promise<ActionEnvelope> {
  assertDescriptorSafe(descriptor);
  const argumentsValue = request.params.arguments ?? {};
  if (!isRecord(argumentsValue)) throw new Error("arguments must be an object");
  if (descriptor.inputSchema !== undefined) validateSchema(argumentsValue, descriptor.inputSchema, "#/arguments");
  else if (descriptor.fields.length === 0 && Object.keys(argumentsValue).length > 0) throw new Error("UNMODELED_ARGUMENT");
  assertModeledTree(argumentsValue, "", descriptor);
  const resources: Resource[] = [];
  for (const field of descriptor.fields) {
    const value = atPointer(argumentsValue, field.pointer);
    if (value === undefined) continue;
    if (field.type === "path") { if (typeof value !== "string") throw new Error(`${field.pointer}: expected string path`); resources.push(await normalizePath(value, field.pointer, field.access ?? "read", context)); }
    if (field.type === "url") { if (typeof value !== "string") throw new Error(`${field.pointer}: expected URL string`); const method = field.methodPointer ? atPointer(argumentsValue, field.methodPointer) : undefined; resources.push(normalizeUrl(value, field.pointer, typeof method === "string" ? method : undefined)); }
    if (field.type === "command" || field.type === "command-argv") resources.push(normalizeCommand(value as string | Record<string, unknown>, field.pointer));
    if (field.type === "recipient") { if (typeof value !== "string") throw new Error(`${field.pointer}: expected email string`); resources.push(normalizeRecipient(value, field.pointer, context.organizationDomains)); }
    if (field.type === "data") { if (typeof value !== "string") throw new Error(`${field.pointer}: expected text data`); assertSafeText(value, field.pointer); resources.push({ kind: "data", argumentPointer: field.pointer, rawDigest: sha256(value), byteLength: Buffer.byteLength(value), labels: [], uncertainty: [] }); }
  }
  const inferred = infer(resources, descriptor);
  const labels = stableUnique([...(descriptor.declaredLabels ?? []), ...resources.flatMap(resource => resource.labels)]);
  const uncertainty = stableUnique(resources.flatMap(resource => resource.uncertainty));
  return {
    envelopeVersion: "1.0", invocationId: newId("inv"), requestId: String(request.id ?? "notification"), sessionId: context.sessionId, timestamp: (context.now?.() ?? new Date()).toISOString(), subject: context.principal,
    target: { serverId: context.serverId ?? "default", toolName: request.params.name, toolSchemaDigest: context.schemaDigest, toolDescriptorDigest: context.descriptorDigest, registryVersion: context.registryVersion ?? "registry_static", protocolEra: context.protocolEra ?? "2025-11-25" },
    raw: { protocolMethod: "tools/call", argumentBytes: Buffer.byteLength(JSON.stringify(argumentsValue)), argumentKeys: Object.keys(argumentsValue).sort() },
    capabilities: inferred.capabilities, effects: inferred.effects, resources, labels, lineage: context.lineage, riskSignals: inferred.signals, uncertainty,
    integrity: { argumentsDigest: digestJson(argumentsValue), requestDigest: digestJson(request), policyVersionId: context.policyVersionId, normalizerVersion: "1.0" },
  };
}
