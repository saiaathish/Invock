import { createHmac, generateKeyPairSync, sign, verify } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { canonicalize, digestJson } from "../core/canonical.js";
import { generateSigningMaterial } from "../storage/receipts.js";
import { type LocalLegacyState, type LegacySourceType } from "./legacy/types.js";

export type InvockPrivacyMode = "LOCAL_ZDR" | "END_TO_END_ZDR";
export type DataClass = "PUBLIC" | "INTERNAL" | "SOURCE_CODE" | "PERSONAL" | "HEALTH" | "FINANCIAL" | "LEGAL" | "CREDENTIAL" | "SECRET" | "REGULATED" | "UNKNOWN";
export type RetentionClass = "VERIFIED_ZDR" | "CONTRACTUAL_ZDR" | "SELF_ATTESTED_ZDR" | "STANDARD_RETENTION" | "UNKNOWN_RETENTION";
export type ProcessorType = "AGENT_HOST" | "MODEL_PROVIDER" | "MODEL_ENDPOINT" | "MCP_SERVER" | "TOOL" | "DOWNSTREAM_API" | "DATABASE" | "QUEUE" | "PROXY" | "OBSERVABILITY" | "BACKUP_SYSTEM";
export type PrivacyReasonCode = "LOCAL_ZDR_SATISFIED" | "LOCAL_ZDR_PERSISTENCE_ATTEMPT" | "LOCAL_ZDR_CONTENT_LOGGING_ATTEMPT" | "LOCAL_ZDR_TEMP_FILE_ATTEMPT" | "PRIVACY_CONTRACT_INVALID" | "PRIVACY_CONTRACT_EXPIRED" | "PRIVACY_MODE_UNSUPPORTED" | "PROCESSOR_NOT_DECLARED" | "PROCESSOR_PROFILE_MISSING" | "PROCESSOR_PROFILE_INVALID" | "PROCESSOR_PROFILE_EXPIRED" | "PROCESSOR_RETENTION_UNKNOWN" | "PROCESSOR_NOT_ZDR" | "PROCESSOR_SELF_ATTESTED_ONLY" | "CONTENT_LOGGING_ENABLED" | "CUSTOMER_CONTENT_PERSISTED" | "PERSISTENT_FEATURE_REQUIRED" | "REQUIRED_REQUEST_SETTING_MISSING" | "PRIVACY_CHAIN_CHANGED" | "END_TO_END_ZDR_SATISFIED" | "END_TO_END_ZDR_UNSATISFIED" | "UNOBSERVABLE_PROCESSOR_PATH" | "UPSTREAM_BLOCKED_BY_PRIVACY";

export interface LegacyOnboardingConfig {
  status: LocalLegacyState;
  reminder: boolean;
  last_scan_id: string | null;
  last_scan_at: string | null;
  boundary_id: string | null;
  default_scopes: LegacySourceType[];
  include_workspace_by_default: boolean;
  include_custom_roots_by_default: boolean;
  maximum_file_size_bytes: number;
  maximum_total_scan_bytes: number;
}

export interface ProcessorRetentionProfile {
  id: string; version: number; processorType: ProcessorType; provider?: string; product?: string; endpoint?: string;
  retentionClass: RetentionClass; receivesCustomerContent: boolean; customerContentPersisted: false | true | "UNKNOWN"; contentLoggingEnabled: false | true | "UNKNOWN"; contentUsedForTraining: false | true | "UNKNOWN"; humanReviewPossible: false | true | "UNKNOWN"; maximumContentRetentionSeconds?: number; requiredRequestSettings: Record<string, unknown>; forbiddenFeatures: string[]; evidence: { type: "PROVIDER_CONFIGURATION" | "CONTRACT" | "SIGNED_MANIFEST" | "ADMIN_ATTESTATION" | "SELF_ATTESTATION" | "UNKNOWN"; issuer?: string; reference?: string; verifiedAt?: string; expiresAt?: string }; createdAt: string; updatedAt: string; digest: string; keyId: string; signature: string;
}
export interface PrivacyContract { id: string; version: number; mode: InvockPrivacyMode; metadataTtlSeconds: number; digest: string; keyId: string; publicKeyPem: string; signature: string; createdAt: string; notBefore: string; expiresAt?: string; }
export interface PrivacyConfig { mode: InvockPrivacyMode; contractId: string; metadataTtlSeconds: number; pseudonymizationScope: "session"; contract: PrivacyContract; processors: ProcessorRetentionProfile[]; pseudonymKeyPath: string; legacy_onboarding?: LegacyOnboardingConfig; }
export interface PrivacyEvaluation { mode: InvockPrivacyMode; verdict: "ALLOW" | "BLOCK"; reasonCodes: PrivacyReasonCode[]; localZdrSatisfied: boolean; endToEndZdrSatisfied: boolean; chainDigest: string; contractDigest: string; processorProfileDigests: string[]; }

const allowedModes = new Set<InvockPrivacyMode>(["LOCAL_ZDR", "END_TO_END_ZDR"]);
const now = () => new Date().toISOString();
const baseContract = (mode: InvockPrivacyMode, id: string): PrivacyContract => { const unsigned = { id, version: 1, mode, metadataTtlSeconds: 2_592_000, createdAt: now(), notBefore: now() }; const digest = digestJson(unsigned); const signing = generateSigningMaterial(); const signature = sign(null, Buffer.from(`invock-privacy-contract-v1\0${digest}`, "utf8"), signing.privateKeyPem).toString("base64url"); return { ...unsigned, digest, keyId: signing.signingKeyId, publicKeyPem: signing.publicKeyPem, signature }; };
const atomic = (path: string, value: unknown) => { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); chmodSync(path, 0o600); };
const keyAt = (path: string) => { if (!existsSync(path)) { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); writeFileSync(path, generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" })); chmodSync(path, 0o600); } return readFileSync(path); };

export function validateMode(value: unknown): InvockPrivacyMode { if (typeof value !== "string" || !allowedModes.has(value as InvockPrivacyMode)) throw new Error("PRIVACY_MODE_UNSUPPORTED"); return value as InvockPrivacyMode; }
export function defaultPrivacyConfig(directory: string): PrivacyConfig {
  const contract = baseContract("LOCAL_ZDR", "default-local-zdr");
  return {
    mode: "LOCAL_ZDR",
    contractId: contract.id,
    metadataTtlSeconds: contract.metadataTtlSeconds,
    pseudonymizationScope: "session",
    contract,
    processors: [],
    pseudonymKeyPath: join(directory, "privacy-pseudonym.key"),
    legacy_onboarding: {
      status: "NOT_SCANNED",
      reminder: true,
      last_scan_id: null,
      last_scan_at: null,
      boundary_id: null,
      default_scopes: ["INVOCK_LEGACY", "CLAUDE_LOCAL", "CODEX_LOCAL"],
      include_workspace_by_default: false,
      include_custom_roots_by_default: false,
      maximum_file_size_bytes: 16777216,
      maximum_total_scan_bytes: 2147483648
    }
  };
}
export function loadPrivacyConfig(directory: string): PrivacyConfig {
  const path = join(directory, "privacy.json");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (!existsSync(path)) {
    const config = defaultPrivacyConfig(directory);
    atomic(path, config);
    return config;
  }
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<PrivacyConfig>;
  const mode = validateMode(parsed.mode ?? "LOCAL_ZDR");
  if (!parsed.contract || !parsed.contractId) {
    const config = defaultPrivacyConfig(directory);
    config.mode = mode;
    config.contract = baseContract(mode, mode === "LOCAL_ZDR" ? "default-local-zdr" : "default-end-to-end-zdr");
    config.contractId = config.contract.id;
    atomic(path, config);
    return config;
  }
  if (parsed.contract.mode !== mode) throw new Error("PRIVACY_CONTRACT_INVALID");
  const config = {
    ...defaultPrivacyConfig(directory),
    ...parsed,
    mode,
    contract: parsed.contract as PrivacyContract,
    processors: parsed.processors ?? [],
    legacy_onboarding: parsed.legacy_onboarding ?? {
      status: "NOT_SCANNED",
      reminder: true,
      last_scan_id: null,
      last_scan_at: null,
      boundary_id: null,
      default_scopes: ["INVOCK_LEGACY", "CLAUDE_LOCAL", "CODEX_LOCAL"],
      include_workspace_by_default: false,
      include_custom_roots_by_default: false,
      maximum_file_size_bytes: 16777216,
      maximum_total_scan_bytes: 2147483648
    }
  } as PrivacyConfig;
  if (!parsed.legacy_onboarding) {
    atomic(path, config);
  }
  return config;
}
export function savePrivacyConfig(directory: string, config: PrivacyConfig): void { validateMode(config.mode); if (config.contract.mode !== config.mode) throw new Error("PRIVACY_CONTRACT_INVALID"); atomic(join(directory, "privacy.json"), config); }
export function setPrivacyMode(directory: string, mode: InvockPrivacyMode): PrivacyConfig { const config = loadPrivacyConfig(directory); validateMode(mode); const contract = baseContract(mode, mode === "LOCAL_ZDR" ? "default-local-zdr" : "default-end-to-end-zdr"); const next = { ...config, mode, contractId: contract.id, contract }; savePrivacyConfig(directory, next); return next; }
export function pseudonymize(value: string, keyPath: string): string { return createHmac("sha256", keyAt(keyPath)).update(value).digest("hex").slice(0, 32); }
export function evaluatePrivacy(config: PrivacyConfig, declaredProcessorIds: string[] = []): PrivacyEvaluation { const reasons: PrivacyReasonCode[] = ["LOCAL_ZDR_SATISFIED"]; const profiles = declaredProcessorIds.map(id => config.processors.find(profile => profile.id === id)); if (config.mode === "END_TO_END_ZDR") { for (const profile of profiles) { if (!profile) { reasons.push("PROCESSOR_PROFILE_MISSING"); continue; } if (profile.retentionClass === "UNKNOWN_RETENTION") reasons.push("PROCESSOR_RETENTION_UNKNOWN"); else if (profile.retentionClass === "SELF_ATTESTED_ZDR") reasons.push("PROCESSOR_SELF_ATTESTED_ONLY"); else if (!["VERIFIED_ZDR", "CONTRACTUAL_ZDR"].includes(profile.retentionClass)) reasons.push("PROCESSOR_NOT_ZDR"); if (profile.customerContentPersisted !== false) reasons.push("CUSTOMER_CONTENT_PERSISTED"); if (profile.contentLoggingEnabled !== false) reasons.push("CONTENT_LOGGING_ENABLED"); if (profile.evidence.expiresAt && Date.parse(profile.evidence.expiresAt) <= Date.now()) reasons.push("PROCESSOR_PROFILE_EXPIRED"); } if (profiles.length === 0) reasons.push("PROCESSOR_NOT_DECLARED"); if (reasons.length === 1) reasons.push("END_TO_END_ZDR_SATISFIED"); else reasons.push("END_TO_END_ZDR_UNSATISFIED"); } const blocked = config.mode === "END_TO_END_ZDR" && reasons.includes("END_TO_END_ZDR_UNSATISFIED"); return { mode: config.mode, verdict: blocked ? "BLOCK" : "ALLOW", reasonCodes: reasons, localZdrSatisfied: true, endToEndZdrSatisfied: !blocked, chainDigest: digestJson(profiles.map(profile => profile ? ({ id: profile.id, version: profile.version, digest: profile.digest }) : null)), contractDigest: config.contract.digest, processorProfileDigests: profiles.filter((profile): profile is ProcessorRetentionProfile => Boolean(profile)).map(profile => profile.digest) }; }
export function addProcessor(config: PrivacyConfig, profile: ProcessorRetentionProfile): PrivacyConfig { const next = { ...config, processors: [...config.processors.filter(item => item.id !== profile.id), profile] }; savePrivacyConfig(dirname(config.pseudonymKeyPath), next); return next; }
export function removeProcessor(config: PrivacyConfig, id: string): PrivacyConfig { const next = { ...config, processors: config.processors.filter(item => item.id !== id) }; savePrivacyConfig(dirname(config.pseudonymKeyPath), next); return next; }
export function isPrivacyCustomerContent(value: unknown): boolean { return value !== undefined && value !== null; }
export function privacyContractDigest(config: PrivacyConfig): string { return digestJson({ ...config.contract, signature: undefined }); }
export function verifyPrivacyContract(config: PrivacyConfig): boolean { try { const unsigned = { id: config.contract.id, version: config.contract.version, mode: config.contract.mode, metadataTtlSeconds: config.contract.metadataTtlSeconds, createdAt: config.contract.createdAt, notBefore: config.contract.notBefore, ...(config.contract.expiresAt ? { expiresAt: config.contract.expiresAt } : {}) }; return config.contract.digest === digestJson(unsigned) && verify(null, Buffer.from(`invock-privacy-contract-v1\0${config.contract.digest}`, "utf8"), config.contract.publicKeyPem, Buffer.from(config.contract.signature, "base64url")); } catch { return false; } }
