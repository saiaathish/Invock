import { createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { canonicalize, digestJson, sha256 } from "../core/canonical.js";

const MAX_EVIDENCE_BYTES = 4 * 1024 * 1024;
const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json"] as const;
const CONTAINER_FILES = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "docker/containment.Dockerfile"] as const;

export interface SupplyChainEvidenceFile { path: string; bytes: number; digest: string; status: "read" | "too_large" | "missing"; }
export interface SupplyChainDependency { name: string; requestedVersion: string; scope: "runtime" | "development" | "optional" | "peer"; }
export interface SupplyChainResolvedDependency { name: string; version: string; integrity?: string; source: "pnpm-lockfile"; }
export interface SupplyChainDependencyEdge { importer: string; from: string; name: string; version: string; resolved: boolean; }
export interface SupplyChainImporterSnapshot { importer: string; dependencies: Record<string, { requestedVersion?: string; resolvedVersion?: string }>; }
export interface SupplyChainContainerReference { source: string; image: string; digestPinned: boolean; }
export interface SupplyChainSigningMaterial { privateKeyPem: string | KeyObject; publicKeyPem: string; keyId?: string; }
export interface SupplyChainSignature {
  algorithm: "Ed25519";
  keyId: string;
  publicKeyPem: string;
  signedDigest: string;
  signature: string;
  trust: "self-generated-local-evidence";
}
export interface SupplyChainReport {
  schemaVersion: "invock/supply-chain-report/v1";
  root: string;
  evidenceFiles: SupplyChainEvidenceFile[];
  dependencies: SupplyChainDependency[];
  resolvedDependencies: SupplyChainResolvedDependency[];
  resolutionStatus: "resolved" | "unresolved" | "missing";
  resolutionCompleteness: "complete" | "partial" | "none";
  dependencyEdges: SupplyChainDependencyEdge[];
  importerSnapshots: SupplyChainImporterSnapshot[];
  lockfileMetadata: { format: "pnpm" | "unknown"; lockfileVersion?: string; snapshotCount: number };
  sbom: { bomFormat: "CycloneDX"; specVersion: "1.5"; serialNumber: string; components: Array<{ type: "library"; name: string; version: string; scope: string; integrity?: string }>; digest: string };
  containerReferences: SupplyChainContainerReference[];
  lockfileStatus: "present" | "missing";
  advisoryStatus: "not-queried" | "queried-no-findings" | "queried-findings" | "query-failed";
  advisoryEvidenceDigest?: string;
  signatureStatus: "verified" | "not-verified";
  signature?: SupplyChainSignature;
  claims: { maliciousPackage: "not-claimed"; provenance: "signed-local-evidence" | "evidence-only" };
  reproducibleDigest: string;
}

export interface SupplyChainScanOptions {
  signing?: SupplyChainSigningMaterial;
  advisory?: { status: Exclude<SupplyChainReport["advisoryStatus"], "not-queried">; evidenceDigest: string };
}

function validEvidenceDigest(value: string): boolean { return /^[A-Za-z0-9_-]{43}$/.test(value); }

function deterministicSbomSerialNumber(value: unknown): string {
  const hex = Buffer.from(sha256(canonicalize(value)), "base64url").toString("hex");
  const variant = ((Number.parseInt(hex[16] ?? "0", 16) & 0x3) | 0x8).toString(16);
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function boundedText(path: string): { text?: string; evidence: SupplyChainEvidenceFile } {
  if (!existsSync(path)) return { evidence: { path, bytes: 0, digest: digestJson({ status: "missing", path: basename(path) }), status: "missing" } };
  const bytes = statSync(path).size;
  if (bytes > MAX_EVIDENCE_BYTES) return { evidence: { path, bytes, digest: digestJson({ status: "too_large", path: basename(path), bytes }), status: "too_large" } };
  const content = readFileSync(path);
  return { text: content.toString("utf8"), evidence: { path, bytes: content.byteLength, digest: sha256(content), status: "read" } };
}

function dependencies(manifest: Record<string, unknown>): SupplyChainDependency[] {
  const output: SupplyChainDependency[] = [];
  for (const [field, scope] of [["dependencies", "runtime"], ["devDependencies", "development"], ["optionalDependencies", "optional"], ["peerDependencies", "peer"]] as const) {
    const values = manifest[field];
    if (values === null || typeof values !== "object" || Array.isArray(values)) continue;
    for (const [name, requestedVersion] of Object.entries(values as Record<string, unknown>)) if (typeof requestedVersion === "string") output.push({ name, requestedVersion, scope });
  }
  return output.sort((a, b) => a.name.localeCompare(b.name) || a.scope.localeCompare(b.scope));
}

function snapshotIdentity(key: string): { name: string; version: string } | undefined {
  const normalized = key.replace(/^\/+/u, "");
  const at = normalized.indexOf("@", normalized.startsWith("@") ? 1 : 0);
  if (at <= 0 || at === normalized.length - 1) return undefined;
  const version = normalized.slice(at + 1).split("(", 1)[0]?.trim();
  const name = normalized.slice(0, at).trim();
  if (!name || !version || !/^[0-9A-Za-z][0-9A-Za-z.+_-]*(?:\.[0-9A-Za-z.+_-]+)*$/u.test(version)) return undefined;
  return { name, version };
}

function resolvePnpmLockfile(text: string): { status: "resolved" | "unresolved"; completeness: "complete" | "partial" | "none"; dependencies: SupplyChainResolvedDependency[]; edges: SupplyChainDependencyEdge[]; importers: SupplyChainImporterSnapshot[]; lockfileVersion?: string } {
  try {
    const parsed: unknown = parseYaml(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return { status: "unresolved", completeness: "none", dependencies: [], edges: [], importers: [] };
    const root = parsed as Record<string, unknown>; const packages = root.packages;
    if (packages === null || typeof packages !== "object" || Array.isArray(packages)) return { status: "unresolved", completeness: "none", dependencies: [], edges: [], importers: [] };
    const resolved: SupplyChainResolvedDependency[] = [];
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      const identity = snapshotIdentity(key);
      if (!identity || value === null || typeof value !== "object" || Array.isArray(value)) return { status: "unresolved", completeness: "none", dependencies: [], edges: [], importers: [] };
      const resolution = (value as Record<string, unknown>).resolution;
      const integrity = resolution !== null && typeof resolution === "object" && !Array.isArray(resolution) && typeof (resolution as Record<string, unknown>).integrity === "string"
        ? (resolution as Record<string, unknown>).integrity as string
        : undefined;
      resolved.push({ ...identity, ...(integrity ? { integrity } : {}), source: "pnpm-lockfile" });
    }
    resolved.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version) || (a.integrity ?? "").localeCompare(b.integrity ?? ""));
    const edges: SupplyChainDependencyEdge[] = []; const importers: SupplyChainImporterSnapshot[] = [];
    const importerRoot = root.importers;
    if (importerRoot !== null && typeof importerRoot === "object" && !Array.isArray(importerRoot)) for (const [importer, raw] of Object.entries(importerRoot as Record<string, unknown>)) {
      const data = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : {};
      const deps: Record<string, { requestedVersion?: string; resolvedVersion?: string }> = {};
      for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const value = data[field]; if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
        for (const [name, rawSpec] of Object.entries(value as Record<string, unknown>)) {
          const spec = rawSpec !== null && typeof rawSpec === "object" && !Array.isArray(rawSpec) ? rawSpec as Record<string, unknown> : {};
          const requestedVersion = typeof spec.specifier === "string" ? spec.specifier : undefined;
          const resolvedVersion = typeof spec.version === "string" ? spec.version.split("(", 1)[0] : undefined;
          deps[name] = { ...(requestedVersion ? { requestedVersion } : {}), ...(resolvedVersion ? { resolvedVersion } : {}) };
          edges.push({ importer, from: importer, name, version: resolvedVersion ?? "UNKNOWN", resolved: resolvedVersion !== undefined });
        }
      }
      importers.push({ importer, dependencies: deps });
    }
    const snapshots = root.snapshots;
    if (snapshots !== null && typeof snapshots === "object" && !Array.isArray(snapshots)) for (const [key, raw] of Object.entries(snapshots as Record<string, unknown>)) {
      const identity = snapshotIdentity(key); const data = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : {};
      const deps = data.dependencies; if (!identity || deps === null || typeof deps !== "object" || Array.isArray(deps)) continue;
      for (const [name, version] of Object.entries(deps as Record<string, unknown>)) if (typeof version === "string") edges.push({ importer: "<snapshot>", from: `${identity.name}@${identity.version}`, name, version: version.split("(", 1)[0] ?? "UNKNOWN", resolved: true });
    }
    edges.sort((a, b) => a.importer.localeCompare(b.importer) || a.from.localeCompare(b.from) || a.name.localeCompare(b.name) || a.version.localeCompare(b.version)); importers.sort((a, b) => a.importer.localeCompare(b.importer));
    // An absent importer map must never become "complete" through vacuous
    // truth. A package snapshot without importer edges is only partial
    // resolution evidence, even when every package entry parsed cleanly.
    const complete = resolved.length > 0 && importers.length > 0 && importers.every(item => Object.values(item.dependencies).every(dep => dep.resolvedVersion !== undefined));
    return { status: resolved.length > 0 ? "resolved" : "unresolved", completeness: resolved.length === 0 ? "none" : complete ? "complete" : "partial", dependencies: resolved, edges, importers, ...(typeof root.lockfileVersion === "string" ? { lockfileVersion: root.lockfileVersion } : {}) };
  } catch {
    return { status: "unresolved", completeness: "none", dependencies: [], edges: [], importers: [] };
  }
}

function containers(root: string, files: Array<{ path: string; text?: string }>): SupplyChainContainerReference[] {
  const references: SupplyChainContainerReference[] = [];
  for (const file of files) {
    if (!file.text) continue;
    const source = file.path.slice(root.length + 1);
    const matches = file.text.matchAll(/^\s*FROM\s+([^\s#]+)|^\s*image:\s*([^\s#]+)/gim);
    for (const match of matches) {
      const image = (match[1] ?? match[2])?.trim();
      if (image) references.push({ source, image, digestPinned: /@sha256:[a-f0-9]{64}$/u.test(image) });
    }
  }
  return references.sort((a, b) => a.source.localeCompare(b.source) || a.image.localeCompare(b.image));
}

function signingPayload(report: SupplyChainReport): Record<string, unknown> {
  return {
    domain: "invock-supply-chain-report-signature-v1",
    schemaVersion: report.schemaVersion,
    root: report.root,
    evidenceFiles: report.evidenceFiles,
    dependencies: report.dependencies,
    resolvedDependencies: report.resolvedDependencies,
    resolutionStatus: report.resolutionStatus,
    resolutionCompleteness: report.resolutionCompleteness,
    dependencyEdges: report.dependencyEdges,
    importerSnapshots: report.importerSnapshots,
    lockfileMetadata: report.lockfileMetadata,
    sbom: report.sbom,
    containerReferences: report.containerReferences,
    lockfileStatus: report.lockfileStatus,
    advisoryStatus: report.advisoryStatus,
    ...(report.advisoryEvidenceDigest ? { advisoryEvidenceDigest: report.advisoryEvidenceDigest } : {}),
    signatureStatus: report.signatureStatus,
    claims: report.claims,
    reproducibleDigest: report.reproducibleDigest,
  };
}

function publicKeyId(publicKeyPem: string): string {
  return sha256(publicKeyPem);
}

function signaturePayload(report: SupplyChainReport): Buffer {
  return Buffer.from(canonicalize(signingPayload(report)), "utf8");
}

function validSignatureShape(signature: SupplyChainSignature): boolean {
  return signature.algorithm === "Ed25519"
    && signature.trust === "self-generated-local-evidence"
    && signature.keyId === publicKeyId(signature.publicKeyPem)
    && /^[A-Za-z0-9_-]{43}$/u.test(signature.keyId)
    && /^[A-Za-z0-9_-]+$/u.test(signature.signature)
    && /^[A-Za-z0-9_-]{43}$/u.test(signature.signedDigest);
}

export function generateSupplyChainSigningMaterial(): SupplyChainSigningMaterial {
  const pair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKeyPem: pair.privateKey, publicKeyPem: pair.publicKey, keyId: publicKeyId(pair.publicKey) };
}

export function signSupplyChainReport(report: SupplyChainReport, material: SupplyChainSigningMaterial): SupplyChainSignature {
  const publicKeyPem = material.publicKeyPem;
  const keyId = material.keyId ?? publicKeyId(publicKeyPem);
  if (keyId !== publicKeyId(publicKeyPem)) throw new Error("SUPPLY_CHAIN_SIGNING_KEY_ID_MISMATCH");
  const signedReport: SupplyChainReport = { ...report, signatureStatus: "verified", claims: { ...report.claims, provenance: "signed-local-evidence" } };
  const payload = signaturePayload(signedReport);
  const signedDigest = digestJson(signingPayload(signedReport));
  const signature: SupplyChainSignature = {
    algorithm: "Ed25519",
    keyId,
    publicKeyPem,
    signedDigest,
    signature: sign(null, payload, material.privateKeyPem).toString("base64url"),
    trust: "self-generated-local-evidence",
  };
  if (!verifySupplyChainSignature({ ...signedReport, signature }, signature)) throw new Error("SUPPLY_CHAIN_SIGNATURE_SELF_CHECK_FAILED");
  return signature;
}

export function verifySupplyChainSignature(report: SupplyChainReport, signature = report.signature, trustedPublicKeyPem?: string): boolean {
  if (!signature || !validSignatureShape(signature)) return false;
  if (trustedPublicKeyPem !== undefined && trustedPublicKeyPem !== signature.publicKeyPem) return false;
  const payload = signaturePayload(report);
  if (signature.signedDigest !== digestJson(signingPayload(report))) return false;
  try { return verify(null, payload, createPublicKey(signature.publicKeyPem), Buffer.from(signature.signature, "base64url")); } catch { return false; }
}

/**
 * Produce a local, deterministic supply-chain inventory from checked-in evidence.
 * It never infers that a package is malicious. Manifest ranges are kept separate
 * from resolved lockfile snapshots so an incomplete parser cannot masquerade as
 * a complete SBOM.
 */
export function scanSupplyChain(rootDirectory: string, options: SupplyChainScanOptions = {}): SupplyChainReport {
  const root = resolve(rootDirectory);
  const packagePath = resolve(root, "package.json");
  const packageEvidence = boundedText(packagePath);
  let manifest: Record<string, unknown> = {};
  if (packageEvidence.text) {
    try {
      const parsed: unknown = JSON.parse(packageEvidence.text);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) manifest = parsed as Record<string, unknown>;
    } catch { /* malformed manifests remain evidence, not a security verdict */ }
  }
  const lockEvidence = LOCKFILES.map(name => boundedText(resolve(root, name)));
  const containerEvidence = CONTAINER_FILES.map(name => boundedText(resolve(root, name)));
  const evidenceFiles = [packageEvidence.evidence, ...lockEvidence.map(item => item.evidence), ...containerEvidence.map(item => item.evidence)].sort((a, b) => a.path.localeCompare(b.path));
  const inventory = dependencies(manifest);
  const packageName = typeof manifest.name === "string" ? manifest.name : "unnamed-project";
  const packageVersion = typeof manifest.version === "string" ? manifest.version : "unversioned";
  const lockfileStatus = lockEvidence.some(item => item.evidence.status === "read") ? "present" : "missing";
  const pnpmLock = lockEvidence.find(item => item.evidence.path.endsWith("/pnpm-lock.yaml") && item.text !== undefined);
  const resolution = pnpmLock?.text !== undefined ? resolvePnpmLockfile(pnpmLock.text) : { status: lockfileStatus === "missing" ? "missing" as const : "unresolved" as const, completeness: "none" as const, dependencies: [], edges: [], importers: [] };
  const resolvedDependencies = resolution.dependencies;
  const resolutionStatus = resolution.status;
  const resolutionCompleteness = resolution.completeness;
  const advisoryStatus = options.advisory?.status ?? "not-queried";
  if (options.advisory && !validEvidenceDigest(options.advisory.evidenceDigest)) throw new Error("SUPPLY_CHAIN_ADVISORY_EVIDENCE_REQUIRED");
  const versionEvidence = resolutionStatus === "resolved" ? "resolved-lockfile" : lockfileStatus === "present" ? "unresolved-lockfile" : "manifest-range";
  const components = [
    { type: "library" as const, name: packageName, version: packageVersion, scope: "application" },
    ...(resolutionStatus === "resolved"
      ? resolvedDependencies.map(item => ({ type: "library" as const, name: item.name, version: item.version, scope: "resolved:pnpm-lockfile", ...(item.integrity ? { integrity: item.integrity } : {}) }))
      : inventory.map(item => ({ type: "library" as const, name: item.name, version: item.requestedVersion, scope: `${item.scope}:${versionEvidence}` }))),
  ];
  const sbomBody = { bomFormat: "CycloneDX" as const, specVersion: "1.5" as const, components };
  const serialNumber = deterministicSbomSerialNumber(sbomBody);
  const sbom = { ...sbomBody, serialNumber, digest: digestJson({ ...sbomBody, serialNumber }) };
  const containerReferences = containers(root, containerEvidence.map(item => ({ path: item.evidence.path, ...(item.text !== undefined ? { text: item.text } : {}) })));
  const { digest: _sbomDigest, ...sbomEvidence } = sbom;
  const lockfileVersion = "lockfileVersion" in resolution ? resolution.lockfileVersion : undefined;
  const lockfileMetadata = { format: pnpmLock ? "pnpm" as const : "unknown" as const, ...(lockfileVersion ? { lockfileVersion } : {}), snapshotCount: resolvedDependencies.length };
  const advisoryEvidenceDigest = options.advisory?.evidenceDigest;
  const reproducibleDigest = digestJson({ evidenceFiles: evidenceFiles.map(file => ({ path: file.path.slice(root.length + 1), bytes: file.bytes, digest: file.digest, status: file.status })), dependencies: inventory, resolvedDependencies, resolutionStatus, resolutionCompleteness, dependencyEdges: resolution.edges, importerSnapshots: resolution.importers, lockfileMetadata, sbom: sbomEvidence, containerReferences, lockfileStatus, advisoryStatus, ...(advisoryEvidenceDigest ? { advisoryEvidenceDigest } : {}), signatureStatus: "not-verified" });
  const unsigned: SupplyChainReport = { schemaVersion: "invock/supply-chain-report/v1", root, evidenceFiles, dependencies: inventory, resolvedDependencies, resolutionStatus, resolutionCompleteness, dependencyEdges: resolution.edges, importerSnapshots: resolution.importers, lockfileMetadata, sbom, containerReferences, lockfileStatus, advisoryStatus, ...(advisoryEvidenceDigest ? { advisoryEvidenceDigest } : {}), signatureStatus: "not-verified", claims: { maliciousPackage: "not-claimed", provenance: "evidence-only" }, reproducibleDigest };
  if (!options.signing) return unsigned;
  const signature = signSupplyChainReport(unsigned, options.signing);
  const signed: SupplyChainReport = { ...unsigned, signatureStatus: "verified", signature, claims: { ...unsigned.claims, provenance: "signed-local-evidence" } };
  if (!verifySupplyChainSignature(signed)) throw new Error("SUPPLY_CHAIN_SIGNATURE_SELF_CHECK_FAILED");
  return signed;
}
