import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { generateSigningMaterial, type SigningMaterial } from "../storage/receipts.js";
import { sign, verify } from "node:crypto";
import { basename, join, resolve } from "node:path";
import { canonicalize, digestJson } from "../core/canonical.js";
import { isValidContainmentTelemetry, unavailableTelemetry, type ContainmentResult } from "./types.js";

export interface ContainmentRunRecord {
  schemaVersion: "invock/containment-run/v2";
  runId: string;
  createdAt: string;
  requestDigest: string;
  /** Digest of the canonical authorized invocation request, when bound to a gateway forward. */
  authorizedRequestDigest?: string;
  command: string;
  result: ContainmentResult;
  invocationId?: string;
  sessionId?: string;
  profileDigest?: string;
  integrity: ContainmentRunIntegrity;
}

export interface UnsignedContainmentRunRecord {
  schemaVersion: "invock/containment-run/v2";
  runId: string;
  createdAt: string;
  requestDigest: string;
  /** Digest of the canonical authorized invocation request, when bound to a gateway forward. */
  authorizedRequestDigest?: string;
  command: string;
  result: ContainmentResult;
  invocationId?: string;
  sessionId?: string;
  profileDigest?: string;
}

export interface ContainmentRunIntegrity {
  algorithm: "Ed25519";
  keyId: string;
  publicKeyPem: string;
  recordDigest: string;
  signature: string;
}

export interface TrustedContainmentKey {
  readonly keyId: string;
  readonly publicKeyPem: string;
}
export type TrustedContainmentKeys = readonly TrustedContainmentKey[];
export interface ApprovedContainmentProfile {
  readonly profileDigest: string;
  readonly capabilities: ContainmentResult["capabilities"];
}

const DOMAIN = "invock-containment-run-v2\0";
const DIGEST = /^[A-Za-z0-9_-]{43}$/u;
let temporarySequence = 0;

function keyPaths(directory: string): { privatePath: string; publicPath: string; keyIdPath: string } {
  return {
    privatePath: join(directory, ".containment-ed25519.private.pem"),
    publicPath: join(directory, ".containment-ed25519.public.pem"),
    keyIdPath: join(directory, ".containment-ed25519.key-id"),
  };
}

function writeSecret(path: string, content: string): void {
  writeFileSync(path, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
  try { chmodSync(path, 0o600); } catch { /* best effort on non-POSIX filesystems */ }
}

function signingMaterial(directory: string, stateExists: boolean): SigningMaterial {
  const paths = keyPaths(directory);
  const present = [paths.privatePath, paths.publicPath, paths.keyIdPath].map(path => existsSync(path));
  if (present.some(Boolean) && !present.every(Boolean)) throw new Error("CONTAINMENT_SIGNING_KEY_SET_INCOMPLETE");
  if (present.every(Boolean)) {
    return { privateKeyPem: readFileSync(paths.privatePath, "utf8"), publicKeyPem: readFileSync(paths.publicPath, "utf8"), signingKeyId: readFileSync(paths.keyIdPath, "utf8").trim() };
  }
  if (stateExists) throw new Error("CONTAINMENT_SIGNING_KEY_MISSING");
  const material = generateSigningMaterial();
  writeSecret(paths.privatePath, material.privateKeyPem);
  writeSecret(paths.publicPath, material.publicKeyPem);
  writeSecret(paths.keyIdPath, material.signingKeyId);
  return material;
}

function payload(record: UnsignedContainmentRunRecord): string {
  return `${DOMAIN}${canonicalize(record)}`;
}

function unsigned(record: UnsignedContainmentRunRecord | ContainmentRunRecord): UnsignedContainmentRunRecord {
  return {
    schemaVersion: record.schemaVersion,
    runId: record.runId,
    createdAt: record.createdAt,
    requestDigest: record.requestDigest,
    ...(record.authorizedRequestDigest ? { authorizedRequestDigest: record.authorizedRequestDigest } : {}),
    command: record.command,
    result: record.result,
    ...(record.invocationId ? { invocationId: record.invocationId } : {}),
    ...(record.sessionId ? { sessionId: record.sessionId } : {}),
    ...(record.profileDigest ? { profileDigest: record.profileDigest } : {}),
  };
}

function signedResult(result: ContainmentResult): ContainmentResult {
  return { ...result, telemetry: result.telemetry ?? unavailableTelemetry("legacy_record") };
}

function assertUnsigned(record: UnsignedContainmentRunRecord): void {
  if (record.schemaVersion !== "invock/containment-run/v2" || typeof record.runId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(record.runId)) throw new Error("CONTAINMENT_RUN_INVALID");
  if (typeof record.createdAt !== "string" || !Number.isFinite(Date.parse(record.createdAt))) throw new Error("CONTAINMENT_RUN_INVALID");
  if (typeof record.requestDigest !== "string" || !DIGEST.test(record.requestDigest) || typeof record.command !== "string" || record.command.length === 0 || record.command.length > 512 || record.result === null || typeof record.result !== "object") throw new Error("CONTAINMENT_RUN_INVALID");
  if (record.authorizedRequestDigest !== undefined && (typeof record.authorizedRequestDigest !== "string" || !DIGEST.test(record.authorizedRequestDigest))) throw new Error("CONTAINMENT_RUN_INVALID");
  if (record.invocationId !== undefined && (typeof record.invocationId !== "string" || record.invocationId.length === 0 || record.invocationId.length > 256)) throw new Error("CONTAINMENT_RUN_INVALID");
  if (record.sessionId !== undefined && (typeof record.sessionId !== "string" || record.sessionId.length === 0 || record.sessionId.length > 256)) throw new Error("CONTAINMENT_RUN_INVALID");
  if (record.profileDigest !== undefined && (typeof record.profileDigest !== "string" || !DIGEST.test(record.profileDigest))) throw new Error("CONTAINMENT_RUN_INVALID");
  if (record.result.telemetry !== undefined && !isValidContainmentTelemetry(record.result.telemetry)) throw new Error("CONTAINMENT_RUN_INVALID");
}

function assertIntegrity(integrity: unknown): asserts integrity is ContainmentRunIntegrity {
  if (integrity === null || typeof integrity !== "object") throw new Error("CONTAINMENT_RUN_INTEGRITY_MISSING");
  const value = integrity as Partial<ContainmentRunIntegrity>;
  if (value.algorithm !== "Ed25519" || typeof value.keyId !== "string" || value.keyId.length === 0 || typeof value.publicKeyPem !== "string" || !value.publicKeyPem.includes("PUBLIC KEY") || typeof value.recordDigest !== "string" || !DIGEST.test(value.recordDigest) || typeof value.signature !== "string" || value.signature.length === 0) throw new Error("CONTAINMENT_RUN_INTEGRITY_INVALID");
}

export function signContainmentRun(record: UnsignedContainmentRunRecord, signing: SigningMaterial): ContainmentRunRecord {
  const normalized = { ...record, result: signedResult(record.result) };
  assertUnsigned(normalized);
  const recordDigest = digestJson(normalized);
  const signature = sign(null, Buffer.from(payload(normalized), "utf8"), signing.privateKeyPem).toString("base64url");
  return { ...normalized, integrity: { algorithm: "Ed25519", keyId: signing.signingKeyId, publicKeyPem: signing.publicKeyPem, recordDigest, signature } };
}

export function verifyContainmentRun(record: ContainmentRunRecord, trusted?: TrustedContainmentKeys | string): boolean {
  try {
    if (trusted === undefined && process.env.INVOCK_TEST_MODE !== "1") return false;
    assertUnsigned(unsigned(record));
    assertIntegrity(record.integrity);
    const publicKeyPem = typeof trusted === "string"
      ? trusted
      : trusted === undefined
        ? record.integrity.publicKeyPem
        : trusted.find(key => key.keyId === record.integrity.keyId)?.publicKeyPem;
    if (publicKeyPem === undefined || record.integrity.publicKeyPem !== publicKeyPem) return false;
    if (record.integrity.recordDigest !== digestJson(unsigned(record))) return false;
    return verify(null, Buffer.from(payload(unsigned(record)), "utf8"), publicKeyPem, Buffer.from(record.integrity.signature, "base64url"));
  } catch { return false; }
}

function stateExists(directory: string): boolean {
  return readdirSync(directory, { withFileTypes: true }).some(entry => entry.isFile() && entry.name.endsWith(".json"));
}

export async function persistContainmentRun(directoryInput: string, input: UnsignedContainmentRunRecord | ContainmentRunRecord): Promise<string> {
  const directory = resolve(directoryInput);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  try { chmodSync(directory, 0o700); } catch { /* best effort on non-POSIX filesystems */ }
  const material = signingMaterial(directory, stateExists(directory));
  const record = signContainmentRun(unsigned(input), material);
  const path = join(directory, `${record.runId}.json`);
  if (existsSync(path)) throw new Error("CONTAINMENT_RUN_ALREADY_EXISTS");
  const temporaryPath = join(directory, `.${basename(path)}.${process.pid}.${temporarySequence++}.tmp`);
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    try { chmodSync(temporaryPath, 0o600); } catch { /* best effort on non-POSIX filesystems */ }
    renameSync(temporaryPath, path);
  } catch (error) {
    try { if (existsSync(temporaryPath)) unlinkSync(temporaryPath); } catch { /* preserve original failure */ }
    throw error;
  }
  return path;
}

export async function readContainmentRun(directoryInput: string, runId: string): Promise<ContainmentRunRecord> {
  const directory = resolve(directoryInput);
  if (typeof runId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(runId)) throw new Error("CONTAINMENT_RUN_INVALID");
  const path = join(directory, `${runId}.json`);
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (value === null || typeof value !== "object") throw new Error("CONTAINMENT_RUN_INVALID");
  const record = value as Partial<ContainmentRunRecord>;
  assertUnsigned(record as UnsignedContainmentRunRecord);
  assertIntegrity(record.integrity);
  const paths = keyPaths(directory);
  if (![paths.privatePath, paths.publicPath, paths.keyIdPath].every(item => existsSync(item))) throw new Error("CONTAINMENT_SIGNING_KEY_MISSING");
  const publicKeyPem = readFileSync(paths.publicPath, "utf8");
  const keyId = readFileSync(paths.keyIdPath, "utf8").trim();
  if (record.integrity.keyId !== keyId || record.integrity.publicKeyPem !== publicKeyPem || !verifyContainmentRun(record as ContainmentRunRecord, publicKeyPem)) throw new Error("CONTAINMENT_RUN_INTEGRITY_INVALID");
  return record as ContainmentRunRecord;
}
