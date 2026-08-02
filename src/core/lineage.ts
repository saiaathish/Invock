import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { brotliCompressSync, brotliDecompressSync, deflateSync, gunzipSync, gzipSync, inflateSync } from "node:zlib";
import { digestJson, newId } from "./canonical.js";
import type { DataLabel, LineageReference } from "./types.js";

export type FingerprintKind = "exact" | "base64" | "base64url" | "urlencoded" | "hex" | "gzip" | "deflate" | "brotli" | "sha256" | "sha1" | "md5" | "hmac_sha256" | "reversed" | "rot13";
export interface NewFingerprint { fingerprintId: string; kind: FingerprintKind; digest: Buffer; sourceLength: number; }
export interface StoredFingerprint extends NewFingerprint { taintRecordId: string; sourceInvocationId: string; labels: DataLabel[]; expiresAt?: string; }
export interface DetachedFingerprintProof { fingerprintId: string; kind: FingerprintKind; digest: string; sourceLength: number; }

const MIN_SECRET_BYTES = 8;
const MAX_VALUE_BYTES = 4096;

function hmac(key: Buffer, kind: FingerprintKind, value: Buffer): Buffer {
  return createHmac("sha256", key)
    .update("invock-taint-v1\0", "utf8").update(kind, "utf8").update("\0", "utf8").update(value).digest();
}

function meaningful(value: Buffer): boolean {
  if (value.byteLength < MIN_SECRET_BYTES || value.byteLength > MAX_VALUE_BYTES) return false;
  const distinct = new Set(value).size;
  return distinct >= 3;
}

const CRYPTO_HMAC_DOMAIN = "invock-crypto-detect-v1";

function rot13(value: string): string {
  return value.replace(/[a-zA-Z]/g, character => {
    const code = character.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function cryptographicVariants(value: Buffer): Array<{ kind: FingerprintKind; bytes: Buffer }> {
  const text = value.toString("utf8");
  return [
    { kind: "sha256", bytes: Buffer.from(createHash("sha256").update(value).digest("hex"), "utf8") },
    { kind: "sha1", bytes: Buffer.from(createHash("sha1").update(value).digest("hex"), "utf8") },
    { kind: "md5", bytes: Buffer.from(createHash("md5").update(value).digest("hex"), "utf8") },
    { kind: "hmac_sha256", bytes: Buffer.from(createHmac("sha256", CRYPTO_HMAC_DOMAIN).update(value).digest("hex"), "utf8") },
    { kind: "reversed", bytes: Buffer.from([...text].reverse().join(""), "utf8") },
    { kind: "rot13", bytes: Buffer.from(rot13(text), "utf8") },
  ];
}

function variants(value: Buffer): Array<{ kind: FingerprintKind; bytes: Buffer }> {
  const text = value.toString("utf8");
  const base64 = value.toString("base64");
  const base64url = value.toString("base64url");
  const direct: Array<{ kind: FingerprintKind; bytes: Buffer }> = [
    { kind: "exact", bytes: value },
    { kind: "base64", bytes: Buffer.from(base64, "utf8") },
    { kind: "base64", bytes: Buffer.from(base64.replace(/=+$/u, ""), "utf8") },
    { kind: "base64url", bytes: Buffer.from(base64url, "utf8") },
    { kind: "base64url", bytes: Buffer.from(`${base64url}${"=".repeat((4 - base64url.length % 4) % 4)}`, "utf8") },
    { kind: "urlencoded", bytes: Buffer.from(encodeURIComponent(text), "utf8") },
    { kind: "hex", bytes: Buffer.from(value.toString("hex"), "utf8") },
  ];
  for (const [kind, encode] of [["gzip", gzipSync], ["deflate", deflateSync], ["brotli", brotliCompressSync]] as const) {
    try {
      const compressed = encode(value);
      if (compressed.byteLength <= MAX_VALUE_BYTES) direct.push({ kind, bytes: compressed });
    } catch { /* compression failure is not authority */ }
  }
  return [...direct, ...cryptographicVariants(value)];
}

/** Creates keyed records only; neither values nor unkeyed hashes are retained. */
export function fingerprintSensitiveValue(value: string | Buffer, key: Buffer): NewFingerprint[] {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
  if (!meaningful(bytes)) return [];
  const seen = new Set<string>();
  return variants(bytes).flatMap(variant => {
    if (variant.bytes.byteLength > MAX_VALUE_BYTES) return [];
    const digest = hmac(key, variant.kind, variant.bytes);
    const marker = `${variant.kind}:${digest.toString("base64url")}`;
    if (seen.has(marker)) return [];
    seen.add(marker);
    return [{ fingerprintId: newId("fp"), kind: variant.kind, digest, sourceLength: bytes.byteLength }];
  });
}

/** Binds exported fingerprint metadata without exposing the source value or HMAC key. */
export function fingerprintProofDigest(fingerprints: readonly (NewFingerprint | DetachedFingerprintProof)[]): string {
  return digestJson(fingerprints.map(fingerprint => ({
    fingerprintId: fingerprint.fingerprintId,
    kind: fingerprint.kind,
    digest: typeof fingerprint.digest === "string" ? fingerprint.digest : fingerprint.digest.toString("base64url"),
    sourceLength: fingerprint.sourceLength,
  })).sort((left, right) => left.fingerprintId.localeCompare(right.fingerprintId)));
}

function candidateForms(bytes: Buffer): Buffer[] {
  const forms = [bytes]; const text = bytes.toString("utf8");
  try { const decoded = Buffer.from(text, "base64"); if (decoded.length > 0 && decoded.toString("base64").replace(/=+$/u, "") === text.replace(/=+$/u, "")) forms.push(decoded); } catch { /* not Base64 */ }
  try { const decoded = Buffer.from(text, "base64url"); if (decoded.length > 0 && decoded.toString("base64url") === text) forms.push(decoded); } catch { /* not Base64URL */ }
  try { const decoded = decodeURIComponent(text); if (decoded !== text) forms.push(Buffer.from(decoded, "utf8")); } catch { /* not URL encoded */ }
  if (text.length >= 2 && text.length % 2 === 0 && /^[0-9a-f]+$/iu.test(text)) {
    try { forms.push(Buffer.from(text, "hex")); } catch { /* not hex */ }
  }
  try {
    const url = new URL(text);
    for (const value of url.searchParams.values()) forms.push(Buffer.from(value, "utf8"));
  } catch { /* not a URL */ }
  try {
    const collect = (value: unknown): void => {
      if (typeof value === "string") forms.push(Buffer.from(value, "utf8"));
      else if (Array.isArray(value)) value.forEach(collect);
      else if (value !== null && typeof value === "object") Object.values(value as Record<string, unknown>).forEach(collect);
    };
    collect(JSON.parse(text));
  } catch { /* not JSON text */ }
  for (const decode of [gunzipSync, inflateSync, brotliDecompressSync]) {
    try {
      const decoded = decode(bytes, { maxOutputLength: MAX_VALUE_BYTES });
      if (decoded.byteLength <= MAX_VALUE_BYTES) forms.push(decoded);
    } catch { /* not a supported bounded compression stream */ }
  }
  return forms;
}

export function matchSensitiveValue(value: string | Buffer, key: Buffer, candidates: readonly StoredFingerprint[]): LineageReference[] {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
  if (!meaningful(bytes)) return [];
  const probes = new Map<FingerprintKind, Buffer[]>();
  const sourceLengths = [...new Set(candidates.map(candidate => candidate.sourceLength))];
  for (const form of candidateForms(bytes)) {
    const forms = [form];
    for (const length of sourceLengths) if (length > 0 && form.byteLength > length) for (let start = 0; start <= form.byteLength - length; start++) forms.push(form.subarray(start, start + length));
    for (const probeValue of forms) for (const kind of ["exact", "base64", "base64url", "urlencoded", "hex", "gzip", "deflate", "brotli", "sha256", "sha1", "md5", "hmac_sha256", "reversed", "rot13"] as const) probes.set(kind, [...(probes.get(kind) ?? []), hmac(key, kind, probeValue)]);
  }
  const groups = new Map<string, { sourceInvocationId: string; labels: DataLabel[]; ids: string[]; kinds: LineageReference["matchKinds"]; fingerprints: StoredFingerprint[]; expiresAt?: string }>();
  for (const candidate of candidates) {
    const matched = (probes.get(candidate.kind) ?? []).some(probe => probe.length === candidate.digest.length && timingSafeEqual(probe, candidate.digest));
    if (!matched) continue;
    const group = groups.get(candidate.taintRecordId) ?? { sourceInvocationId: candidate.sourceInvocationId, labels: candidate.labels, ids: [], kinds: [], fingerprints: candidates.filter(item => item.taintRecordId === candidate.taintRecordId), ...(candidate.expiresAt ? { expiresAt: candidate.expiresAt } : {}) };
    group.ids.push(candidate.fingerprintId); group.kinds.push(candidate.kind); groups.set(candidate.taintRecordId, group);
  }
  return [...groups.entries()].map(([taintRecordId, group]) => ({ sourceInvocationId: group.sourceInvocationId, labels: group.labels, matchedFingerprintIds: [...new Set(group.ids)].sort(), matchKinds: [...new Set(group.kinds)].sort() as LineageReference["matchKinds"], taintRecordId, fingerprintProofDigest: fingerprintProofDigest(group.fingerprints), ...(group.expiresAt ? { expiresAt: group.expiresAt } : {}) }));
}

export function generateTaintKey(): Buffer { return randomBytes(32); }
