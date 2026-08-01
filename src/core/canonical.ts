import { createHash, randomUUID, timingSafeEqual } from "node:crypto";

/** A deliberately small, deterministic JSON canonicalizer for security objects. */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Canonical JSON cannot contain non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonicalize(object[key])}`).join(",")}}`;
  }
  throw new Error(`Unsupported canonical value: ${typeof value}`);
}

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function digestJson(value: unknown): string {
  return sha256(canonicalize(value));
}

export function stableUnique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll("-", "")}`;
}

export function sameDigest(left: string, right: string): boolean {
  const a = Buffer.from(left, "base64url");
  const b = Buffer.from(right, "base64url");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function asRecord(value: unknown, name = "value"): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}