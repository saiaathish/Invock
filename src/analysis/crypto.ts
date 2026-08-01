/**
 * Cryptographic / encoding transformation detection for known secrets.
 *
 * Detects whether a candidate string is a known cryptographic or encoding
 * transformation of a known secret (hash, HMAC, hex, base64, base64url,
 * URL-encoded, reversed, ROT13). Pure, deterministic, and bounded: inputs
 * over a size limit are rejected with a "none" match (never throws).
 */

import { createHash, createHmac } from "node:crypto";

export type CryptoTransformKind =
  | "sha256"
  | "sha1"
  | "md5"
  | "hmac_sha256"
  | "hex"
  | "base64"
  | "base64url"
  | "url_encoded"
  | "reversed"
  | "rot13"
  | "none";

export interface CryptoMatch {
  kind: CryptoTransformKind;
  confidence: number;
}

const MAX_INPUT_BYTES = 16 * 1024; // 16 KiB
const HMAC_DOMAIN_KEY = "invock-crypto-detect-v1";

function none(): CryptoMatch {
  return { kind: "none", confidence: 0 };
}

function overLimit(secret: string, candidate: string): boolean {
  return Buffer.byteLength(secret, "utf8") > MAX_INPUT_BYTES || Buffer.byteLength(candidate, "utf8") > MAX_INPUT_BYTES;
}

function hexOf(value: string): string {
  return Buffer.from(value, "utf8").toString("hex");
}

function base64Of(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function base64urlOf(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function urlEncodedOf(value: string): string {
  return encodeURIComponent(value);
}

function reversed(value: string): string {
  return value.split("").reverse().join("");
}

function rot13(value: string): string {
  return value.replace(/[a-zA-Z]/g, ch => {
    const code = ch.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function hashHex(algorithm: string, value: string): string {
  return createHash(algorithm).update(value, "utf8").digest("hex");
}

function hmacSha256Hex(key: string, value: string): string {
  return createHmac("sha256", key).update(value, "utf8").digest("hex");
}

/**
 * Detects whether `candidate` is a known cryptographic or encoding
 * transformation of `secret`. Returns the strongest matching transformation
 * kind with a confidence in [0, 1]. Never throws; oversized inputs yield
 * "none" / 0.
 */
export function detectCryptoTransformation(secret: string, candidate: string): CryptoMatch {
  if (overLimit(secret, candidate)) return none();

  if (candidate === hexOf(secret)) return { kind: "hex", confidence: 0.95 };
  if (candidate === base64Of(secret)) return { kind: "base64", confidence: 0.95 };
  if (candidate === base64urlOf(secret)) return { kind: "base64url", confidence: 0.95 };
  if (candidate === urlEncodedOf(secret)) return { kind: "url_encoded", confidence: 0.9 };
  if (candidate === reversed(secret)) return { kind: "reversed", confidence: 0.9 };
  if (candidate === rot13(secret)) return { kind: "rot13", confidence: 0.9 };
  if (candidate === hashHex("sha256", secret)) return { kind: "sha256", confidence: 0.9 };
  if (candidate === hashHex("sha1", secret)) return { kind: "sha1", confidence: 0.85 };
  if (candidate === hashHex("md5", secret)) return { kind: "md5", confidence: 0.8 };
  if (candidate === hmacSha256Hex(HMAC_DOMAIN_KEY, secret)) return { kind: "hmac_sha256", confidence: 0.85 };
  return none();
}

/** Convenience batch wrapper over {@link detectCryptoTransformation}. */
export function detectCryptoTransformationBatch(secret: string, candidates: string[]): Array<{ candidate: string; match: CryptoMatch }> {
  return candidates.map(candidate => ({ candidate, match: detectCryptoTransformation(secret, candidate) }));
}
