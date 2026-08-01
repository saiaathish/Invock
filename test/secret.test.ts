import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, createHmac } from "node:crypto";
import { detectParaphrase, detectParaphraseBatch } from "../src/analysis/secret.js";
import { detectCryptoTransformation, detectCryptoTransformationBatch } from "../src/analysis/crypto.js";
import type { ParaphraseKind } from "../src/analysis/secret.js";

const SECRET = "s3cr3t-api-key-9f2c";
const UNRELATED = "totally-unrelated-value-xyz";

function rot13(value: string): string {
  return value.replace(/[a-zA-Z]/g, ch => {
    const code = ch.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function reversed(value: string): string {
  return value.split("").reverse().join("");
}

function charShift(value: string, shift: number): string {
  return value.split("").map(ch => String.fromCharCode(ch.charCodeAt(0) + shift)).join("");
}

test("detectParaphrase: exact match", () => {
  const match = detectParaphrase(SECRET, SECRET);
  assert.equal(match.kind, "exact");
  assert.equal(match.confidence, 1.0);
});

test("detectParaphrase: case-insensitive match", () => {
  const match = detectParaphrase(SECRET, "S3CR3T-API-KEY-9F2C");
  assert.equal(match.kind, "case_insensitive");
  assert.equal(match.confidence, 0.95);
});

test("detectParaphrase: whitespace-normalized match", () => {
  const match = detectParaphrase(SECRET, "s3cr3t api key 9f2c");
  assert.equal(match.kind, "whitespace_normalized");
  assert.equal(match.confidence, 0.9);
});

test("detectParaphrase: token-reordered match", () => {
  const match = detectParaphrase(SECRET, "9f2c key api s3cr3t");
  assert.equal(match.kind, "token_reordered");
  assert.equal(match.confidence, 0.85);
});

test("detectParaphrase: reversed match", () => {
  const match = detectParaphrase(SECRET, reversed(SECRET));
  assert.equal(match.kind, "reversed");
  assert.equal(match.confidence, 0.9);
});

test("detectParaphrase: ROT13 match", () => {
  const match = detectParaphrase(SECRET, rot13(SECRET));
  assert.equal(match.kind, "rot13");
  assert.equal(match.confidence, 0.9);
});

test("detectParaphrase: character-shift match", () => {
  const match = detectParaphrase(SECRET, charShift(SECRET, 1));
  assert.equal(match.kind, "char_shift");
  assert.equal(match.confidence, 0.8);
});

test("detectParaphrase: substring match", () => {
  const match = detectParaphrase(SECRET, `prefix-${SECRET.slice(7)}-suffix`);
  assert.equal(match.kind, "substring");
  assert.equal(match.confidence, 0.7);
});

test("detectParaphrase: edit-distance near-miss", () => {
  // Single substitution that breaks all significant substrings.
  const nearMiss = "s3cr3t-aXi-key-9f2c";
  const match = detectParaphrase(SECRET, nearMiss);
  assert.equal(match.kind, "edit_distance");
  assert.ok(match.confidence > 0.7 && match.confidence < 1.0);
});

test("detectParaphrase: unrelated candidate is none", () => {
  const match = detectParaphrase(SECRET, UNRELATED);
  assert.equal(match.kind, "none");
  assert.equal(match.confidence, 0);
});

test("detectParaphrase: confidence ordering", () => {
  const cases: Array<[string, ParaphraseKind, number]> = [
    [SECRET, "exact", 1.0],
    ["S3CR3T-API-KEY-9F2C", "case_insensitive", 0.95],
    ["s3cr3t api key 9f2c", "whitespace_normalized", 0.9],
    ["9f2c key api s3cr3t", "token_reordered", 0.85],
    [reversed(SECRET), "reversed", 0.9],
    [rot13(SECRET), "rot13", 0.9],
    [charShift(SECRET, 1), "char_shift", 0.8],
    [`prefix-${SECRET.slice(7)}-suffix`, "substring", 0.7],
  ];
  for (const [candidate, kind, confidence] of cases) {
    const match = detectParaphrase(SECRET, candidate);
    assert.equal(match.kind, kind, `expected ${kind} for ${candidate}`);
    assert.equal(match.confidence, confidence, `expected confidence ${confidence} for ${candidate}`);
  }
  // Priority: a candidate that is both exact and would match other checks returns "exact".
  const exact = detectParaphrase(SECRET, SECRET);
  assert.equal(exact.kind, "exact");
  assert.equal(exact.confidence, 1.0);
});

test("detectParaphrase: bounded on oversized input, never throws", () => {
  const big = "x".repeat(17 * 1024); // > 16 KiB
  const match = detectParaphrase(SECRET, big);
  assert.equal(match.kind, "none");
  assert.equal(match.confidence, 0);
  const match2 = detectParaphrase(big, SECRET);
  assert.equal(match2.kind, "none");
  assert.equal(match2.confidence, 0);
});

test("detectParaphraseBatch: returns per-candidate results", () => {
  const results = detectParaphraseBatch(SECRET, [SECRET, UNRELATED]);
  assert.equal(results.length, 2);
  assert.equal(results[0]?.candidate, SECRET);
  assert.equal(results[0]?.match.kind, "exact");
  assert.equal(results[1]?.candidate, UNRELATED);
  assert.equal(results[1]?.match.kind, "none");
});

test("detectCryptoTransformation: hex", () => {
  const match = detectCryptoTransformation(SECRET, Buffer.from(SECRET, "utf8").toString("hex"));
  assert.equal(match.kind, "hex");
  assert.equal(match.confidence, 0.95);
});

test("detectCryptoTransformation: base64", () => {
  const match = detectCryptoTransformation(SECRET, Buffer.from(SECRET, "utf8").toString("base64"));
  assert.equal(match.kind, "base64");
  assert.equal(match.confidence, 0.95);
});

test("detectCryptoTransformation: base64url", () => {
  const match = detectCryptoTransformation(SECRET, Buffer.from(SECRET, "utf8").toString("base64url"));
  assert.equal(match.kind, "base64url");
  assert.equal(match.confidence, 0.95);
});

test("detectCryptoTransformation: url_encoded", () => {
  const match = detectCryptoTransformation(SECRET, encodeURIComponent(SECRET));
  assert.equal(match.kind, "url_encoded");
  assert.equal(match.confidence, 0.9);
});

test("detectCryptoTransformation: reversed", () => {
  const match = detectCryptoTransformation(SECRET, reversed(SECRET));
  assert.equal(match.kind, "reversed");
  assert.equal(match.confidence, 0.9);
});

test("detectCryptoTransformation: rot13", () => {
  const match = detectCryptoTransformation(SECRET, rot13(SECRET));
  assert.equal(match.kind, "rot13");
  assert.equal(match.confidence, 0.9);
});

test("detectCryptoTransformation: sha256", () => {
  const digest = createHash("sha256").update(SECRET, "utf8").digest("hex");
  const match = detectCryptoTransformation(SECRET, digest);
  assert.equal(match.kind, "sha256");
  assert.equal(match.confidence, 0.9);
});

test("detectCryptoTransformation: sha1", () => {
  const digest = createHash("sha1").update(SECRET, "utf8").digest("hex");
  const match = detectCryptoTransformation(SECRET, digest);
  assert.equal(match.kind, "sha1");
  assert.equal(match.confidence, 0.85);
});

test("detectCryptoTransformation: md5", () => {
  const digest = createHash("md5").update(SECRET, "utf8").digest("hex");
  const match = detectCryptoTransformation(SECRET, digest);
  assert.equal(match.kind, "md5");
  assert.equal(match.confidence, 0.8);
});

test("detectCryptoTransformation: hmac_sha256", () => {
  const digest = createHmac("sha256", "invock-crypto-detect-v1").update(SECRET, "utf8").digest("hex");
  const match = detectCryptoTransformation(SECRET, digest);
  assert.equal(match.kind, "hmac_sha256");
  assert.equal(match.confidence, 0.85);
});

test("detectCryptoTransformation: unrelated candidate is none", () => {
  const match = detectCryptoTransformation(SECRET, UNRELATED);
  assert.equal(match.kind, "none");
  assert.equal(match.confidence, 0);
});

test("detectCryptoTransformation: bounded on oversized input, never throws", () => {
  const big = "x".repeat(17 * 1024); // > 16 KiB
  const match = detectCryptoTransformation(SECRET, big);
  assert.equal(match.kind, "none");
  assert.equal(match.confidence, 0);
  const match2 = detectCryptoTransformation(big, SECRET);
  assert.equal(match2.kind, "none");
  assert.equal(match2.confidence, 0);
});

test("detectCryptoTransformationBatch: returns per-candidate results", () => {
  const hex = Buffer.from(SECRET, "utf8").toString("hex");
  const results = detectCryptoTransformationBatch(SECRET, [hex, UNRELATED]);
  assert.equal(results.length, 2);
  assert.equal(results[0]?.candidate, hex);
  assert.equal(results[0]?.match.kind, "hex");
  assert.equal(results[1]?.candidate, UNRELATED);
  assert.equal(results[1]?.match.kind, "none");
});
