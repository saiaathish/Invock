import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { gzipSync, deflateSync, brotliCompressSync } from "node:zlib";
import test from "node:test";
import { fingerprintSensitiveValue, matchSensitiveValue } from "../src/core/lineage.js";
import type { StoredFingerprint } from "../src/core/lineage.js";

const secret = "bounded-secret-value-9f2c";
const key = Buffer.alloc(32, 7);

for (const [name, encoded] of [["hex", Buffer.from(secret, "utf8").toString("hex")], ["gzip", gzipSync(secret)], ["deflate", deflateSync(secret)], ["brotli", brotliCompressSync(secret)]] as const) {
  test(`lineage detects bounded ${name} transformation`, () => {
    const fingerprints = fingerprintSensitiveValue(secret, key).map((fingerprint): StoredFingerprint => ({ ...fingerprint, taintRecordId: "taint-1", sourceInvocationId: "inv-1", labels: ["secret"] }));
    const matches = matchSensitiveValue(encoded, key, fingerprints);
    assert.equal(matches.length, 1);
    assert.ok(matches[0]?.matchKinds.includes(name));
  });
}

for (const [name, encoded] of [
  ["sha256", createHash("sha256").update(secret).digest("hex")],
  ["sha1", createHash("sha1").update(secret).digest("hex")],
  ["md5", createHash("md5").update(secret).digest("hex")],
  ["hmac_sha256", createHmac("sha256", "invock-crypto-detect-v1").update(secret).digest("hex")],
  ["reversed", [...secret].reverse().join("")],
  ["rot13", secret.replace(/[a-zA-Z]/g, character => { const code = character.charCodeAt(0); const base = code >= 97 ? 97 : 65; return String.fromCharCode(((code - base + 13) % 26) + base); })],
] as const) {
  test(`lineage detects bounded ${name} transformation`, () => {
    const fingerprints = fingerprintSensitiveValue(secret, key).map((fingerprint): StoredFingerprint => ({ ...fingerprint, taintRecordId: "taint-crypto", sourceInvocationId: "inv-crypto", labels: ["secret"] }));
    const matches = matchSensitiveValue(encoded, key, fingerprints);
    assert.equal(matches.length, 1);
    assert.ok(matches[0]?.matchKinds.includes(name));
  });
}

test("lineage remains bounded for oversized compressed input", () => {
  const fingerprints = fingerprintSensitiveValue(secret, key).map((fingerprint): StoredFingerprint => ({ ...fingerprint, taintRecordId: "taint-1", sourceInvocationId: "inv-1", labels: ["secret"] }));
  assert.doesNotThrow(() => matchSensitiveValue(gzipSync("x".repeat(100_000)), key, fingerprints));
});
