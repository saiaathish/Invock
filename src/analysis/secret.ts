/**
 * Semantic paraphrase detection for known secrets.
 *
 * Detects whether a candidate string is a paraphrased or lightly transformed
 * version of a known secret. Pure, deterministic, and bounded: inputs over a
 * size limit are rejected with a "none" match (never throws).
 */

export type ParaphraseKind =
  | "exact"
  | "case_insensitive"
  | "whitespace_normalized"
  | "token_reordered"
  | "reversed"
  | "rot13"
  | "char_shift"
  | "substring"
  | "edit_distance"
  | "none";

export interface ParaphraseMatch {
  kind: ParaphraseKind;
  confidence: number;
}

const MAX_INPUT_BYTES = 16 * 1024; // 16 KiB
const MAX_EDIT_DISTANCE_DIMENSION = 512;
const MIN_SUBSTRING_LENGTH = 8;
const SUBSTRING_FRACTION = 0.6;
const MAX_EDIT_DISTANCE_NORMALIZED = 0.2;

function none(): ParaphraseMatch {
  return { kind: "none", confidence: 0 };
}

function overLimit(secret: string, candidate: string): boolean {
  return Buffer.byteLength(secret, "utf8") > MAX_INPUT_BYTES || Buffer.byteLength(candidate, "utf8") > MAX_INPUT_BYTES;
}

function stripNonAlphanumeric(value: string): string {
  return value.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

function tokens(value: string): string[] {
  return value.split(/[^a-zA-Z0-9]+/).filter(token => token.length > 0);
}

function sortedTokensKey(value: string): string {
  return tokens(value).map(token => token.toLowerCase()).sort().join(" ");
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

function charShift(value: string, shift: number): string {
  return value.split("").map(ch => String.fromCharCode(ch.charCodeAt(0) + shift)).join("");
}

function containsSignificantSubstring(needleSource: string, haystack: string, minLength: number): boolean {
  if (needleSource.length < minLength) return false;
  const windows = new Set<string>();
  for (let i = 0; i + minLength <= needleSource.length; i++) windows.add(needleSource.slice(i, i + minLength));
  for (let i = 0; i + minLength <= haystack.length; i++) if (windows.has(haystack.slice(i, i + minLength))) return true;
  return false;
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    const curr = new Array<number>(n + 1);
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min((prev[j] ?? n) + 1, (curr[j - 1] ?? n) + 1, (prev[j - 1] ?? n) + cost);
    }
    prev = curr;
  }
  return prev[n] ?? n;
}

/**
 * Detects whether `candidate` is a paraphrased or lightly transformed version
 * of `secret`. Returns the strongest matching transformation kind with a
 * confidence in [0, 1]. Never throws; oversized inputs yield "none" / 0.
 */
export function detectParaphrase(secret: string, candidate: string): ParaphraseMatch {
  if (overLimit(secret, candidate)) return none();

  if (secret === candidate) return { kind: "exact", confidence: 1.0 };
  if (secret.toLowerCase() === candidate.toLowerCase()) return { kind: "case_insensitive", confidence: 0.95 };
  if (stripNonAlphanumeric(secret) === stripNonAlphanumeric(candidate)) return { kind: "whitespace_normalized", confidence: 0.9 };
  if (sortedTokensKey(secret) === sortedTokensKey(candidate)) return { kind: "token_reordered", confidence: 0.85 };
  if (reversed(secret) === candidate) return { kind: "reversed", confidence: 0.9 };
  if (rot13(secret) === candidate) return { kind: "rot13", confidence: 0.9 };
  for (let shift = -5; shift <= 5; shift++) {
    if (shift === 0) continue;
    if (charShift(secret, shift) === candidate) return { kind: "char_shift", confidence: 0.8 };
  }
  const shorter = Math.min(secret.length, candidate.length);
  const minSubstring = Math.max(MIN_SUBSTRING_LENGTH, Math.floor(SUBSTRING_FRACTION * shorter));
  if (containsSignificantSubstring(secret, candidate, minSubstring) || containsSignificantSubstring(candidate, secret, minSubstring)) {
    return { kind: "substring", confidence: 0.7 };
  }
  if (secret.length <= MAX_EDIT_DISTANCE_DIMENSION && candidate.length <= MAX_EDIT_DISTANCE_DIMENSION) {
    const distance = levenshtein(secret, candidate);
    const normalized = distance / Math.max(secret.length, candidate.length, 1);
    if (normalized <= MAX_EDIT_DISTANCE_NORMALIZED) return { kind: "edit_distance", confidence: 1 - normalized };
  }
  return none();
}

/** Convenience batch wrapper over {@link detectParaphrase}. */
export function detectParaphraseBatch(secret: string, candidates: string[]): Array<{ candidate: string; match: ParaphraseMatch }> {
  return candidates.map(candidate => ({ candidate, match: detectParaphrase(secret, candidate) }));
}
