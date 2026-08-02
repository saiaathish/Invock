import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import {
  type LegacyFindingCategory,
  type LegacyFindingSeverity,
  type LegacyArtifactFormat,
} from "./types.js";

export interface DetectionResult {
  categories: LegacyFindingCategory[];
  severity: LegacyFindingSeverity;
  matchCount: number;
}

// Helper to estimate entropy of a string (for high-entropy secret detection)
function calculateEntropy(str: string): number {
  const freqs: Record<string, number | undefined> = {};
  for (const char of str) {
    freqs[char] = (freqs[char] ?? 0) + 1;
  }
  let entropy = 0;
  for (const char in freqs) {
    const val = freqs[char];
    if (val !== undefined) {
      const p = val / str.length;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

// 2.5 Deterministic Local Detectors
export function scanTextContent(text: string): DetectionResult {
  const categories = new Set<LegacyFindingCategory>();
  let matchCount = 0;
  let severity: LegacyFindingSeverity = "LOW";

  // Secret headers/prefixes
  const secretPatterns = [
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----/i,
    /bearer\s+[A-Za-z0-9_\-\.\~]+/i,
    /(password|secret|token|api_key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-\.\~]+["']/i,
    /(AIzaSy[A-Za-z0-9_\-]{33})/i, // Google API key
    /sk-[a-zA-Z0-9]{32,}/i, // OpenAI API key
  ];

  for (const pattern of secretPatterns) {
    const matches = text.match(pattern);
    if (matches) {
      categories.add("SECRET");
      categories.add("CREDENTIAL");
      matchCount += matches.length;
      severity = "CRITICAL";
    }
  }

  // PII patterns
  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const phonePattern = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
  const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/g;

  const emailMatches = text.match(emailPattern);
  if (emailMatches) {
    categories.add("PERSONAL_DATA");
    matchCount += emailMatches.length;
    severity = severity === "CRITICAL" ? "CRITICAL" : "HIGH";
  }

  const phoneMatches = text.match(phonePattern);
  if (phoneMatches) {
    categories.add("PERSONAL_DATA");
    matchCount += phoneMatches.length;
    severity = severity === "CRITICAL" ? "CRITICAL" : "HIGH";
  }

  const ssnMatches = text.match(ssnPattern);
  if (ssnMatches) {
    categories.add("PERSONAL_DATA");
    matchCount += ssnMatches.length;
    severity = "CRITICAL";
  }

  // Conversation Indicators
  const convoPatterns = [
    /role\s*[:=]\s*["'](user|assistant|system)["']/i,
    /prompt\s*[:=]/i,
    /response\s*[:=]/i,
    /tool_call/i,
    /tool_result/i,
  ];

  for (const pattern of convoPatterns) {
    const matches = text.match(pattern);
    if (matches) {
      categories.add("AGENT_CONVERSATION");
      categories.add("PROMPT_HISTORY");
      matchCount += matches.length;
      if (severity !== "CRITICAL" && severity !== "HIGH") {
        severity = "MEDIUM";
      }
    }
  }

  // Logs / Traces
  if (text.includes("[DEBUG]") || text.includes("[TRACE]") || text.includes("[INFO]")) {
    categories.add("CONTENT_BEARING_LOG");
    if (severity !== "CRITICAL" && severity !== "HIGH") {
      severity = "LOW";
    }
  }

  // High entropy token detection
  const words = text.split(/\s+/);
  for (const word of words) {
    if (word.length >= 32 && word.length <= 128 && /^[a-zA-Z0-9/+=_-]+$/.test(word)) {
      const entropy = calculateEntropy(word);
      if (entropy > 4.5) {
        categories.add("SECRET");
        matchCount++;
        severity = "CRITICAL";
      }
    }
  }

  return {
    categories: Array.from(categories),
    severity,
    matchCount,
  };
}

// 2.7 SQLite scanning
export function scanSQLiteDatabase(dbPath: string): DetectionResult {
  const categories = new Set<LegacyFindingCategory>();
  let matchCount = 0;
  let severity: LegacyFindingSeverity = "LOW";

  let db: DatabaseSync | null = null;
  try {
    // Open SQLite database read-only
    db = new DatabaseSync(dbPath, { open: true });
    // Inspect table and column names
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>;
    for (const table of tables) {
      const tableName = table.name.toLowerCase();
      if (tableName.includes("history") || tableName.includes("message") || tableName.includes("convo") || tableName.includes("session")) {
        categories.add("CONTENT_BEARING_DATABASE");
        categories.add("AGENT_CONVERSATION");
        severity = "HIGH";
        matchCount++;
      }

      // Check schema column names
      const info = db.prepare(`PRAGMA table_info(${table.name})`).all() as Array<{ name: string }>;
      for (const col of info) {
        const colName = col.name.toLowerCase();
        if (colName.includes("secret") || colName.includes("token") || colName.includes("password") || colName.includes("key")) {
          categories.add("SECRET");
          severity = "CRITICAL";
          matchCount++;
        }
        if (colName.includes("prompt") || colName.includes("response") || colName.includes("content")) {
          categories.add("PROMPT_HISTORY");
          severity = "HIGH";
          matchCount++;
        }
      }

      // Sample a few rows from text columns safely without copying or arbitrary query execution
      try {
        const textCols = info.map(c => c.name);
        if (textCols.length > 0) {
          const sampleQuery = `SELECT * FROM ${table.name} LIMIT 5`;
          const rows = db.prepare(sampleQuery).all() as Array<Record<string, unknown>>;
          for (const row of rows) {
            for (const col of textCols) {
              const val = row[col];
              if (typeof val === "string") {
                const subRes = scanTextContent(val);
                for (const cat of subRes.categories) {
                  categories.add(cat);
                }
                matchCount += subRes.matchCount;
                if (subRes.severity === "CRITICAL") severity = "CRITICAL";
                else if (subRes.severity === "HIGH" && severity !== "CRITICAL") severity = "HIGH";
                else if (subRes.severity === "MEDIUM" && severity !== "CRITICAL" && severity !== "HIGH") severity = "MEDIUM";
              }
            }
          }
        }
      } catch {
        // Safe skip on sampling failure
      }
    }
  } catch {
    // Database could be locked or invalid SQLite
  } finally {
    if (db) {
      try {
        db.close();
      } catch {
        // Safe ignore
      }
    }
  }

  return {
    categories: Array.from(categories),
    severity,
    matchCount,
  };
}
