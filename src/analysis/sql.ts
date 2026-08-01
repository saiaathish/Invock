import type { SqlAnalysis, SqlDialect, SqlStatementAnalysis, SqlStatementKind } from "./types.js";

/** Maximum input size accepted by the analyzer (1 MiB). Larger inputs are flagged. */
export const MAX_SQL_LENGTH = 1024 * 1024;

type SqlTokenType = "word" | "string" | "number" | "op" | "param";

interface SqlToken {
  type: SqlTokenType;
  value: string;
  depth: number;
}

interface TokenizedStatement {
  tokens: SqlToken[];
  hasComment: boolean;
  malformed: boolean;
}

interface InternalStatement extends SqlStatementAnalysis {
  dangerous: Array<{ code: string; message: string }>;
  riskSignals: string[];
}

const KIND_WORDS: Record<string, SqlStatementKind> = {
  select: "select",
  insert: "insert",
  update: "update",
  delete: "delete",
  create: "create",
  alter: "alter",
  drop: "drop",
  truncate: "truncate",
  grant: "grant",
  revoke: "revoke",
  attach: "attach",
  pragma: "pragma",
  vacuum: "vacuum",
  copy: "copy",
  merge: "merge",
};

const JOIN_AND_FROM_MODIFIERS = new Set([
  "inner", "left", "right", "full", "outer", "cross", "natural", "straight_join", "lateral", "only",
]);

const SKIP_IF_NOT_EXISTS = new Set(["if", "not", "exists", "temporary", "temp"]);
const SKIP_DROP_OBJECT = new Set(["table", "index", "view", "trigger", "materialized", "if", "not", "exists", "temporary", "temp"]);
const SKIP_TRUNCATE_OBJECT = new Set(["table", "if", "not", "exists"]);

/** PRAGMA names that mutate database state rather than merely reading it. */
const WRITE_PRAGMAS = new Set([
  "journal_mode", "wal_checkpoint", "user_version", "foreign_keys", "synchronous",
  "secure_delete", "auto_vacuum", "journal_size_limit", "wal_autocheckpoint",
  "page_size", "cache_size", "locking_mode",
]);

const SENSITIVE_TABLE_RE = /(^|[^a-z0-9])(api[_-]?keys?|private[_-]?keys?|passwords?|credentials?|secrets?|tokens?|sessions?|users?|accounts?|wallets?|auths?|keys?)([^a-z0-9]|$)/iu;

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function isWord(token: SqlToken | undefined, value: string): boolean {
  return token !== undefined && token.type === "word" && token.value.toLowerCase() === value;
}

/**
 * Hand-rolled, bounded SQL tokenizer. Produces one chunk per top-level statement
 * (semicolons inside strings, quoted identifiers, or comments never split).
 * Never throws: unterminated constructs consume to the end of input and mark the
 * chunk as malformed.
 */
function tokenizeSql(input: string): TokenizedStatement[] {
  const statements: TokenizedStatement[] = [];
  let tokens: SqlToken[] = [];
  let hasComment = false;
  let malformed = false;
  let depth = 0;
  const len = input.length;
  let i = 0;

  const flush = (): void => {
    if (tokens.length > 0 || hasComment) {
      statements.push({ tokens, hasComment, malformed });
    }
    tokens = [];
    hasComment = false;
    malformed = false;
  };

  while (i < len) {
    const c = input[i]!;
    const next = i + 1 < len ? input[i + 1] : undefined;

    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") {
      i++;
      continue;
    }

    // Line comment (-- ...)
    if (c === "-" && next === "-") {
      hasComment = true;
      while (i < len && input[i] !== "\n") i++;
      continue;
    }

    // Block comment (/* ... */)
    if (c === "/" && next === "*") {
      hasComment = true;
      i += 2;
      while (i < len && !(input[i] === "*" && input[i + 1] === "/")) i++;
      if (i < len) i += 2;
      else malformed = true;
      continue;
    }

    // String literal ('...' with '' escape)
    if (c === "'") {
      let value = "";
      i++;
      let closed = false;
      while (i < len) {
        if (input[i] === "'" && input[i + 1] === "'") {
          value += "'";
          i += 2;
          continue;
        }
        if (input[i] === "'") {
          i++;
          closed = true;
          break;
        }
        value += input[i];
        i++;
      }
      if (!closed) malformed = true;
      tokens.push({ type: "string", value, depth });
      continue;
    }

    // Quoted identifiers ("..." and `...` with "" / `` escapes)
    if (c === '"' || c === "`") {
      const quote = c;
      let value = "";
      i++;
      let closed = false;
      while (i < len) {
        if (input[i] === quote && input[i + 1] === quote) {
          value += quote;
          i += 2;
          continue;
        }
        if (input[i] === quote) {
          i++;
          closed = true;
          break;
        }
        value += input[i];
        i++;
      }
      if (!closed) malformed = true;
      tokens.push({ type: "word", value, depth });
      continue;
    }

    // Bracket-quoted identifier ([...])
    if (c === "[") {
      let value = "";
      i++;
      let closed = false;
      while (i < len && input[i] !== "]") {
        value += input[i];
        i++;
      }
      if (i < len) {
        i++;
        closed = true;
      }
      if (!closed) malformed = true;
      tokens.push({ type: "word", value, depth });
      continue;
    }

    // Top-level statement separator
    if (c === ";" && depth === 0) {
      flush();
      i++;
      continue;
    }

    // Number literal (decimal, hex, dotted)
    if ((c >= "0" && c <= "9") || (c === "." && next !== undefined && next >= "0" && next <= "9")) {
      let value = "";
      while (i < len && /[0-9a-fA-FxX_.]/.test(input[i]!)) {
        value += input[i];
        i++;
      }
      tokens.push({ type: "number", value, depth });
      continue;
    }

    // Parameter tokens: ?, :name, $name, @name
    if (c === "?") {
      tokens.push({ type: "param", value: "?", depth });
      i++;
      continue;
    }
    if ((c === ":" || c === "@" || c === "$") && next !== undefined && /[a-zA-Z0-9_]/.test(next)) {
      let value = c;
      i++;
      while (i < len && /[a-zA-Z0-9_$]/.test(input[i]!)) {
        value += input[i];
        i++;
      }
      tokens.push({ type: "param", value, depth });
      continue;
    }

    // Unquoted identifier / keyword (schema-qualified names joined on '.')
    if (/[a-zA-Z_]/.test(c) || (c === "$" && next !== undefined && /[a-zA-Z0-9_]/.test(next))) {
      let value = "";
      while (i < len && /[a-zA-Z0-9_$]/.test(input[i]!)) {
        value += input[i];
        i++;
      }
      while (input[i] === "." && input[i + 1] !== undefined && /[a-zA-Z0-9_$]/.test(input[i + 1]!)) {
        value += ".";
        i++;
        while (i < len && /[a-zA-Z0-9_$]/.test(input[i]!)) {
          value += input[i];
          i++;
        }
      }
      tokens.push({ type: "word", value, depth });
      continue;
    }

    // Operator
    let op = c;
    i++;
    if (
      i < len &&
      ((c === "<" && (input[i] === "=" || input[i] === ">")) ||
        (c === ">" && input[i] === "=") ||
        (c === "!" && input[i] === "=") ||
        (c === "|" && input[i] === "|") ||
        (c === ":" && input[i] === ":") ||
        (c === "<" && input[i] === "<") ||
        (c === ">" && input[i] === ">"))
    ) {
      op += input[i];
      i++;
    }
    if (op === "(") depth++;
    else if (op === ")") {
      if (depth > 0) depth--;
      else malformed = true;
    }
    tokens.push({ type: "op", value: op, depth });
  }

  flush();
  return statements;
}

/** Best-effort next table-like token after `start` (skipping JOIN modifiers). */
function nextTable(tokens: SqlToken[], start: number, skipModifiers: boolean): { name: string; index: number } | undefined {
  let j = start;
  if (skipModifiers) {
    while (true) {
      const candidate = tokens[j];
      if (candidate === undefined || candidate.type !== "word" || !JOIN_AND_FROM_MODIFIERS.has(candidate.value.toLowerCase())) break;
      j++;
    }
  } else {
    const candidate = tokens[j];
    if (candidate !== undefined && candidate.type === "word" && JOIN_AND_FROM_MODIFIERS.has(candidate.value.toLowerCase())) j++;
  }
  const t = tokens[j];
  if (t === undefined || t.type !== "word") return undefined;
  return { name: t.value, index: j };
}

/**
 * Collect table names following FROM / JOIN / USING clauses.
 * `subqueryOnly` excludes top-level FROM (used where the first FROM is the
 * statement target rather than a source, e.g. DELETE ... FROM).
 */
function collectFromJoins(tokens: SqlToken[], subqueryOnly = false): string[] {
  const tables: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === undefined || t.type !== "word") continue;
    const low = t.value.toLowerCase();
    if (low !== "from" && low !== "join" && low !== "using") continue;
    if (subqueryOnly && t.depth === 0 && low === "from") continue;
    const first = nextTable(tokens, i + 1, low === "join");
    if (first === undefined) continue;
    tables.push(first.name);
    let j = first.index + 1;
    while (true) {
      const separator = tokens[j];
      if (separator === undefined || separator.type !== "op" || separator.value !== ",") break;
      const next = nextTable(tokens, j + 1, false);
      if (next === undefined) break;
      tables.push(next.name);
      j = next.index + 1;
    }
  }
  return dedupe(tables);
}

function extractTables(tokens: SqlToken[], kind: SqlStatementKind): { read: string[]; written: string[] } {
  const read: string[] = [];
  const written: string[] = [];

  const writes = (name: string): void => {
    written.push(name);
  };

  if (kind === "select") {
    for (const name of collectFromJoins(tokens)) read.push(name);
    // SELECT ... INTO new_table (MySQL/SQL Server)
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "into") && t.depth === 0) {
        const target = tokens[i + 1];
        if (target !== undefined && target.type === "word") writes(target.value);
        break;
      }
    }
  } else if (kind === "insert") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "into") && t.depth === 0) {
        const table = tokens[i + 1];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
    for (const name of collectFromJoins(tokens)) read.push(name);
  } else if (kind === "update") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "update") && t.depth === 0) {
        // UPDATE [OR REPLACE|ROLLBACK|ABORT|FAIL|IGNORE] <table>
        let j = i + 1;
        if (tokens[j] !== undefined && isWord(tokens[j], "or")) j += 2;
        const table = tokens[j];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
    for (const name of collectFromJoins(tokens)) read.push(name);
  } else if (kind === "delete") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "delete") && t.depth === 0) {
        const nxt = tokens[i + 1];
        if (nxt !== undefined && isWord(nxt, "from")) {
          const table = tokens[i + 2];
          if (table !== undefined && table.type === "word") writes(table.value);
        } else if (nxt !== undefined && nxt.type === "word") {
          writes(nxt.value);
        }
        break;
      }
    }
    // DELETE ... USING src (PostgreSQL) and subquery sources
    for (const name of collectFromJoins(tokens, true)) read.push(name);
  } else if (kind === "create") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "table") && t.depth === 0) {
        let j = i + 1;
        while (true) {
          const candidate = tokens[j];
          if (candidate === undefined || candidate.type !== "word" || !SKIP_IF_NOT_EXISTS.has(candidate.value.toLowerCase())) break;
          j++;
        }
        const table = tokens[j];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
    // CREATE TABLE ... AS SELECT ... FROM <source>
    for (const name of collectFromJoins(tokens)) read.push(name);
  } else if (kind === "alter") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "table") && t.depth === 0) {
        let j = i + 1;
        while (true) {
          const candidate = tokens[j];
          if (candidate === undefined || candidate.type !== "word" || !SKIP_IF_NOT_EXISTS.has(candidate.value.toLowerCase())) break;
          j++;
        }
        const table = tokens[j];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
  } else if (kind === "drop") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "drop") && t.depth === 0) {
        let j = i + 1;
        while (true) {
          const candidate = tokens[j];
          if (candidate === undefined || candidate.type !== "word" || !SKIP_DROP_OBJECT.has(candidate.value.toLowerCase())) break;
          j++;
        }
        const table = tokens[j];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
  } else if (kind === "truncate") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "truncate") && t.depth === 0) {
        let j = i + 1;
        while (true) {
          const candidate = tokens[j];
          if (candidate === undefined || candidate.type !== "word" || !SKIP_TRUNCATE_OBJECT.has(candidate.value.toLowerCase())) break;
          j++;
        }
        const table = tokens[j];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
  } else if (kind === "grant" || kind === "revoke") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "on") && t.depth === 0) {
        const table = tokens[i + 1];
        if (table !== undefined && table.type === "word") writes(table.value);
        break;
      }
    }
  } else if (kind === "attach") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "attach") && t.depth === 0) {
        let j = i + 1;
        while (true) {
          const candidate = tokens[j];
          if (candidate === undefined || candidate.type !== "word") break;
          const low = candidate.value.toLowerCase();
          if (!SKIP_IF_NOT_EXISTS.has(low) && low !== "database") break;
          j++;
        }
        const target = tokens[j];
        if (target !== undefined && (target.type === "word" || target.type === "string")) writes(target.value);
      }
    }
  } else if (kind === "copy") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t !== undefined && isWord(t, "copy") && t.depth === 0) {
        const target = tokens[i + 1];
        if (target !== undefined && target.type === "word" && target.value !== "(") writes(target.value);
        break;
      }
    }
    // COPY (SELECT ... FROM x) TO ... — inner sources only
    for (const name of collectFromJoins(tokens, true)) read.push(name);
  } else if (kind === "merge") {
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t === undefined || t.depth !== 0 || t.type !== "word") continue;
      const low = t.value.toLowerCase();
      if (low === "into") {
        const table = tokens[i + 1];
        if (table !== undefined && table.type === "word") writes(table.value);
      } else if (low === "using") {
        const table = tokens[i + 1];
        if (table !== undefined && table.type === "word") read.push(table.value);
      }
    }
  }

  return { read: dedupe(read), written: dedupe(written) };
}

function classifyKind(tokens: SqlToken[]): SqlStatementKind {
  for (const t of tokens) {
    if (t.type === "word" && t.depth === 0) {
      const mapped = KIND_WORDS[t.value.toLowerCase()];
      if (mapped !== undefined) return mapped;
    }
  }
  return "unknown";
}

function pragmaName(tokens: SqlToken[]): string | undefined {
  const name = tokens[1];
  if (name === undefined || name.type !== "word") return undefined;
  const segments = name.value.split(".");
  return segments[segments.length - 1]?.toLowerCase();
}

function detectDangerous(stmt: InternalStatement, tokens: TokenizedStatement): void {
  const kind = stmt.kind;
  if (kind === "drop") stmt.dangerous.push({ code: "DROP_TABLE", message: "DROP statements are destructive and irreversible" });
  if (kind === "truncate") stmt.dangerous.push({ code: "TRUNCATE_TABLE", message: "TRUNCATE removes every row from the target table" });
  if (kind === "alter") stmt.dangerous.push({ code: "ALTER_TABLE", message: "ALTER modifies the schema of a table" });
  if (kind === "grant") stmt.dangerous.push({ code: "GRANT_PRIVILEGES", message: "GRANT changes database privileges" });
  if (kind === "revoke") stmt.dangerous.push({ code: "REVOKE_PRIVILEGES", message: "REVOKE changes database privileges" });
  if (kind === "attach") stmt.dangerous.push({ code: "ATTACH_DATABASE", message: "ATTACH DATABASE exposes filesystem files to the database engine" });
  if (kind === "vacuum") stmt.dangerous.push({ code: "VACUUM", message: "VACUUM rebuilds the database file" });
  if (kind === "copy") stmt.dangerous.push({ code: "COPY_OPERATION", message: "COPY performs a bulk data transfer" });
  if (kind === "pragma") {
    const name = pragmaName(tokens.tokens);
    if (name !== undefined && WRITE_PRAGMAS.has(name)) {
      stmt.dangerous.push({ code: "WRITE_PRAGMA", message: `PRAGMA ${name} modifies database state` });
    }
  }
  if ((kind === "update" || kind === "delete") && !stmt.hasWhere) {
    stmt.dangerous.push({
      code: "MASS_UPDATE_OR_DELETE_WITHOUT_WHERE",
      message: `${kind.toUpperCase()} statement has no WHERE clause and may affect every row`,
    });
  }
}

function detectRiskSignals(stmt: InternalStatement, tokens: TokenizedStatement): void {
  if (tokens.malformed) stmt.riskSignals.push("MALFORMED_SQL");
  if (stmt.kind === "unknown" && tokens.tokens.length > 0) stmt.riskSignals.push("SQL_KIND_UNKNOWN");
  if (!stmt.isParameterized) {
    const allTables = [...stmt.tablesRead, ...stmt.tablesWritten];
    if (allTables.some(table => SENSITIVE_TABLE_RE.test(table))) {
      stmt.riskSignals.push("SENSITIVE_TABLE_NON_PARAMETERIZED");
    }
  }
}

function analyzeStatement(tokenized: TokenizedStatement): InternalStatement {
  const kind = classifyKind(tokenized.tokens);
  const { read, written } = extractTables(tokenized.tokens, kind);
  const stmt: InternalStatement = {
    kind,
    tablesRead: read,
    tablesWritten: written,
    hasWhere: tokenized.tokens.some(t => t.type === "word" && t.depth === 0 && t.value.toLowerCase() === "where"),
    isParameterized: tokenized.tokens.some(t => t.type === "param"),
    hasComment: tokenized.hasComment,
    dangerous: [],
    riskSignals: [],
  };
  detectDangerous(stmt, tokenized);
  detectRiskSignals(stmt, tokenized);
  return stmt;
}

/**
 * Analyze an SQL string (or SQL-like input) for risky operations.
 *
 * Deterministic and bounded: inputs larger than MAX_SQL_LENGTH are flagged with
 * SIZE_LIMIT_EXCEEDED and not parsed further. Malformed SQL never throws; it is
 * analyzed best-effort and flagged with MALFORMED_SQL.
 */
export function analyzeSql(sql: string, dialect?: SqlDialect): SqlAnalysis {
  void dialect;
  try {
    if (sql.length > MAX_SQL_LENGTH) {
      return { statements: [], dangerous: [], riskSignals: ["SIZE_LIMIT_EXCEEDED"] };
    }
    const tokenized = tokenizeSql(sql);
    const analyzed = tokenized.map(analyzeStatement);
    const dangerous: Array<{ code: string; message: string }> = [];
    const riskSignals: string[] = [];
    if (analyzed.length > 1) riskSignals.push("STACKED_STATEMENTS");
    for (const stmt of analyzed) {
      dangerous.push(...stmt.dangerous);
      riskSignals.push(...stmt.riskSignals);
    }
    return {
      statements: analyzed.map(stmt => ({
        kind: stmt.kind,
        tablesRead: stmt.tablesRead,
        tablesWritten: stmt.tablesWritten,
        hasWhere: stmt.hasWhere,
        isParameterized: stmt.isParameterized,
        hasComment: stmt.hasComment,
      })),
      dangerous,
      riskSignals: dedupe(riskSignals),
    };
  } catch {
    return {
      statements: [{ kind: "unknown", tablesRead: [], tablesWritten: [], hasWhere: false, isParameterized: false, hasComment: false }],
      dangerous: [],
      riskSignals: ["MALFORMED_SQL"],
    };
  }
}
