/**
 * Shared analysis output types for Invock's rich SQL / command semantic analysis.
 *
 * This module is intentionally dependency-free and independent so it can be
 * compiled, tested, and reused on its own.
 */

export type SqlDialect = "sqlite" | "postgres" | "mysql" | "generic";

export type SqlStatementKind =
  | "select"
  | "insert"
  | "update"
  | "delete"
  | "create"
  | "alter"
  | "drop"
  | "truncate"
  | "grant"
  | "revoke"
  | "attach"
  | "pragma"
  | "vacuum"
  | "copy"
  | "merge"
  | "unknown";

export interface SqlStatementAnalysis {
  kind: SqlStatementKind;
  tablesRead: string[];
  tablesWritten: string[];
  hasWhere: boolean;
  isParameterized: boolean;
  hasComment: boolean;
}

export interface SqlAnalysis {
  statements: SqlStatementAnalysis[];
  dangerous: Array<{ code: string; message: string }>;
  riskSignals: string[];
}

export interface CommandAnalysis {
  executable: string;
  argv: string[];
  dangerous: Array<{ code: string; message: string }>;
  riskSignals: string[];
  networkAccess: boolean;
  filesystemWrite: boolean;
  filesystemDelete: boolean;
  privilegeEscalation: boolean;
}
