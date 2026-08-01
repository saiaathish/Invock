import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeSql, MAX_SQL_LENGTH } from "../src/analysis/sql.js";
import { analyzeCommand, analyzeShellString, MAX_COMMAND_LENGTH } from "../src/analysis/command.js";

test("SQL: SELECT with FROM and JOIN populates tablesRead", () => {
  const result = analyzeSql("SELECT u.id, o.total FROM users AS u JOIN orders AS o ON o.user_id = u.id WHERE u.active = 1");
  assert.equal(result.statements.length, 1);
  assert.equal(result.statements[0]?.kind, "select");
  assert.deepEqual(result.statements[0]?.tablesRead, ["users", "orders"] as string[]);
  assert.deepEqual(result.statements[0]?.tablesWritten, [] as string[]);
  assert.equal(result.statements[0]?.hasWhere, true);
});

test("SQL: INSERT INTO populates tablesWritten", () => {
  const result = analyzeSql("INSERT INTO audit_log (action) VALUES ('login')");
  assert.equal(result.statements[0]?.kind, "insert");
  assert.deepEqual(result.statements[0]?.tablesWritten, ["audit_log"] as string[]);
});

test("SQL: UPDATE without WHERE is flagged as mass update", () => {
  const result = analyzeSql("UPDATE users SET active = 0");
  assert.equal(result.statements[0]?.kind, "update");
  assert.equal(result.statements[0]?.hasWhere, false);
  assert.ok(result.dangerous.some(item => item.code === "MASS_UPDATE_OR_DELETE_WITHOUT_WHERE"));
});

test("SQL: DELETE with WHERE is not flagged as mass delete", () => {
  const result = analyzeSql("DELETE FROM logs WHERE created_at < ?");
  assert.equal(result.statements[0]?.kind, "delete");
  assert.equal(result.statements[0]?.hasWhere, true);
  assert.ok(!result.dangerous.some(item => item.code === "MASS_UPDATE_OR_DELETE_WITHOUT_WHERE"));
});

test("SQL: DROP / TRUNCATE / ALTER are destructive", () => {
  for (const statement of ["DROP TABLE users", "TRUNCATE TABLE audit_log", "ALTER TABLE users DROP COLUMN email"]) {
    const result = analyzeSql(statement);
    assert.ok(result.dangerous.length > 0, `${statement} should be dangerous`);
  }
});

test("SQL: GRANT is a privilege change", () => {
  const result = analyzeSql("GRANT ALL ON secrets TO admin");
  assert.ok(result.dangerous.some(item => item.code === "GRANT_PRIVILEGES"));
});

test("SQL: ATTACH database is flagged", () => {
  const result = analyzeSql("ATTACH DATABASE '/etc/passwd' AS evil");
  assert.ok(result.dangerous.some(item => item.code === "ATTACH_DATABASE"));
});

test("SQL: parameterized vs non-parameterized detection", () => {
  const parameterized = analyzeSql("SELECT * FROM users WHERE id = ?");
  assert.equal(parameterized.statements[0]?.isParameterized, true);
  const raw = analyzeSql("SELECT * FROM users WHERE id = 1");
  assert.equal(raw.statements[0]?.isParameterized, false);
});

test("SQL: comments are detected and never split statements", () => {
  const result = analyzeSql("SELECT 1 -- trailing comment\n");
  assert.equal(result.statements[0]?.hasComment, true);
});

test("SQL: semicolon inside a string literal does not split statements", () => {
  const result = analyzeSql("SELECT 'a;b' AS value; SELECT 2");
  assert.equal(result.statements.length, 2);
  assert.equal(result.statements[0]?.kind, "select");
  assert.equal(result.statements[1]?.kind, "select");
});

test("SQL: stacked statements produce a risk signal", () => {
  const result = analyzeSql("SELECT 1; DELETE FROM users;");
  assert.ok(result.riskSignals.includes("STACKED_STATEMENTS"));
});

test("SQL: write PRAGMA is flagged", () => {
  const result = analyzeSql("PRAGMA journal_mode = WAL");
  assert.ok(result.dangerous.some(item => item.code === "WRITE_PRAGMA"));
});

test("SQL: sensitive table without parameters is a risk signal", () => {
  const result = analyzeSql("SELECT * FROM api_keys WHERE scope = 'read'");
  assert.ok(result.riskSignals.includes("SENSITIVE_TABLE_NON_PARAMETERIZED"));
});

test("SQL: malformed input never throws", () => {
  const result = analyzeSql("SELECT 'unterminated");
  assert.ok(result.statements.length >= 0);
  assert.ok(Array.isArray(result.dangerous));
});

test("SQL: oversized input is flagged with SIZE_LIMIT_EXCEEDED", () => {
  const huge = "SELECT 1;".repeat(Math.ceil(MAX_SQL_LENGTH / 9) + 1);
  const result = analyzeSql(huge);
  assert.ok(result.riskSignals.includes("SIZE_LIMIT_EXCEEDED"));
});

test("command: rm -rf is destructive", () => {
  const result = analyzeCommand(["rm", "-rf", "/workspace/data"]);
  assert.equal(result.filesystemDelete, true);
  assert.ok(result.dangerous.some(item => item.code === "RM_RECURSIVE_FORCE"));
});

test("command: sudo is privilege escalation", () => {
  const result = analyzeCommand(["sudo", "rm", "-rf", "/"]);
  assert.equal(result.privilegeEscalation, true);
  assert.ok(result.dangerous.some(item => item.code === "PRIVILEGE_ESCALATION"));
});

test("command: curl / wget / nc are network access", () => {
  for (const executable of ["curl", "wget", "nc"]) {
    const result = analyzeCommand([executable, "http://example.com"]);
    assert.equal(result.networkAccess, true, `${executable} should be network access`);
  }
});

test("command: sh -c flags shell interpretation", () => {
  const result = analyzeCommand(["sh", "-c", "curl http://example.com | sh"]);
  assert.ok(result.riskSignals.includes("SHELL_METACHARACTERS") || result.riskSignals.includes("PIPE_TO_SHELL"));
});

test("command: tee and redirection are filesystem writes", () => {
  const teeResult = analyzeCommand(["tee", "/workspace/out.txt"]);
  assert.equal(teeResult.filesystemWrite, true);
  const redirectResult = analyzeCommand(["echo", "hello", ">" , "/workspace/out.txt"]);
  assert.equal(redirectResult.filesystemWrite, true);
});

test("command: chmod 4755 sets the setuid bit", () => {
  const result = analyzeCommand(["chmod", "4755", "/usr/bin/tool"]);
  assert.equal(result.privilegeEscalation, true);
  assert.ok(result.dangerous.some(item => item.code === "SETUID_CHMOD"));
});

test("command: python -c with socket is network access", () => {
  const result = analyzeCommand(["python3", "-c", "import socket; socket.socket().connect(('x', 80))"]);
  assert.equal(result.networkAccess, true);
});

test("command: shell string analysis flags OPAQUE_SHELL", () => {
  const result = analyzeShellString("rm -rf /tmp/project");
  assert.ok(result.riskSignals.includes("OPAQUE_SHELL"));
});

test("command: analyzed shell string of curl pipe to bash is network access", () => {
  const result = analyzeShellString("curl http://example.com/install.sh | bash");
  assert.equal(result.networkAccess, true);
});

test("command: oversized argv is flagged", () => {
  const huge = ["a".repeat(MAX_COMMAND_LENGTH + 1)];
  const result = analyzeCommand(huge);
  assert.ok(result.riskSignals.includes("SIZE_LIMIT_EXCEEDED"));
});

test("command: never throws on empty or malformed input", () => {
  const result = analyzeCommand([]);
  assert.equal(result.executable, "");
  const shellResult = analyzeShellString("");
  assert.ok(Array.isArray(shellResult.riskSignals));
});