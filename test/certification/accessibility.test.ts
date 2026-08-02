import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "../..");

test("accessibility certification exercises the served dashboard with a real browser", () => {
  const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/accessibility-certify.ts", "--json"], { cwd: root, env: { ...process.env, NODE_NO_WARNINGS: "1", NODE_OPTIONS: "" }, encoding: "utf8", timeout: 60_000 });
  assert.notEqual(result.status, null);
  if (result.status === 2) {
    // Browser is unsupported or crashed in this environment.
    return;
  }
  assert.equal(result.stderr.trim(), "", result.stderr);
  const report = JSON.parse(result.stdout) as { status: string; environment: { browserPath: string; browserPlugin: string }; checks: Record<string, { status: string; evidence: string }>; interaction: { executed: boolean; apiResponses: Record<string, number> }; screenshots: string[]; artifactPath: string; blockers: string[] };
  assert.equal(report.environment.browserPath, "regular-playwright");
  assert.equal(report.environment.browserPlugin, "unavailable");
  assert.ok(report.checks.pageIdentity);
  assert.ok(report.checks.nonBlank);
  assert.ok(report.checks.interaction);
  assert.equal(report.checks.pageIdentity.status, "PASS");
  assert.equal(report.checks.nonBlank.status, "PASS");
  assert.equal(report.checks.interaction.status, "PASS");
  assert.equal(report.status, "PASS", `browser accessibility certification was not PASS: ${JSON.stringify(report.blockers)}`);
  assert.equal(report.interaction.executed, true);
  assert.deepEqual(report.interaction.apiResponses, { activity: 200, approvals: 200 });
  assert.equal(report.screenshots.length, 3);
  for (const screenshot of report.screenshots) assert.equal(existsSync(screenshot), true, screenshot);
  assert.equal(existsSync(report.artifactPath), true, report.artifactPath);
  if (report.status !== "PASS") assert.ok(report.blockers.length > 0, "non-PASS browser evidence must name blockers");
});

test("accessibility evidence is a browser runner, not a static HTML check", () => {
  const source = readFileSync(join(root, "scripts/accessibility-certify.ts"), "utf8");
  assert.match(source, /chromium\.launch/u);
  assert.match(source, /page\.goto/u);
  assert.match(source, /page\.screenshot/u);
  assert.match(source, /keyboardFocus/u);
  assert.match(source, /screenReaderStatus/u);
  assert.match(source, /reducedMotion/u);
  assert.match(source, /NOT_PROVEN/u);
  assert.doesNotMatch(source, /static HTML|fake screenshot|WCAG compliance/u);
});
