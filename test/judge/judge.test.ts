import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";
import test from "node:test";
import { runJudge } from "../../src/judge/index.js";

test("judge flow completes locally with fake data, signed evidence, and cleanup", async () => {
  const result = await runJudge({ mode: "automated" });
  assert.notEqual(result.overall, "failed", JSON.stringify(result));
  assert.equal(result.deterministic.fakeDataOnly, true);
  assert.equal(result.deterministic.externalNetworkCalls, false);
  assert.equal(result.narrative.safeExample.verdict, "ALLOW");
  assert.equal(result.narrative.safeExample.upstreamExecutionCount, 1);
  assert.equal(result.narrative.blockedAttack.verdict, "BLOCK");
  assert.equal(result.narrative.blockedAttack.upstreamExecutionCount, 1);
  assert.equal(result.narrative.signedEvidence.chainValid, true);
  assert.equal(result.narrative.signedEvidence.receiptCount, 2);
  assert.equal(result.cleanup.completed, true);
  assert.equal(result.presentation.browserEvidence, "not-collected");
  const gateway = result.checkpoints.find(item => item.id === "gateway");
  assert.equal(gateway?.details.semanticReadiness, true);
  assert.ok(result.checkpoints.some(item => item.id === "gateway"));
  assert.ok(result.checkpoints.some(item => item.id === "blocked-attack"));

  const repeat = await runJudge({ mode: "automated" });
  const stable = (value: typeof result) => ({
    overall: value.overall,
    checkpointStatuses: value.checkpoints.map(item => [item.id, item.status]),
    decisions: [value.narrative.safeExample.verdict, value.narrative.blockedAttack.verdict],
    executions: [value.narrative.safeExample.upstreamExecutionCount, value.narrative.blockedAttack.upstreamExecutionCount],
    evidence: [value.narrative.signedEvidence.chainValid, value.narrative.signedEvidence.receiptCount],
    cleanup: value.cleanup.completed,
  });
  assert.deepEqual(stable(repeat), stable(result));
});

test("judge command emits one parseable JSON result without a PASS banner", () => {
  const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/judge.ts", "--automated"], { encoding: "utf8", cwd: process.cwd() });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const parsed = JSON.parse(result.stdout) as { schemaVersion: string; overall: string };
  assert.equal(parsed.schemaVersion, "invock/judge-result/v1");
  assert.notEqual(parsed.overall, "failed");
  assert.equal(/INVOCK(?:\s+\w+)*:\s*(?:PASS|READY)/iu.test(result.stdout), false);
});

test("Compose example is version-pinned and explicitly documentation-only", () => {
  const source = readFileSync("docker-compose.yml", "utf8");
  const parsed = parseDocument(source, { uniqueKeys: true }).toJS() as { services?: Record<string, { image?: string; command?: string[] }> };
  assert.equal(parsed.services?.["invock-judge"]?.image, "node:22.18.0-bookworm-slim@sha256:752ea8a2f758c34002a0461bd9f1cee4f9a3c36d48494586f60ffce1fc708e0e");
  assert.match(parsed.services?.["invock-judge"]?.image ?? "", /@sha256:[a-f0-9]{64}$/u);
  assert.match(source, /not Docker runtime evidence/iu);
  assert.equal(parsed.services?.["invock-judge"]?.command?.join(" ").includes("judge --automated"), true);
});

test("presentation mode exposes a pause callback at every checkpoint", async () => {
  let pauses = 0;
  const result = await runJudge({ mode: "presentation", pause: async () => { pauses += 1; } });
  assert.equal(result.presentation.checkpointsPause, true);
  assert.equal(pauses, result.checkpoints.length);
  assert.equal(result.presentation.automatedModeAvailable, true);
  assert.equal(result.cleanup.completed, true);
});
