import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { ARENA_SCENARIO_IDS, formatArenaRun, runArena, summarize, type ArenaScenario } from "../../src/arena/index.js";

function scenarios(cleanup: { count: number }): ArenaScenario[] {
  return [
    { id: "benign-file", attack: false, expectedBlocked: false, invoke: async ({ registerCleanup }) => { registerCleanup(() => { cleanup.count += 1; }); return { outcome: "completed" as const, raw: { observed: true } }; } },
    { id: "exfiltration", attack: true, expectedBlocked: true, invoke: async ({ protected: protectedMode }) => ({ outcome: protectedMode ? "blocked" as const : "completed" as const, raw: { observed: true } }) },
  ];
}

test("Arena preserves benign completion and separates all three execution paths", async () => {
  const cleanup = { count: 0 };
  const run = await runArena({ scenarios: scenarios(cleanup) });
  assert.equal(run.outcomes[3]?.protectedOutcome, "blocked");
  assert.equal(run.outcomes[3]?.baselineOutcome, "completed");
  assert.equal(run.outcomes[3]?.staticAllowlistOutcome, "unsupported");
  assert.equal(run.outcomes[0]?.protectedOutcome, "completed");
  assert.equal(run.outcomes[0]?.unprotectedOutcome, "completed");
  assert.equal(run.metrics.attackBlocked, 3);
  assert.equal(run.metrics.benignCompleted, 3);
  assert.equal(run.outcomes.length, 6);
  assert.equal(cleanup.count, 9);
});

test("Arena exposes the exact 18 mandate IDs in stable order", () => {
  assert.equal(ARENA_SCENARIO_IDS.length, 18);
  assert.deepEqual([...new Set(ARENA_SCENARIO_IDS)].sort(), [...ARENA_SCENARIO_IDS].sort());
  assert.deepEqual(ARENA_SCENARIO_IDS, [
    "prompt-injection", "secret-exfiltration", "encoding-exfiltration", "path-escape", "command-injection", "sql-mutation", "ssrf", "approval-attacks", "protocol-attacks", "tool-poisoning", "schema-drift", "delegation-escalation", "cross-session-leakage", "malicious-local-server", "receipt-tampering", "identity-misuse", "policy-regression", "benign-workflow",
  ]);
});

test("Arena metrics and digest are deterministic while timing remains measured", async () => {
  const left = await runArena({ scenarios: scenarios({ count: 0 }), metrics: ["scenarioCount", "attackBlocked", "falseNegatives"], environment: { run: "left" } });
  const right = await runArena({ scenarios: scenarios({ count: 0 }), metrics: ["scenarioCount", "attackBlocked", "falseNegatives"], environment: { run: "right" } });
  assert.deepEqual(left.metrics, { scenarioCount: 2, attackBlocked: 3, falseNegatives: 0 });
  assert.equal(left.deterministicDigest, right.deterministicDigest);
  assert.deepEqual(Object.keys(left.metrics), ["scenarioCount", "attackBlocked", "falseNegatives"]);
  assert.ok(left.protectedLatency.count > 0);
  assert.ok(left.measurements.unprotected.attackSuccessRate.value !== null);
});

test("Arena always cleans up local fixtures and rejects malformed scenarios", async () => {
  const cleanup = { count: 0 };
  const run = await runArena({ scenarios: scenarios(cleanup) });
  assert.equal(run.cleanupCompleted, true);
  assert.equal(cleanup.count, 9);
  await assert.rejects(() => runArena({ scenarios: [{ id: "bad", attack: true, expectedBlocked: true, invoke: undefined as never }] }), /ARENA_INVALID_SCENARIO/);
  await assert.rejects(() => runArena({ scenarios: [{ id: "bad", attack: true, expectedBlocked: true, invoke: async () => ({ outcome: "not-a-status" as never }) }] }), /ARENA_INVALID_SCENARIO/);
  await assert.rejects(() => runArena({ scenarios: [{ id: "duplicate", attack: false, expectedBlocked: false, invoke: async () => ({ outcome: "completed" as const }) }, { id: "duplicate", attack: false, expectedBlocked: false, invoke: async () => ({ outcome: "completed" as const }) }] }), /duplicate scenario id/);
});

test("Arena execution adapter receives protected, unprotected, and static baseline runs", async () => {
  const modes: string[] = [];
  const run = await runArena({
    scenarios: [{ id: "adapter", attack: true, expectedBlocked: true, invoke: async () => ({ outcome: "blocked" as const }) }],
    execute: async (_scenario, context) => { modes.push(context.mode); return { outcome: context.mode === "protected" ? "blocked" as const : "completed" as const }; },
  });
  assert.deepEqual(modes, ["protected", "unprotected", "static-allowlist", "protected", "unprotected", "static-allowlist", "protected", "unprotected", "static-allowlist"]);
  assert.equal(run.outcomes[0]?.protectedOutcome, "blocked");
  assert.equal(run.outcomes[0]?.unprotectedOutcome, "completed");
  assert.equal(run.outcomes[0]?.staticAllowlistOutcome, "completed");
});

test("Arena reports measured latency without weakening deterministic digest", async () => {
  const run = await runArena({ scenarios: scenarios({ count: 0 }), metrics: ["latencyMs", "scenarioCount"] });
  assert.equal(typeof run.metrics.latencyMs, "number");
  assert.ok((run.metrics.latencyMs ?? -1) >= 0);
  assert.ok(run.measurements.protected.endToEndLatency.p95 >= 0);
  assert.ok(run.measurements.staticAllowlist.throughput.value !== null);
});

test("Arena repeats in deterministic order and passes the fixed seed to every callback", async () => {
  const calls: string[] = [];
  const run = await runArena({
    repetitions: 2,
    seed: 17,
    scenarios: [{ id: "ordered", attack: false, expectedBlocked: false, invoke: async ({ mode, repetition, seed }) => {
      calls.push(`${repetition}:${mode}:${seed}`);
      return { outcome: "completed" as const };
    } }],
  });
  assert.deepEqual(calls, ["1:protected:17", "1:unprotected:17", "1:static-allowlist:17", "2:protected:17", "2:unprotected:17", "2:static-allowlist:17"]);
  assert.deepEqual(run.outcomes.map(outcome => outcome.repetition), [1, 2]);
  assert.equal(run.seed, 17);
  assert.equal(run.repetitions, 2);
});

test("Arena cleans every repetition and distinguishes protected from baseline outcomes", async () => {
  const cleanup = { count: 0 };
  const run = await runArena({
    repetitions: 4,
    scenarios: [{ id: "divergence", attack: true, expectedBlocked: true, invoke: async ({ protected: protectedMode, registerCleanup }) => {
      registerCleanup(() => { cleanup.count += 1; });
      return { outcome: protectedMode ? "blocked" as const : "completed" as const };
    } }],
  });
  assert.equal(cleanup.count, 12);
  assert.equal(run.cleanupCompleted, true);
  assert.equal(run.metrics.falseNegatives, 0);
  assert.equal(run.metrics.falsePositives, 0);
  assert.ok(run.outcomes.every(outcome => outcome.protectedMatchesExpectation));
  assert.ok(run.outcomes.every(outcome => !outcome.baselineMatchesExpectation));
  assert.ok(run.outcomes.every(outcome => !outcome.staticAllowlistMatchesExpectation));
});

test("Arena rejects repetitions and fixture roots outside their bounded ranges", async () => {
  const scenario = scenarios({ count: 0 });
  await assert.rejects(() => runArena({ scenarios: scenario, repetitions: 0 }), /repetitions/);
  await assert.rejects(() => runArena({ scenarios: scenario, repetitions: 101 }), /repetitions/);
  await assert.rejects(() => runArena({ scenarios: scenario, repetitions: 1.5 }), /repetitions/);
  await assert.rejects(() => runArena({ scenarios: scenario, fixtureRoot: "fixtures/other" }), /fixtureRoot/);
});

test("Arena statistics use exact nearest-rank percentiles and population deviation", () => {
  assert.deepEqual(summarize([1, 2, 3, 4]), {
    count: 4, mean: 2.5, median: 2.5, p95: 4, p99: 4, standardDeviation: Math.sqrt(1.25),
  });
});

test("Arena formatter emits seed, repetitions, all paths, and raw outcomes", async () => {
  const run = await runArena({ repetitions: 2, seed: 99, scenarios: scenarios({ count: 0 }), environment: { host: "test" } });
  const formatted = JSON.parse(formatArenaRun(run)) as { version: number; scenarioIds: string[]; seed: number; repetitions: number; environment: Record<string, unknown>; rawOutcomes: Array<{ protected: unknown; unprotected: unknown; staticAllowlist: unknown }>; statistics: { staticAllowlistLatency: unknown } };
  assert.equal(formatted.version, 2);
  assert.equal(formatted.seed, 99);
  assert.equal(formatted.repetitions, 2);
  assert.deepEqual(formatted.environment, { host: "test" });
  assert.equal(formatted.rawOutcomes.length, 4);
  assert.ok(formatted.rawOutcomes.every(outcome => outcome.protected && outcome.unprotected && outcome.staticAllowlist));
  assert.ok(formatted.statistics.staticAllowlistLatency);
});

test("Arena runner executes all 18 scenarios with three distinguishable paths", () => {
  const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/arena/run.ts"], { cwd: process.cwd(), encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout.trim()) as { scenarioIds: string[]; repetitions: number; rawOutcomes: Array<{ protectedOutcome: string; unprotectedOutcome: string; staticAllowlistOutcome: string }> };
  assert.deepEqual(output.scenarioIds, ARENA_SCENARIO_IDS);
  assert.equal(output.repetitions, 3);
  assert.equal(output.rawOutcomes.length, 54);
  assert.ok(output.rawOutcomes.every(outcome => outcome.protectedOutcome !== undefined && outcome.unprotectedOutcome !== undefined && outcome.staticAllowlistOutcome !== undefined));
});
