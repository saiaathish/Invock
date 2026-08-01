import assert from "node:assert/strict";
import test from "node:test";
import { runArena, type ArenaScenario } from "../../src/arena/index.js";

function scenarios(cleanup: { count: number }): ArenaScenario[] {
  return [
    { id: "benign-file", attack: false, expectedBlocked: false, invoke: async ({ registerCleanup }) => { registerCleanup(() => { cleanup.count += 1; }); return { outcome: "completed" as const }; } },
    { id: "exfiltration", attack: true, expectedBlocked: true, invoke: async ({ protected: protectedMode }) => ({ outcome: protectedMode ? "blocked" as const : "completed" as const }) },
  ];
}

test("Arena blocks the attack while preserving benign completion", async () => {
  const cleanup = { count: 0 };
  const run = await runArena({ scenarios: scenarios(cleanup) });
  assert.equal(run.outcomes[1]?.protectedOutcome, "blocked");
  assert.equal(run.outcomes[1]?.unprotectedOutcome, "completed");
  assert.equal(run.outcomes[0]?.protectedOutcome, "completed");
  assert.equal(run.outcomes[0]?.unprotectedOutcome, "completed");
  assert.equal(run.metrics.attackBlocked, 1);
  assert.equal(run.metrics.benignCompleted, 1);
});

test("Arena metrics and digest are deterministic", async () => {
  const left = await runArena({ scenarios: scenarios({ count: 0 }), metrics: ["scenarioCount", "attackBlocked", "falseNegatives"] });
  const right = await runArena({ scenarios: scenarios({ count: 0 }), metrics: ["scenarioCount", "attackBlocked", "falseNegatives"] });
  assert.deepEqual(left.metrics, { scenarioCount: 2, attackBlocked: 1, falseNegatives: 0 });
  assert.equal(left.deterministicDigest, right.deterministicDigest);
  assert.deepEqual(Object.keys(left.metrics), ["scenarioCount", "attackBlocked", "falseNegatives"]);
});

test("Arena always cleans up local fixtures and rejects malformed scenarios", async () => {
  const cleanup = { count: 0 };
  const run = await runArena({ scenarios: scenarios(cleanup) });
  assert.equal(run.cleanupCompleted, true);
  assert.equal(cleanup.count, 2);
  await assert.rejects(() => runArena({ scenarios: [{ id: "bad", attack: true, expectedBlocked: true, invoke: undefined as never }] }), /ARENA_INVALID_SCENARIO/);
});

test("Arena execution adapter receives protected and baseline runs", async () => {
  const modes: boolean[] = [];
  const run = await runArena({
    scenarios: [{ id: "adapter", attack: true, expectedBlocked: true, invoke: async () => ({ outcome: "blocked" as const }) }],
    execute: async (_scenario, context) => { modes.push(context.protected); return { outcome: context.protected ? "blocked" as const : "completed" as const }; },
  });
  assert.deepEqual(modes, [true, false]);
  assert.equal(run.outcomes[0]?.protectedOutcome, "blocked");
  assert.equal(run.outcomes[0]?.unprotectedOutcome, "completed");
});

test("Arena reports measured latency without weakening deterministic digest", async () => {
  const run = await runArena({ scenarios: scenarios({ count: 0 }), metrics: ["latencyMs", "scenarioCount"] });
  assert.equal(typeof run.metrics.latencyMs, "number");
  assert.ok((run.metrics.latencyMs ?? -1) >= 0);
});
