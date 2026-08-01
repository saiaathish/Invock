import { digestJson } from "../core/canonical.js";

export type ArenaMetricName =
  | "scenarioCount"
  | "attackBlocked"
  | "benignCompleted"
  | "falsePositives"
  | "falseNegatives"
  | "cleanupCompleted"
  | "latencyMs";

export interface ArenaInvocationContext {
  readonly protected: boolean;
  readonly fixtureRoot: string;
  registerCleanup(cleanup: () => void | Promise<void>): void;
}

export interface ArenaInvocationResult {
  readonly outcome: "blocked" | "completed";
  readonly cleanup?: () => void | Promise<void>;
}

export interface ArenaScenario {
  readonly id: string;
  readonly attack: boolean;
  readonly expectedBlocked: boolean;
  readonly invoke: (context: ArenaInvocationContext) => ArenaInvocationResult | Promise<ArenaInvocationResult>;
}

export interface ArenaOutcome {
  readonly scenarioId: string;
  readonly protectedOutcome: "blocked" | "completed";
  readonly unprotectedOutcome: "blocked" | "completed";
  readonly expectedBlocked: boolean;
  readonly attack: boolean;
}

export interface ArenaMetrics {
  readonly [metric: string]: number;
}

export interface ArenaRunOptions {
  readonly scenarios: readonly ArenaScenario[];
  readonly fixtureRoot?: string;
  readonly metrics?: readonly ArenaMetricName[];
  readonly plan?: { readonly metrics: readonly ArenaMetricName[] };
  /** Optional real execution adapter. When supplied, Arena does not simulate protection in the scenario callback. */
  readonly execute?: (scenario: ArenaScenario, context: ArenaInvocationContext) => ArenaInvocationResult | Promise<ArenaInvocationResult>;
}

export interface ArenaRun {
  readonly metrics: ArenaMetrics;
  readonly outcomes: readonly ArenaOutcome[];
  readonly deterministicDigest: string;
  readonly cleanupCompleted: boolean;
}

const DEFAULT_METRICS: readonly ArenaMetricName[] = [
  "scenarioCount", "attackBlocked", "benignCompleted", "falsePositives", "falseNegatives", "cleanupCompleted", "latencyMs",
];
const METRIC_SET = new Set<ArenaMetricName>(DEFAULT_METRICS);

function fail(message: string): never { throw new Error(`ARENA_INVALID_SCENARIO: ${message}`); }

function validateScenario(candidate: ArenaScenario, index: number): void {
  if (candidate === null || typeof candidate !== "object") fail(`scenario[${index}] must be an object`);
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(candidate.id)) fail(`scenario[${index}].id is invalid`);
  if (typeof candidate.attack !== "boolean") fail(`scenario[${index}].attack must be boolean`);
  if (typeof candidate.expectedBlocked !== "boolean") fail(`scenario[${index}].expectedBlocked must be boolean`);
  if (typeof candidate.invoke !== "function") fail(`scenario[${index}].invoke must be a function`);
}

function selectedMetrics(options: ArenaRunOptions): readonly ArenaMetricName[] {
  const requested = options.plan?.metrics ?? options.metrics ?? DEFAULT_METRICS;
  if (!Array.isArray(requested) || requested.length === 0) fail("metrics must be a non-empty array");
  const unique = [...new Set(requested)];
  if (unique.some(metric => !METRIC_SET.has(metric))) fail("metrics contains an unsupported metric");
  return unique;
}

function result(value: unknown, scenarioId: string): ArenaInvocationResult {
  if (value === null || typeof value !== "object") fail(`${scenarioId}.invoke must return an object`);
  const candidate = value as Record<string, unknown>;
  if (candidate.outcome !== "blocked" && candidate.outcome !== "completed") fail(`${scenarioId}.invoke returned an invalid outcome`);
  if (candidate.cleanup !== undefined && typeof candidate.cleanup !== "function") fail(`${scenarioId}.cleanup must be a function`);
  return candidate as unknown as ArenaInvocationResult;
}

async function invokeScenario(scenario: ArenaScenario, protectedMode: boolean, fixtureRoot: string, execute?: ArenaRunOptions["execute"]): Promise<ArenaInvocationResult> {
  const cleanups: Array<() => void | Promise<void>> = [];
  const context: ArenaInvocationContext = { protected: protectedMode, fixtureRoot, registerCleanup: cleanup => {
    if (typeof cleanup !== "function") fail(`${scenario.id}.registerCleanup received a non-function`);
    cleanups.push(cleanup);
  } };
  let invocation: ArenaInvocationResult | undefined;
  try {
    invocation = result(await (execute ? execute(scenario, context) : scenario.invoke(context)), scenario.id);
    if (invocation.cleanup) cleanups.push(invocation.cleanup);
    return invocation;
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup();
  }
}

/** Runs only local scenario functions twice: once through protection and once as a baseline. */
export async function runArena(options: ArenaRunOptions): Promise<ArenaRun> {
  if (options === null || typeof options !== "object" || !Array.isArray(options.scenarios)) fail("options.scenarios must be an array");
  const metricsToMeasure = selectedMetrics(options);
  if (options.execute !== undefined && typeof options.execute !== "function") fail("execute must be a function");
  const ids = new Set<string>();
  for (const [index, scenario] of options.scenarios.entries()) {
    validateScenario(scenario, index);
    if (ids.has(scenario.id)) fail(`duplicate scenario id: ${scenario.id}`);
    ids.add(scenario.id);
  }
  const fixtureRoot = options.fixtureRoot ?? "fixtures/arena";
  if (!fixtureRoot.startsWith("fixtures/arena") || fixtureRoot.includes("..")) fail("fixtureRoot must be below fixtures/arena");

  const outcomes: ArenaOutcome[] = [];
  let cleanupCompleted = true;
  let latencyMs = 0;
  for (const scenario of options.scenarios) {
    let protectedResult: ArenaInvocationResult;
    let baselineResult: ArenaInvocationResult;
    const started = Date.now();
    try {
      protectedResult = await invokeScenario(scenario, true, fixtureRoot, options.execute);
      baselineResult = await invokeScenario(scenario, false, fixtureRoot, options.execute);
    } catch (error) {
      // An invocation error is fail-closed: it is represented as a blocked protected run.
      if (error instanceof Error && error.message.startsWith("ARENA_INVALID_SCENARIO:")) throw error;
      protectedResult = { outcome: "blocked" };
      baselineResult = { outcome: "blocked" };
      cleanupCompleted = false;
    }
    latencyMs += Date.now() - started;
    outcomes.push({ scenarioId: scenario.id, protectedOutcome: protectedResult.outcome, unprotectedOutcome: baselineResult.outcome, expectedBlocked: scenario.expectedBlocked, attack: scenario.attack });
  }

  const values: Record<ArenaMetricName, number> = {
    scenarioCount: outcomes.length,
    attackBlocked: outcomes.filter(item => item.attack && item.expectedBlocked && item.protectedOutcome === "blocked").length,
    benignCompleted: outcomes.filter(item => !item.attack && !item.expectedBlocked && item.protectedOutcome === "completed").length,
    falsePositives: outcomes.filter(item => !item.attack && item.protectedOutcome === "blocked").length,
    falseNegatives: outcomes.filter(item => item.attack && item.expectedBlocked && item.protectedOutcome !== "blocked").length,
    cleanupCompleted: cleanupCompleted ? 1 : 0,
    latencyMs,
  };
  const measured = Object.fromEntries(metricsToMeasure.map(metric => [metric, values[metric]]));
  const digestMetrics = Object.fromEntries(Object.entries(measured).filter(([metric]) => metric !== "latencyMs"));
  const deterministicDigest = digestJson({ outcomes, metrics: digestMetrics });
  return { metrics: measured, outcomes, deterministicDigest, cleanupCompleted };
}
