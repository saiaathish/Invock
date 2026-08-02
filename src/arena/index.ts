import { digestJson } from "../core/canonical.js";

export const ARENA_SCENARIO_IDS = [
  "prompt-injection",
  "secret-exfiltration",
  "encoding-exfiltration",
  "path-escape",
  "command-injection",
  "sql-mutation",
  "ssrf",
  "approval-attacks",
  "protocol-attacks",
  "tool-poisoning",
  "schema-drift",
  "delegation-escalation",
  "cross-session-leakage",
  "malicious-local-server",
  "receipt-tampering",
  "identity-misuse",
  "policy-regression",
  "benign-workflow",
] as const;

export type ArenaScenarioId = (typeof ARENA_SCENARIO_IDS)[number];
export type ArenaExecutionMode = "protected" | "unprotected" | "static-allowlist";
export type ArenaOutcomeStatus = "blocked" | "completed" | "unknown" | "unsupported";
export type ArenaSupportStatus = "measured" | "unknown" | "unsupported";

export type ArenaMetricName =
  | "scenarioCount"
  | "attackBlocked"
  | "benignCompleted"
  | "falsePositives"
  | "falseNegatives"
  | "cleanupCompleted"
  | "latencyMs";

export interface ArenaInvocationContext {
  /** Legacy flag retained for callers that only distinguish protected/baseline. */
  readonly protected: boolean;
  /** The explicit path being measured. */
  readonly mode: ArenaExecutionMode;
  /** Null for protected runs, otherwise the named baseline. */
  readonly baseline: Exclude<ArenaExecutionMode, "protected"> | null;
  readonly fixtureRoot: string;
  readonly repetition: number;
  readonly seed: number;
  registerCleanup(cleanup: () => void | Promise<void>): void;
}

export interface ArenaInvocationMeasurements {
  readonly unauthorizedUpstreamCalls?: number;
  readonly secretSinkCalls?: number;
  readonly approvalReplays?: number;
  readonly quarantineDetections?: number;
  readonly containmentDenials?: number;
  readonly decisionLatencyMs?: number;
}

export interface ArenaInvocationResult {
  readonly outcome: ArenaOutcomeStatus;
  readonly support?: ArenaSupportStatus;
  readonly reason?: string;
  readonly raw?: Record<string, unknown>;
  readonly measurements?: ArenaInvocationMeasurements;
  /** Adapter-only input. It is never included in formatted results. */
  readonly executionInput?: unknown;
  readonly cleanup?: () => void | Promise<void>;
}

export interface ArenaScenario {
  readonly id: string;
  readonly attack: boolean;
  readonly expectedBlocked: boolean;
  readonly category?: string;
  readonly invoke: (context: ArenaInvocationContext) => ArenaInvocationResult | Promise<ArenaInvocationResult>;
}

export interface ArenaPathResult {
  readonly mode: ArenaExecutionMode;
  readonly outcome: ArenaOutcomeStatus;
  readonly support: ArenaSupportStatus;
  readonly reason?: string;
  readonly latencyMs: number;
  readonly raw?: Record<string, unknown>;
  readonly measurements?: ArenaInvocationMeasurements;
}

export interface ArenaOutcome {
  readonly scenarioId: string;
  readonly category?: string;
  readonly repetition: number;
  readonly expectedBlocked: boolean;
  readonly attack: boolean;
  readonly protected: ArenaPathResult;
  readonly unprotected: ArenaPathResult;
  readonly staticAllowlist: ArenaPathResult;
  readonly protectedOutcome: ArenaOutcomeStatus;
  /** Legacy baseline alias. It refers to the unprotected path. */
  readonly baselineOutcome: ArenaOutcomeStatus;
  /** @deprecated Use baselineOutcome or unprotected. */
  readonly unprotectedOutcome: ArenaOutcomeStatus;
  readonly staticAllowlistOutcome: ArenaOutcomeStatus;
  readonly protectedLatencyMs: number;
  readonly baselineLatencyMs: number;
  readonly staticAllowlistLatencyMs: number;
  readonly protectedMatchesExpectation: boolean;
  readonly baselineMatchesExpectation: boolean;
  readonly staticAllowlistMatchesExpectation: boolean;
}

export interface ArenaMetrics {
  readonly [metric: string]: number;
}

export interface ArenaStatistics {
  readonly count: number;
  readonly mean: number;
  readonly median: number;
  readonly p95: number;
  readonly p99: number;
  readonly standardDeviation: number;
}

export interface ArenaMetricValue {
  readonly value: number | null;
  readonly status: ArenaSupportStatus;
  readonly numerator?: number;
  readonly denominator?: number;
  readonly unit?: string;
}

export interface ArenaPathSummary {
  readonly invocationCount: number;
  readonly attackSuccessRate: ArenaMetricValue;
  readonly attackBlockRate: ArenaMetricValue;
  readonly benignCompletionRate: ArenaMetricValue;
  readonly falsePositiveRate: ArenaMetricValue;
  readonly falseNegativeRate: ArenaMetricValue;
  readonly unauthorizedUpstreamCalls: ArenaMetricValue;
  readonly secretSinkCalls: ArenaMetricValue;
  readonly approvalReplayRate: ArenaMetricValue;
  readonly quarantineDetectionRate: ArenaMetricValue;
  readonly containmentDenialRate: ArenaMetricValue;
  readonly decisionLatency: ArenaStatistics;
  readonly endToEndLatency: ArenaStatistics;
  readonly throughput: ArenaMetricValue;
  readonly unsupportedOutcomes: number;
  readonly unknownOutcomes: number;
}

export interface ArenaMeasurements {
  readonly protected: ArenaPathSummary;
  readonly unprotected: ArenaPathSummary;
  readonly staticAllowlist: ArenaPathSummary;
}

export interface ArenaRunOptions {
  readonly scenarios: readonly ArenaScenario[];
  readonly fixtureRoot?: string;
  readonly metrics?: readonly ArenaMetricName[];
  readonly plan?: { readonly metrics: readonly ArenaMetricName[] };
  readonly repetitions?: number;
  readonly seed?: number;
  readonly environment?: Readonly<Record<string, string | number | boolean | null>>;
  /** Existing adapter. It is called for all three paths when supplied. */
  readonly execute?: (scenario: ArenaScenario, context: ArenaInvocationContext, prepared?: ArenaInvocationResult) => ArenaInvocationResult | Promise<ArenaInvocationResult>;
}

export interface ArenaRun {
  readonly version: 2;
  readonly metrics: ArenaMetrics;
  readonly measurements: ArenaMeasurements;
  readonly outcomes: readonly ArenaOutcome[];
  readonly rawOutcomes: readonly ArenaOutcome[];
  readonly scenarioIds: readonly string[];
  readonly environment: Readonly<Record<string, string | number | boolean | null>>;
  readonly deterministicDigest: string;
  readonly cleanupCompleted: boolean;
  readonly repetitions: number;
  readonly seed: number;
  readonly protectedLatency: ArenaStatistics;
  readonly baselineLatency: ArenaStatistics;
  readonly staticAllowlistLatency: ArenaStatistics;
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

function validateRepetitions(value: number | undefined): number {
  const repetitions = value ?? 3;
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 100) fail("repetitions must be an integer from 1 through 100");
  return repetitions;
}

function validateSeed(value: number | undefined): number {
  const seed = value ?? 0;
  if (!Number.isSafeInteger(seed)) fail("seed must be a safe integer");
  return seed;
}

function validateMeasurements(value: unknown, scenarioId: string): ArenaInvocationMeasurements | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${scenarioId}.measurements must be an object`);
  const result: Record<string, number> = {};
  for (const key of ["unauthorizedUpstreamCalls", "secretSinkCalls", "approvalReplays", "quarantineDetections", "containmentDenials", "decisionLatencyMs"]) {
    const candidate = (value as Record<string, unknown>)[key];
    if (candidate !== undefined) {
      if (typeof candidate !== "number" || !Number.isFinite(candidate) || candidate < 0) fail(`${scenarioId}.measurements.${key} must be a finite non-negative number`);
      result[key] = candidate;
    }
  }
  return result as ArenaInvocationMeasurements;
}

function validateResult(value: unknown, scenarioId: string): ArenaInvocationResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${scenarioId}.invoke must return an object`);
  const candidate = value as Record<string, unknown>;
  if (!(["blocked", "completed", "unknown", "unsupported"] as string[]).includes(candidate.outcome as string)) fail(`${scenarioId}.invoke returned an invalid outcome`);
  if (candidate.support !== undefined && !(["measured", "unknown", "unsupported"] as string[]).includes(candidate.support as string)) fail(`${scenarioId}.support is invalid`);
  if (candidate.reason !== undefined && typeof candidate.reason !== "string") fail(`${scenarioId}.reason must be a string`);
  if (candidate.raw !== undefined) {
    if (candidate.raw === null || typeof candidate.raw !== "object" || Array.isArray(candidate.raw)) fail(`${scenarioId}.raw must be an object`);
    try { JSON.stringify(candidate.raw); } catch { fail(`${scenarioId}.raw must be JSON serializable`); }
  }
  if (candidate.cleanup !== undefined && typeof candidate.cleanup !== "function") fail(`${scenarioId}.cleanup must be a function`);
  const measurements = validateMeasurements(candidate.measurements, scenarioId);
  return { ...candidate as unknown as ArenaInvocationResult, ...(measurements ? { measurements } : {}) };
}

async function invokeScenario(scenario: ArenaScenario, mode: ArenaExecutionMode, fixtureRoot: string, repetition: number, seed: number, execute?: ArenaRunOptions["execute"]): Promise<ArenaInvocationResult> {
  const cleanups: Array<() => void | Promise<void>> = [];
  const context: ArenaInvocationContext = {
    protected: mode === "protected",
    mode,
    baseline: mode === "protected" ? null : mode,
    fixtureRoot,
    repetition,
    seed,
    registerCleanup: cleanup => {
      if (typeof cleanup !== "function") fail(`${scenario.id}.registerCleanup received a non-function`);
      cleanups.push(cleanup);
    },
  };
  try {
    // Preserve the original adapter contract: when `execute` is supplied it
    // owns execution and the legacy scenario callback is not implicitly run.
    // A new adapter may call the callback explicitly when it needs a prepared
    // operation, as the research runner does.
    const invocation = execute ? validateResult(await execute(scenario, context), scenario.id) : validateResult(await scenario.invoke(context), scenario.id);
    if (invocation.cleanup) cleanups.push(invocation.cleanup);
    return invocation;
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup();
  }
}

function expectedMatch(status: ArenaOutcomeStatus, expectedBlocked: boolean): boolean {
  return status === (expectedBlocked ? "blocked" : "completed");
}

function metricValue(numerator: number, denominator: number, unit?: string): ArenaMetricValue {
  return denominator > 0 ? { value: numerator / denominator, status: "measured", numerator, denominator, ...(unit ? { unit } : {}) } : { value: null, status: "unsupported", numerator, denominator, ...(unit ? { unit } : {}) };
}

function numericMetric(results: readonly ArenaPathResult[], key: keyof ArenaInvocationMeasurements): ArenaMetricValue {
  const values = results.map(result => result.measurements?.[key]).filter((value): value is number => value !== undefined);
  if (values.length !== results.length) return { value: null, status: "unsupported" };
  return { value: values.reduce((sum, value) => sum + value, 0), status: "measured" };
}

function rateMetric(results: readonly ArenaPathResult[], key: keyof ArenaInvocationMeasurements): ArenaMetricValue {
  const values = results.map(result => result.measurements?.[key]).filter((value): value is number => value !== undefined);
  if (values.length !== results.length) return { value: null, status: "unsupported" };
  return metricValue(values.reduce((sum, value) => sum + value, 0), results.length);
}

function summarizePath(results: readonly ArenaPathResult[], scenarios: readonly ArenaScenario[]): ArenaPathSummary {
  const scenarioById = new Map(scenarios.map(scenario => [scenario.id, scenario]));
  const attacks = results.filter(result => scenarioById.get(result.raw?.scenarioId as string)?.attack === true);
  const benign = results.filter(result => scenarioById.get(result.raw?.scenarioId as string)?.attack === false);
  const supportedAttacks = attacks.filter(result => result.support === "measured");
  const supportedBenign = benign.filter(result => result.support === "measured");
  const attackSuccesses = supportedAttacks.filter(result => result.outcome === "completed").length;
  const attackBlocks = supportedAttacks.filter(result => result.outcome === "blocked").length;
  const benignCompletions = supportedBenign.filter(result => result.outcome === "completed").length;
  const falsePositives = supportedBenign.filter(result => result.outcome === "blocked").length;
  const falseNegatives = supportedAttacks.filter(result => result.outcome === "completed").length;
  const decisionLatencies = results.map(result => result.measurements?.decisionLatencyMs).filter((value): value is number => value !== undefined);
  const approvalAttempts = results.filter(result => result.raw?.gate === "approval-replay");
  const approvalReplayRate = approvalAttempts.length > 0 ? rateMetric(approvalAttempts, "approvalReplays") : { value: null, status: "unsupported" as const };
  return {
    invocationCount: results.length,
    attackSuccessRate: metricValue(attackSuccesses, supportedAttacks.length),
    attackBlockRate: metricValue(attackBlocks, supportedAttacks.length),
    benignCompletionRate: metricValue(benignCompletions, supportedBenign.length),
    falsePositiveRate: metricValue(falsePositives, supportedBenign.length),
    falseNegativeRate: metricValue(falseNegatives, supportedAttacks.length),
    unauthorizedUpstreamCalls: numericMetric(results, "unauthorizedUpstreamCalls"),
    secretSinkCalls: numericMetric(results, "secretSinkCalls"),
    approvalReplayRate,
    quarantineDetectionRate: numericMetric(results, "quarantineDetections"),
    containmentDenialRate: numericMetric(results, "containmentDenials"),
    decisionLatency: summarize(decisionLatencies),
    endToEndLatency: summarize(results.map(result => result.latencyMs)),
    throughput: results.length > 0 ? { value: results.length / (results.reduce((sum, result) => sum + result.latencyMs, 0) / 1000 || 0.001), status: "measured", unit: "invocations_per_second" } : { value: null, status: "unsupported", unit: "invocations_per_second" },
    unsupportedOutcomes: results.filter(result => result.support === "unsupported").length,
    unknownOutcomes: results.filter(result => result.support === "unknown").length,
  };
}

/** Summarizes finite measurements using nearest-rank percentiles (ceil(p*n), one-indexed). */
export function summarize(values: readonly number[]): ArenaStatistics {
  if (!Array.isArray(values) || values.some(value => !Number.isFinite(value))) fail("statistics values must be finite numbers");
  if (values.length === 0) return { count: 0, mean: 0, median: 0, p95: 0, p99: 0, standardDeviation: 0 };
  const sorted = [...values].sort((left, right) => left - right);
  const percentile = (p: number): number => sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)]!;
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / values.length;
  const middle = Math.floor(sorted.length / 2);
  return {
    count: values.length,
    mean,
    median: sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle]!,
    p95: percentile(0.95),
    p99: percentile(0.99),
    standardDeviation: Math.sqrt(variance),
  };
}

/** Returns bounded, machine-readable JSON with raw per-path outcomes in deterministic order. */
export function formatArenaRun(run: ArenaRun): string {
  return JSON.stringify({
    version: run.version,
    benchmark: "invock-arena",
    scenarioIds: run.scenarioIds,
    seed: run.seed,
    repetitions: run.repetitions,
    environment: run.environment,
    metrics: run.metrics,
    measurements: run.measurements,
    statistics: { protectedLatency: run.protectedLatency, baselineLatency: run.baselineLatency, staticAllowlistLatency: run.staticAllowlistLatency },
    cleanupCompleted: run.cleanupCompleted,
    deterministicDigest: run.deterministicDigest,
    rawOutcomes: run.rawOutcomes,
    outcomes: run.outcomes,
  });
}

/** Runs real local scenario callbacks in deterministic scenario/repetition/path order. */
export async function runArena(options: ArenaRunOptions): Promise<ArenaRun> {
  if (options === null || typeof options !== "object" || !Array.isArray(options.scenarios)) fail("options.scenarios must be an array");
  const metricsToMeasure = selectedMetrics(options);
  const repetitions = validateRepetitions(options.repetitions);
  const seed = validateSeed(options.seed);
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
  const protectedLatencies: number[] = [];
  const baselineLatencies: number[] = [];
  const staticAllowlistLatencies: number[] = [];
  const protectedResults: ArenaPathResult[] = [];
  const baselineResults: ArenaPathResult[] = [];
  const staticAllowlistResults: ArenaPathResult[] = [];
  let cleanupCompleted = true;
  const runPath = async (scenario: ArenaScenario, mode: ArenaExecutionMode, repetition: number): Promise<ArenaPathResult> => {
    const started = performance.now();
    let invocation: ArenaInvocationResult;
    try {
      if (mode === "static-allowlist" && options.execute === undefined) {
        // Still run the callback so fixture setup/cleanup is exercised, but do
        // not mislabel the original callback as a static allowlist baseline.
        await invokeScenario(scenario, mode, fixtureRoot, repetition, seed);
        invocation = { outcome: "unsupported", support: "unsupported", reason: "STATIC_ALLOWLIST_ADAPTER_NOT_SUPPLIED", raw: { adapter: "static-allowlist" } };
      } else {
        invocation = await invokeScenario(scenario, mode, fixtureRoot, repetition, seed, options.execute);
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("ARENA_INVALID_SCENARIO:")) throw error;
      cleanupCompleted = false;
      invocation = { outcome: "blocked", support: "unknown", reason: "CALLBACK_FAILED", raw: { error: "CALLBACK_FAILED" } };
    }
    const latencyMs = performance.now() - started;
    return {
      mode,
      outcome: invocation.outcome,
      support: invocation.support ?? "measured",
      ...(invocation.reason ? { reason: invocation.reason } : {}),
      latencyMs,
      ...(invocation.raw ? { raw: { ...invocation.raw, scenarioId: scenario.id } } : { raw: { scenarioId: scenario.id } }),
      ...(invocation.measurements ? { measurements: invocation.measurements } : {}),
    };
  };

  for (const scenario of options.scenarios) {
    for (let repetition = 1; repetition <= repetitions; repetition += 1) {
      const protectedResult = await runPath(scenario, "protected", repetition);
      const baselineResult = await runPath(scenario, "unprotected", repetition);
      const staticResult = await runPath(scenario, "static-allowlist", repetition);
      protectedResults.push(protectedResult); baselineResults.push(baselineResult); staticAllowlistResults.push(staticResult);
      protectedLatencies.push(protectedResult.latencyMs); baselineLatencies.push(baselineResult.latencyMs); staticAllowlistLatencies.push(staticResult.latencyMs);
      outcomes.push({
        scenarioId: scenario.id,
        ...(scenario.category ? { category: scenario.category } : {}),
        repetition,
        expectedBlocked: scenario.expectedBlocked,
        attack: scenario.attack,
        protected: protectedResult,
        unprotected: baselineResult,
        staticAllowlist: staticResult,
        protectedOutcome: protectedResult.outcome,
        baselineOutcome: baselineResult.outcome,
        unprotectedOutcome: baselineResult.outcome,
        staticAllowlistOutcome: staticResult.outcome,
        protectedLatencyMs: protectedResult.latencyMs,
        baselineLatencyMs: baselineResult.latencyMs,
        staticAllowlistLatencyMs: staticResult.latencyMs,
        protectedMatchesExpectation: expectedMatch(protectedResult.outcome, scenario.expectedBlocked),
        baselineMatchesExpectation: expectedMatch(baselineResult.outcome, scenario.expectedBlocked),
        staticAllowlistMatchesExpectation: expectedMatch(staticResult.outcome, scenario.expectedBlocked),
      });
    }
  }

  const values: Record<ArenaMetricName, number> = {
    scenarioCount: options.scenarios.length,
    attackBlocked: outcomes.filter(item => item.attack && item.protectedOutcome === "blocked").length,
    benignCompleted: outcomes.filter(item => !item.attack && item.protectedOutcome === "completed").length,
    falsePositives: outcomes.filter(item => !item.expectedBlocked && !item.protectedMatchesExpectation).length,
    falseNegatives: outcomes.filter(item => item.expectedBlocked && !item.protectedMatchesExpectation).length,
    cleanupCompleted: cleanupCompleted ? 1 : 0,
    latencyMs: [...protectedLatencies, ...baselineLatencies, ...staticAllowlistLatencies].reduce((sum, value) => sum + value, 0),
  };
  const measured = Object.fromEntries(metricsToMeasure.map(metric => [metric, values[metric]]));
  const measurements: ArenaMeasurements = {
    protected: summarizePath(protectedResults, options.scenarios),
    unprotected: summarizePath(baselineResults, options.scenarios),
    staticAllowlist: summarizePath(staticAllowlistResults, options.scenarios),
  };
  const digestMetrics = Object.fromEntries(Object.entries(measured).filter(([metric]) => metric !== "latencyMs"));
  const digestOutcomes = outcomes.map(outcome => ({
    scenarioId: outcome.scenarioId,
    ...(outcome.category ? { category: outcome.category } : {}),
    repetition: outcome.repetition,
    expectedBlocked: outcome.expectedBlocked,
    attack: outcome.attack,
    paths: [outcome.protected, outcome.unprotected, outcome.staticAllowlist].map(path => ({
      mode: path.mode,
      outcome: path.outcome,
      support: path.support,
      ...(path.reason ? { reason: path.reason } : {}),
      ...(path.raw ? { raw: path.raw } : {}),
      ...(path.measurements ? { measurements: Object.fromEntries(Object.entries(path.measurements).filter(([key]) => key !== "decisionLatencyMs")) } : {}),
    })),
  }));
  const deterministicDigest = digestJson({ seed, repetitions, scenarioIds: options.scenarios.map(scenario => scenario.id), outcomes: digestOutcomes, metrics: digestMetrics });
  const environment = options.environment ?? {};
  return {
    version: 2,
    metrics: measured,
    measurements,
    outcomes,
    rawOutcomes: outcomes,
    scenarioIds: options.scenarios.map(scenario => scenario.id),
    environment,
    deterministicDigest,
    cleanupCompleted,
    repetitions,
    seed,
    protectedLatency: summarize(protectedLatencies),
    baselineLatency: summarize(baselineLatencies),
    staticAllowlistLatency: summarize(staticAllowlistLatencies),
  };
}
