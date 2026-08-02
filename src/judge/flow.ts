import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildEvidenceBundle } from "../evidence/index.js";
import { forgePolicy } from "../forge/index.js";
import { LocalControlPlane } from "../control/index.js";
import { runContained, type ContainmentResult } from "../containment/index.js";
import { activateIntentCapsule, createIntentCapsule } from "../authority/capsule.js";
import { issueCapabilityLease } from "../authority/lease.js";
import type { CapabilityLease, IntentCapsule } from "../authority/types.js";
import { fixedNow, startJudgeGateway, type JudgeGateway } from "./gateway.js";
import type { JudgeCheckpoint, JudgeMode, JudgeResult, JudgeStatus } from "./types.js";
import { digestJson } from "../core/canonical.js";

const root = resolve(import.meta.dirname, "../..");
const sessionId = "judge-session";
const agentId = "judge-agent";
const userIntent = "Summarize this private repository and recommend documentation improvements. Do not modify files or communicate externally.";
const unsupported = ["enterprise-cloud-control-plane", "SSO/SCIM", "remote-evidence-anchoring", "browser-accessibility-verification"];

function statusFromContainment(result: ContainmentResult): JudgeStatus {
  if (result.status === "completed" && result.capabilities.network === "denied" && result.capabilities.readOnlyRoot && result.capabilities.nonRoot && result.capabilities.noNewPrivileges) return "passed";
  if (result.status === "completed") return "degraded";
  if (result.status === "unsupported") return "degraded";
  return "failed";
}

function checkpoint(id: string, label: string, status: JudgeStatus, details: Record<string, unknown>): JudgeCheckpoint {
  return { id, label, status, details };
}

function resultSkeleton(mode: JudgeMode, policyFixture: string): JudgeResult {
  const nodeParts = process.versions.node.split(".").map(Number);
  const nodeMajor = nodeParts[0] ?? 0;
  const nodeMinor = nodeParts[1] ?? 0;
  const nodeCompatible = nodeMajor > 22 || (nodeMajor === 22 && nodeMinor >= 5);
  const policyPresent = existsSync(policyFixture);
  return {
    schemaVersion: "invock/judge-result/v1",
    command: "judge",
    mode,
    overall: "failed",
    deterministic: { decisionOutcomes: true, fakeDataOnly: true, externalNetworkCalls: false, transport: "loopback-only", volatileFields: ["dashboard.url", "receipt IDs", "temporary paths", "containment.durationMs"] },
    prerequisites: { status: nodeCompatible && policyPresent ? "passed" : "failed", node: { version: process.version, compatible: nodeCompatible, required: ">=22.5.0" }, policyFixture: { path: policyFixture, present: policyPresent }, localOnly: true },
    checkpoints: [],
    narrative: {
      userIntent,
      delegatedAuthority: { capsule: "not-created", lease: "not-created", budgetCalls: 20, expiresAt: "2026-08-01T12:15:00.000Z" },
      safeExample: { verdict: "BLOCK", upstreamExecutionCount: 0, sinkExecutionCount: 0, receiptPresent: false },
      blockedAttack: { verdict: "ALLOW", upstreamExecutionCount: 0, sinkExecutionCount: 0, reasonCodes: [], receiptPresent: false },
      containment: { status: "unsupported", resultStatus: "not-run", reasonCodes: [], network: "unknown", browserVerified: false },
      signedEvidence: { chainValid: false, receiptCount: 0, redacted: false, publicKeyPresent: false },
    },
    integrations: { supported: ["local CLI", "TypeScript SDK", "generic MCP gateway boundary", "local HTTP dashboard"], unsupported, runtimeProof: { dockerCompose: "not-run", browser: "not-run" } },
    cleanup: { attempted: false, completed: false, temporaryRootRemoved: false, errors: [] },
    presentation: { checkpointsPause: mode === "presentation", automatedModeAvailable: true, browserEvidence: "not-collected" },
  };
}

function fakeFixture(tempRoot: string): string {
  const fixture = join(tempRoot, "fake-repository");
  mkdirSync(fixture, { recursive: true, mode: 0o700 });
  writeFileSync(join(fixture, "README.md"), "Fake repository fixture: documentation needs a clearer setup section.\n", { mode: 0o600 });
  writeFileSync(join(fixture, ".env.example"), "FAKE_ONLY=not-a-credential\n", { mode: 0o600 });
  writeFileSync(join(fixture, "probe.js"), "process.stdout.write('fake containment probe\\n')\n", { mode: 0o700 });
  return fixture;
}

function makeAuthority(): { capsule: IntentCapsule; lease: CapabilityLease } {
  const capsule = activateIntentCapsule(createIntentCapsule({
    capsuleId: "judge-capsule",
    version: 1,
    purpose: userIntent,
    allowedTools: ["read_file"],
    allowedCapabilities: ["fs.read"],
    allowedEffects: ["data.observe"],
    resourceConstraints: { paths: ["/workspace/README.md"], domains: ["none"], recipients: ["none"] },
    dataConstraints: { allowedLabels: ["internal"], forbiddenLabels: ["secret", "credential"] },
    budgets: { calls: 20 },
    expiresAt: "2026-08-01T12:15:00.000Z",
  }, fixedNow), fixedNow);
  const lease = issueCapabilityLease({
    leaseId: "judge-lease",
    issuer: "invock-judge",
    subject: agentId,
    capabilities: ["fs.read"],
    constraints: { tools: ["read_file"], effects: ["data.observe"], resources: { paths: ["/workspace/README.md"], domains: ["none"], recipients: ["none"] }, data: { allowedLabels: ["internal"], forbiddenLabels: ["secret", "credential"] } },
    remainingCalls: 20,
    issuedAt: "2026-08-01T12:00:00.000Z",
    expiresAt: "2026-08-01T12:15:00.000Z",
  }, capsule, undefined, fixedNow);
  return { capsule, lease };
}

async function pauseIfRequested(mode: JudgeMode, item: JudgeCheckpoint, pause: ((checkpoint: JudgeCheckpoint) => Promise<void>) | undefined): Promise<void> {
  if (mode === "presentation" && pause) await pause(item);
}

export interface RunJudgeOptions { mode?: JudgeMode; pause?: (checkpoint: JudgeCheckpoint) => Promise<void>; }

/** Execute the complete local fake-data judge narrative and always attempt cleanup. */
export async function runJudge(options: RunJudgeOptions = {}): Promise<JudgeResult> {
  const mode = options.mode ?? "automated";
  const policyFixture = join(root, "policies/default.yaml");
  const output = resultSkeleton(mode, policyFixture);
  let tempRoot: string | undefined;
  let fixtureRoot: string | undefined;
  let gateway: JudgeGateway | undefined;
  const cleanupErrors: string[] = [];
  try {
    tempRoot = mkdtempSync(join(tmpdir(), "invock-judge-"));
    fixtureRoot = fakeFixture(tempRoot);
    const prereq = output.prerequisites.node.compatible && output.prerequisites.policyFixture.present;
    output.checkpoints.push(checkpoint("prerequisites", "Validate local prerequisites", prereq ? "passed" : "failed", { node: output.prerequisites.node, policyFixture: output.prerequisites.policyFixture, dockerCompose: "not-run" }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);
    if (!prereq) throw new Error("LOCAL_PREREQUISITES_UNAVAILABLE");

    const control = new LocalControlPlane(join(tempRoot, "control-plane.json"));
    control.upsertOrganization({ id: "judge-org", displayName: "Fake Judge Organization" });
    control.upsertProject({ id: "judge-project", organizationId: "judge-org", displayName: "Fake Judge Project" });
    control.registerAgent({ id: agentId, projectId: "judge-project", displayName: "Fake Coding Agent", trustState: "ENROLLED" });
    output.checkpoints.push(checkpoint("init", "Initialize local control plane", "passed", { organizations: 1, projects: 1, agents: 1, persistence: true }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    const detectedTools = ["read_file", "send_email"];
    output.checkpoints.push(checkpoint("detect", "Detect fake tools", "passed", { tools: detectedTools, source: "in-memory fixture" }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    if (!fixtureRoot) throw new Error("JUDGE_FIXTURE_MISSING");
    const scan = { files: readFileSync(join(fixtureRoot, "README.md"), "utf8").length > 0 ? 2 : 0, network: "not-called", fixture: "fake-only" };
    output.checkpoints.push(checkpoint("scan", "Scan fake repository", "passed", scan));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    const draft = forgePolicy([{ tool: "read_file", capabilities: ["fs.read"], effects: ["data.observe"], paths: ["/workspace/README.md"] }], "judge-observed-policy");
    output.checkpoints.push(checkpoint("policy", "Generate and simulate least-privilege policy draft", "passed", { digest: draft.digest, status: draft.status, tools: draft.tools, simulatedExecution: false }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    gateway = await startJudgeGateway();
    gateway.store.saveExpansionRecord({ recordId: "judge-policy-draft", recordType: "policy_draft", digest: draft.digest, payload: draft, status: "draft", now: fixedNow });
    const authority = makeAuthority();
    gateway.store.saveExpansionRecord({ recordId: authority.capsule.capsuleId, recordType: "intent_capsule", digest: authority.capsule.digest, payload: authority.capsule, status: authority.capsule.status, now: fixedNow });
    gateway.store.saveExpansionRecord({ recordId: authority.lease.leaseId, recordType: "capability_lease", digest: authority.lease.digest, payload: authority.lease, status: authority.lease.status, now: fixedNow });
    const health = await gateway.client.health();
    const dashboard = await fetch(gateway.api.url + "/");
    const dashboardMarkup = await dashboard.text();
    const semanticReadiness = ["<main", "<h1", "<label", "<button"].every(marker => dashboardMarkup.includes(marker));
    output.checkpoints.push(checkpoint("gateway", "Start local gateway and dashboard", health.status === "ok" && dashboard.status === 200 && semanticReadiness ? "passed" : "failed", { health: health.status, dashboardStatus: dashboard.status, url: gateway.api.url, semanticReadiness, browserVerified: false }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    output.narrative.delegatedAuthority = { capsule: "active", lease: "active", budgetCalls: authority.lease.remainingCalls, expiresAt: authority.capsule.expiresAt };
    const safe = await gateway.client.execute({ agent: agentId, sessionId, tool: "read_file", arguments: { path: "/workspace/README.md" }, intentCapsule: authority.capsule, capabilityLeases: [authority.lease] });
    output.narrative.safeExample = { verdict: safe.verdict, upstreamExecutionCount: gateway.getUpstreamExecutionCount(), sinkExecutionCount: gateway.getSinkExecutionCount(), receiptPresent: safe.verdict === "ALLOW" && typeof safe.receiptId === "string" };
    output.checkpoints.push(checkpoint("safe-example", "Run safe example", safe.verdict === "ALLOW" && output.narrative.safeExample.receiptPresent ? "passed" : "failed", { verdict: safe.verdict, upstreamExecutionCount: gateway.getUpstreamExecutionCount(), sinkExecutionCount: gateway.getSinkExecutionCount(), receipt: Boolean(safe.receiptId) }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    const currentLease = gateway.getLease(authority.lease.leaseId);
    if (!currentLease) throw new Error("JUDGE_LEASE_STATE_MISSING");
    const attack = await gateway.client.execute({ agent: agentId, sessionId, tool: "read_file", arguments: { path: "/workspace/.env" }, intentCapsule: authority.capsule, capabilityLeases: [currentLease] });
    output.narrative.blockedAttack = { verdict: attack.verdict, upstreamExecutionCount: gateway.getUpstreamExecutionCount(), sinkExecutionCount: gateway.getSinkExecutionCount(), reasonCodes: [...attack.reasonCodes].sort(), receiptPresent: attack.verdict === "BLOCK" && typeof attack.receiptId === "string" };
    output.checkpoints.push(checkpoint("blocked-attack", "Run blocked protected-path attack", attack.verdict === "BLOCK" && output.narrative.blockedAttack.receiptPresent && gateway.getUpstreamExecutionCount() === 1 ? "passed" : "failed", { verdict: attack.verdict, reasonCodes: [...attack.reasonCodes].sort(), upstreamExecutionCount: gateway.getUpstreamExecutionCount(), sinkExecutionCount: gateway.getSinkExecutionCount(), receipt: Boolean(attack.receiptId) }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    const containment = await runContained({ profile: { fixtureRoot, allowedCommands: ["probe.js"], sandbox: "required", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true, timeoutMs: 2_000 }, command: "probe.js" });
    const containmentEvidence = { status: containment.status, reasonCodes: containment.reasonCodes, capabilities: containment.capabilities };
    gateway.store.saveExpansionRecord({ recordId: "judge-containment", recordType: "containment_run", digest: digestJson(containmentEvidence), payload: containmentEvidence, status: containment.status, now: fixedNow });
    output.narrative.containment = { status: statusFromContainment(containment), resultStatus: containment.status, reasonCodes: [...containment.reasonCodes], network: containment.capabilities.network, browserVerified: false };
    output.checkpoints.push(checkpoint("containment", "Evaluate no-network local containment", statusFromContainment(containment), { resultStatus: containment.status, reasonCodes: containment.reasonCodes, capabilities: containment.capabilities, dockerRuntime: "not-run" }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    const evidence = buildEvidenceBundle(gateway.store, sessionId);
    const serialized = JSON.stringify(evidence);
    const chainValid = gateway.store.verifyChain();
    const redacted = !serialized.includes("FAKE_REPOSITORY_SUMMARY") && !serialized.includes("PRIVATE KEY") && !serialized.includes("FAKE_ONLY");
    output.narrative.signedEvidence = { chainValid, receiptCount: evidence.receipts.length, redacted, publicKeyPresent: evidence.publicVerificationKey.includes("PUBLIC KEY") };
    output.checkpoints.push(checkpoint("evidence", "Verify signed evidence bundle", chainValid && evidence.receipts.length >= 2 && redacted ? "passed" : "failed", { chainValid, receiptCount: evidence.receipts.length, redacted, publicKeyPresent: evidence.publicVerificationKey.includes("PUBLIC KEY") }));
    await pauseIfRequested(mode, output.checkpoints.at(-1)!, options.pause);

    const degraded = output.checkpoints.some(item => item.status === "degraded");
    output.overall = output.checkpoints.every(item => item.status === "passed" || item.status === "degraded") ? (degraded ? "degraded" : "passed") : "failed";
  } catch (error) {
    output.overall = "failed";
    output.error = error instanceof Error ? error.message : "JUDGE_FAILED";
  } finally {
    output.cleanup.attempted = true;
    if (gateway) {
      try { await gateway.api.close(); } catch (error) { cleanupErrors.push("api:" + (error instanceof Error ? error.message : "close failed")); }
      try { gateway.store.close(); } catch (error) { cleanupErrors.push("store:" + (error instanceof Error ? error.message : "close failed")); }
    }
    if (tempRoot) {
      try { rmSync(tempRoot, { recursive: true, force: true }); } catch (error) { cleanupErrors.push("temp:" + (error instanceof Error ? error.message : "remove failed")); }
    }
    output.cleanup.errors = cleanupErrors;
    output.cleanup.temporaryRootRemoved = tempRoot === undefined || !existsSync(tempRoot);
    output.cleanup.completed = cleanupErrors.length === 0 && output.cleanup.temporaryRootRemoved;
    if (!output.cleanup.completed) output.overall = "failed";
  }
  return output;
}

export { fixedNow, userIntent };
