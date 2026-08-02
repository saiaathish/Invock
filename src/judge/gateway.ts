import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { startApi, type ApiAuthorizeInput, type ApiContainedForwardResult, type ApiHandle, type ApiRuntimeResolution } from "../api/server.js";
import { assertCapsule } from "../authority/capsule.js";
import { assertLease } from "../authority/lease.js";
import type { CapabilityLease, IntentCapsule } from "../authority/types.js";
import { compilePolicy, parsePolicyYaml } from "../core/policy.js";
import type { ToolResult } from "../core/types.js";
import { digestJson } from "../core/canonical.js";
import { InvocationGate, StaticDescriptorRegistry } from "../gateway/engine.js";
import { signContainmentRun } from "../containment/lifecycle.js";
import { generateSigningMaterial } from "../storage/receipts.js";
import { InvockClient } from "../sdk/index.js";
import { InvockStore } from "../storage/store.js";

const root = resolve(import.meta.dirname, "../..");
const fixedNow = new Date("2026-08-01T12:00:00.000Z");

export interface JudgeGateway {
  readonly store: InvockStore;
  readonly api: ApiHandle;
  readonly client: InvockClient;
  readonly gate: InvocationGate;
  readonly getLease: (leaseId: string) => CapabilityLease | undefined;
  readonly getUpstreamExecutionCount: () => number;
  readonly getSinkExecutionCount: () => number;
}

function descriptors(): StaticDescriptorRegistry {
  return new StaticDescriptorRegistry({
    read_file: { fields: [{ pointer: "/path", type: "path", access: "read" }] },
    send_email: { fields: [{ pointer: "/to", type: "recipient" }, { pointer: "/body", type: "data" }] },
  });
}

function fakeReadResult(): ToolResult {
  return { content: [{ type: "text", text: "FAKE_REPOSITORY_SUMMARY: documentation improvements" }] };
}

/** Starts the real local API boundary with a fake-only upstream sink. */
export async function startJudgeGateway(): Promise<JudgeGateway> {
  const containmentSigning = generateSigningMaterial();
  const containmentProfile = { sandbox: "judge-fixture", network: "none", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true };
  const trustedContainmentKeys = [{ keyId: containmentSigning.signingKeyId, publicKeyPem: containmentSigning.publicKeyPem }];
  const approvedContainmentProfiles = [{ profileDigest: digestJson(containmentProfile), capabilities: { sandbox: "available" as const, network: "denied" as const, readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } }];
  const store = new InvockStore(":memory:", { trustedContainmentKeys, approvedContainmentProfiles });
  const monitor = new InvocationGate(
    compilePolicy(parsePolicyYaml(readFileSync(resolve(root, "policies/default.yaml"), "utf8"))),
    descriptors(),
    store,
    {
      cwd: root,
      // The judge uses a virtual /workspace namespace for its deterministic
      // fixture. Keep the normalizer's project boundary aligned with that
      // namespace so ordinary fixture files receive the explicit `internal`
      // label instead of falling back to `unknown`.
      projectRoot: "/workspace",
      organizationDomains: ["example.com"],
      sessionId: "judge-session",
      principal: { principalId: "judge-user", clientId: "invock-judge", agentId: "judge-agent", scopes: ["*"] },
      now: () => fixedNow,
    },
    { requireContainment: true, trustedContainmentKeys, approvedContainmentProfiles },
  );

  const leases = new Map<string, CapabilityLease>();
  const leaseSessions = new Map<string, string>();
  let upstreamExecutionCount = 0;
  let sinkExecutionCount = 0;

  const resolveRuntime = async (input: ApiAuthorizeInput): Promise<ApiRuntimeResolution> => {
    if (!input.agent || !input.sessionId || input.intentCapsule === undefined || !input.capabilityLeases) {
      return { denial: { verdict: "BLOCK", reasonCodes: ["JUDGE_AUTHORITY_METADATA_REQUIRED"] } };
    }
    let capsule: IntentCapsule;
    let suppliedLeases: CapabilityLease[];
    try {
      capsule = input.intentCapsule as IntentCapsule;
      assertCapsule(capsule);
      suppliedLeases = input.capabilityLeases.map(value => value as CapabilityLease);
      suppliedLeases.forEach(assertLease);
      if (suppliedLeases.at(-1)?.subject !== input.agent) throw new Error("LEASE_AGENT_MISMATCH");
      suppliedLeases = suppliedLeases.map(lease => {
        const owner = leaseSessions.get(lease.leaseId);
        if (owner && owner !== input.sessionId) throw new Error("LEASE_SESSION_MISMATCH");
        const previous = leases.get(lease.leaseId);
        if (previous && lease.remainingCalls > previous.remainingCalls) throw new Error("LEASE_STATE_REPLAY");
        const effective = previous ?? lease;
        leaseSessions.set(effective.leaseId, input.sessionId!);
        leases.set(effective.leaseId, effective);
        return effective;
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : "MALFORMED_CAPABILITY_LEASE";
      return { denial: { verdict: "BLOCK", reasonCodes: [reason] } };
    }
    return {
      overrides: {
        sessionId: input.sessionId,
        principal: { principalId: input.agent, clientId: "invock-judge-sdk", agentId: input.agent, scopes: ["*"] },
        authority: {
          capsule,
          leases: suppliedLeases,
          sessionId: input.sessionId,
          request: { tool: input.tool, capabilities: [], effects: [], resources: { paths: [], domains: [], recipients: [] }, dataLabels: [] },
          consume: next => next.forEach(lease => leases.set(lease.leaseId, lease)),
        },
      },
    };
  };

  const onContainedForward = async (outcome: Extract<Awaited<ReturnType<InvocationGate["authorizeInvocation"]>>, { kind: "forward" }>): Promise<ApiContainedForwardResult> => {
    upstreamExecutionCount += 1;
    return {
      result: fakeReadResult(),
      containment: signContainmentRun({
        schemaVersion: "invock/containment-run/v2",
        runId: `judge-contained-${outcome.envelope.invocationId}`,
        createdAt: fixedNow.toISOString(),
        requestDigest: digestJson({ command: "judge-fake-contained", argv: [] }),
        authorizedRequestDigest: outcome.envelope.integrity.requestDigest,
        command: "judge-fake-contained",
        invocationId: outcome.envelope.invocationId,
        sessionId: outcome.envelope.sessionId,
        profileDigest: digestJson(containmentProfile),
        result: { status: "completed", stdout: "", stderr: "", durationMs: 1, reasonCodes: [], cleanup: "completed", capabilities: { sandbox: "available", network: "denied", readOnlyRoot: true, nonRoot: true, noNewPrivileges: true } },
      }, containmentSigning),
    };
  };

  try {
    const api = await startApi(store, { token: "judge-local-token", sessionId: "judge-session", gate: monitor, resolveRuntime, onContainedForward });
    return {
      store,
      api,
      client: new InvockClient({ endpoint: api.url, token: api.token }),
      gate: monitor,
      getLease: leaseId => leases.get(leaseId),
      getUpstreamExecutionCount: () => upstreamExecutionCount,
      getSinkExecutionCount: () => sinkExecutionCount,
    };
  } catch (error) {
    store.close();
    throw error;
  }
}

export { fixedNow };
