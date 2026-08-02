import { canonicalize, digestJson, newId } from "../core/canonical.js";
import { fingerprintSensitiveValue, matchSensitiveValue } from "../core/lineage.js";
import { normalizeInvocation, type NormalizationContext, type NormalizationDescriptor } from "../core/normalize.js";
import { evaluatePolicy, type CompiledPolicy } from "../core/policy.js";
import type { ActionEnvelope, PolicyDecision, Principal, ToolCallRequest, ToolResult } from "../core/types.js";
import { InvockStore, type PendingApproval } from "../storage/store.js";
import { evaluateMonotonicAuthority } from "../authority/evaluate.js";
import { assertAuthorityBinding, type AuthorityBinding, type TrustedApproverKeys } from "../authority/binding.js";
import type { AuthorityRequest, CapabilityLease, IntentCapsule } from "../authority/types.js";
import { assertIdentityEvidenceBinding, IdentityAuthority } from "../identity/authority.js";
import type { IdentityEvidenceBinding, IdentityRuntimeContext } from "../identity/types.js";
import { verifyContainmentRun, type ApprovedContainmentProfile, type ContainmentRunRecord, type TrustedContainmentKeys } from "../containment/lifecycle.js";

export interface DescriptorRegistry { get(toolName: string): NormalizationDescriptor | undefined; schemaDigest(toolName: string): string; descriptorDigest(toolName: string): string; registryVersion?(toolName: string): string; isQuarantined?(toolName: string): boolean; observeToolsList?(value: unknown): void; }
export interface ForwardedCall { kind: "forward"; request: ToolCallRequest; envelope: ActionEnvelope; decision: PolicyDecision; approvalId?: string; receiptMetadata?: Parameters<InvockStore["complete"]>[6]; /** Production forwards must attach a signed containment run before execution. */ containmentRequired: boolean; }
export interface RespondedCall { kind: "respond"; response: { jsonrpc: "2.0"; id: string | number; result: ToolResult }; }
export interface NotificationOutcome { kind: "notification"; decision: PolicyDecision; receiptId: string; request?: ToolCallRequest; }
export type GateOutcome = ForwardedCall | RespondedCall | NotificationOutcome;
export interface InvocationGateOptions { requireAuthority?: boolean; requireIdentity?: boolean; requireContainment?: boolean; allowUnboundForTests?: boolean; trustedApproverKeys?: TrustedApproverKeys; trustedContainmentKeys?: TrustedContainmentKeys; approvedContainmentProfiles?: readonly ApprovedContainmentProfile[]; authorityResolver?: (request: ToolCallRequest) => InvocationRuntimeOverrides["authority"] | Promise<InvocationRuntimeOverrides["authority"]>; }
export interface InvocationRuntimeOverrides { sessionId?: string; projectId?: string; protocolEra?: string; principal?: Principal; identityBinding?: IdentityEvidenceBinding; identityAuthority?: IdentityAuthority; identityContext?: IdentityRuntimeContext; authority?: { capsule: IntentCapsule; leases: readonly CapabilityLease[]; request: AuthorityRequest; binding?: AuthorityBinding; sessionId?: string; consume?: (leases: readonly CapabilityLease[]) => void } | undefined; }

function errorResult(text: string, verdict: "BLOCK" | "APPROVAL_REQUIRED", receiptId: string, reasonCodes: string[], approval?: PendingApproval): ToolResult {
  return {
    content: [{ type: "text", text }], isError: true,
    structuredContent: { verdict, reasonCodes, receiptId, retryable: verdict === "APPROVAL_REQUIRED", ...(approval ? { approvalId: approval.approvalId, approvalBindingDigest: approval.bindingDigest, expiresAt: approval.expiresAt } : {}) },
    _meta: { "io.invock/decision": verdict, "io.invock/receipt-id": receiptId, ...(approval ? { "io.invock/approval-id": approval.approvalId } : {}) },
  };
}
function approvedDecision(decision: PolicyDecision): PolicyDecision { return { ...decision, decisionId: newId("dec"), verdict: "ALLOW", reasonCodes: [...new Set([...decision.reasonCodes, "APPROVED_ONE_TIME"])].sort(), obligations: [], retryable: false }; }
function blockedDecision(decision: PolicyDecision, reason: string): PolicyDecision { return { ...decision, decisionId: newId("dec"), verdict: "BLOCK", reasonCodes: [...new Set([...decision.reasonCodes, reason])].sort(), obligations: [], retryable: false }; }

function extractTextArguments(value: unknown, output: string[] = []): string[] {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) value.forEach(item => extractTextArguments(item, output));
  else if (value !== null && typeof value === "object") Object.values(value as Record<string, unknown>).forEach(item => extractTextArguments(item, output));
  return output;
}

function validateToolParameters(request: ToolCallRequest): void {
  const params = request.params as Record<string, unknown>;
  for (const key of Object.keys(params)) if (key !== "name" && key !== "arguments" && key !== "_meta") throw new Error(`UNMODELED_ARGUMENT: /params/${key}`);
  if (typeof params.name !== "string" || params.name.length === 0) throw new Error("INVALID_TOOL_PARAMS");
  if (params.arguments !== undefined && (params.arguments === null || Array.isArray(params.arguments) || typeof params.arguments !== "object")) throw new Error("INVALID_TOOL_PARAMS");
  if (params._meta !== undefined) {
    if (params._meta === null || Array.isArray(params._meta) || typeof params._meta !== "object") throw new Error("INVALID_TOOL_PARAMS");
    const meta = params._meta as Record<string, unknown>;
    for (const key of Object.keys(meta)) if (key !== "io.invock/approval-id") throw new Error(`UNMODELED_ARGUMENT: /params/_meta/${key}`);
    if (meta["io.invock/approval-id"] !== undefined && typeof meta["io.invock/approval-id"] !== "string") throw new Error("INVALID_TOOL_PARAMS");
  }
}

function failureEnvelope(request: ToolCallRequest, context: NormalizationContext, error: unknown): ActionEnvelope {
  const argumentsValue = request.params.arguments ?? {};
  return {
    envelopeVersion: "1.0", invocationId: newId("inv"), requestId: String(request.id ?? "notification"), sessionId: context.sessionId, timestamp: (context.now?.() ?? new Date()).toISOString(), subject: context.principal,
    target: { serverId: context.serverId ?? "default", toolName: request.params.name, toolSchemaDigest: context.schemaDigest, toolDescriptorDigest: context.descriptorDigest, registryVersion: context.registryVersion ?? "registry_unknown", protocolEra: context.protocolEra ?? "2025-11-25" },
    raw: { protocolMethod: "tools/call", argumentBytes: Buffer.byteLength(JSON.stringify(argumentsValue)), argumentKeys: argumentsValue !== null && !Array.isArray(argumentsValue) && typeof argumentsValue === "object" ? Object.keys(argumentsValue).sort() : [] }, capabilities: ["unknown"], effects: ["unknown"], resources: [], labels: [], lineage: [], riskSignals: ["NORMALIZATION_FAILURE"], uncertainty: [error instanceof Error ? error.message.slice(0, 256) : "NORMALIZATION_FAILURE"],
    integrity: { argumentsDigest: digestJson(argumentsValue), requestDigest: digestJson(request), policyVersionId: context.policyVersionId, normalizerVersion: "1.0" },
  };
}

/** Security orchestration. The only API that returns `forward` is this method after persistence and authorization. */
export class InvocationGate {
  private readonly options: InvocationGateOptions;
  private readonly testEscape: boolean;

  constructor(private readonly policy: CompiledPolicy, private readonly descriptors: DescriptorRegistry, private readonly store: InvockStore, private readonly contextBase: Omit<NormalizationContext, "lineage" | "schemaDigest" | "descriptorDigest" | "policyVersionId">, options: InvocationGateOptions = {}) {
    const testEscape = options.allowUnboundForTests === true && process.env.INVOCK_TEST_MODE === "1";
    this.testEscape = testEscape;
    // Production gates are always containment-required. The only uncontained
    // fixture path is explicit, test-mode-only, and therefore cannot be
    // enabled by a production caller passing `requireContainment: false`.
    this.options = { ...options, requireAuthority: testEscape ? false : true, requireIdentity: testEscape ? false : true, requireContainment: testEscape ? options.requireContainment === true : true };
  }

  /** Canonical, non-bypassable authorization entry point for every supported tools/call. */
  async authorizeInvocation(request: ToolCallRequest, overrides: InvocationRuntimeOverrides = {}): Promise<GateOutcome> {
    const callerSuppliedReceiptMetadata = Object.prototype.hasOwnProperty.call(overrides as object, "receiptMetadata");
    let runtimeBase = { ...this.contextBase, ...overrides };
    if (!this.store.isReady()) {
      const now = runtimeBase.now?.() ?? new Date();
      const context: NormalizationContext = { ...runtimeBase, lineage: [], policyVersionId: this.policy.policyVersionId, schemaDigest: this.descriptors.schemaDigest(request.params.name), descriptorDigest: this.descriptors.descriptorDigest(request.params.name), registryVersion: this.descriptors.registryVersion?.(request.params.name) ?? "registry_unknown" };
      const envelope = failureEnvelope(request, context, new Error("RECEIPT_CHAIN_CORRUPT"));
      const decision = blockedDecision(evaluatePolicy(this.policy, envelope, now), "RECEIPT_CHAIN_CORRUPT");
      if (request.id === undefined) return { kind: "notification", decision, receiptId: "unavailable" };
      return { kind: "respond", response: { jsonrpc: "2.0", id: request.id, result: errorResult("Invock is not ready because receipt integrity verification failed.", "BLOCK", "unavailable", decision.reasonCodes) } };
    }
    if (!runtimeBase.authority && this.options.authorityResolver) {
      const resolved = await this.options.authorityResolver(request);
      if (resolved) runtimeBase = { ...runtimeBase, authority: resolved };
    }
    const descriptor = this.descriptors.get(request.params.name);
    const now = runtimeBase.now?.() ?? new Date();
    const lineage = extractTextArguments(request.params.arguments ?? {}).flatMap(value => matchSensitiveValue(value, this.store.taintKey, this.store.activeFingerprints(runtimeBase.sessionId, now)));
    const context: NormalizationContext = { ...runtimeBase, lineage, policyVersionId: this.policy.policyVersionId, schemaDigest: this.descriptors.schemaDigest(request.params.name), descriptorDigest: this.descriptors.descriptorDigest(request.params.name), registryVersion: this.descriptors.registryVersion?.(request.params.name) ?? "registry_static" };
    let envelope: ActionEnvelope;
    let decision: PolicyDecision;
    let authorityLeaseToConsume: CapabilityLease | undefined;
    let authoritativeLeases: readonly CapabilityLease[] | undefined;
    let authoritativeSessionId: string | undefined;
    let receiptMetadata: Parameters<InvockStore["complete"]>[6] = { ...(runtimeBase.protocolEra ? { protocolProfileId: runtimeBase.protocolEra } : {}) };
    try {
      if (callerSuppliedReceiptMetadata) throw new Error("RECEIPT_METADATA_UNTRUSTED");
      if (runtimeBase.identityBinding) {
        assertIdentityEvidenceBinding(runtimeBase.identityBinding);
        if (!runtimeBase.identityAuthority || !runtimeBase.identityContext) throw new Error("IDENTITY_AUTHORITY_REQUIRED");
        const verifiedBinding = runtimeBase.identityAuthority.evidenceBinding(runtimeBase.identityContext.identity, runtimeBase.identityContext.session, now);
        if (verifiedBinding.bindingDigest !== runtimeBase.identityBinding.bindingDigest || verifiedBinding.identityDigest !== runtimeBase.identityBinding.identityDigest || verifiedBinding.sessionDigest !== runtimeBase.identityBinding.sessionDigest || verifiedBinding.projectDigest !== runtimeBase.identityBinding.projectDigest || verifiedBinding.agentDigest !== runtimeBase.identityBinding.agentDigest) throw new Error("IDENTITY_BINDING_MISMATCH");
        const runtimeAgentId = runtimeBase.principal.agentId ?? runtimeBase.principal.principalId;
        if (runtimeAgentId !== runtimeBase.identityContext.identity.id) throw new Error("IDENTITY_PRINCIPAL_MISMATCH");
        if (runtimeBase.sessionId !== runtimeBase.identityContext.session.id) throw new Error("IDENTITY_SESSION_MISMATCH");
        if (runtimeBase.projectId !== runtimeBase.identityContext.identity.projectId) throw new Error("IDENTITY_PROJECT_MISMATCH");
        const attestation = runtimeBase.identityAuthority.verifyExecutionTrust(runtimeBase.identityContext.identity.id, now);
        receiptMetadata = { ...receiptMetadata, identityDigest: runtimeBase.identityBinding.identityDigest, sessionDigest: runtimeBase.identityBinding.sessionDigest, projectDigest: runtimeBase.identityBinding.projectDigest, agentDigest: runtimeBase.identityBinding.agentDigest, identityBindingDigest: runtimeBase.identityBinding.bindingDigest, attestationDigest: digestJson(attestation) };
      } else if (runtimeBase.identityAuthority || runtimeBase.identityContext) {
        throw new Error("IDENTITY_BINDING_REQUIRED");
      }
      if (this.options.requireAuthority && runtimeBase.authority?.capsule.authorityBinding && !runtimeBase.identityBinding) throw new Error("IDENTITY_BINDING_REQUIRED");
      validateToolParameters(request);
      if (!descriptor) throw new Error("UNKNOWN_TOOL_DESCRIPTOR");
      if (this.descriptors.isQuarantined?.(request.params.name)) throw new Error("TOOL_QUARANTINED");
      if (this.options.requireAuthority && !runtimeBase.authority) throw new Error("STRICT_AUTHORITY_REQUIRED");
      if (this.options.requireIdentity && !runtimeBase.identityBinding) throw new Error("IDENTITY_BINDING_REQUIRED");
      if (!this.testEscape && this.options.requireAuthority && (!runtimeBase.authority?.capsule.authorityBinding || !runtimeBase.authority.capsule.humanActivation)) throw new Error("BOUND_HUMAN_AUTHORITY_REQUIRED");
      envelope = await normalizeInvocation(request, descriptor, context);
      decision = evaluatePolicy(this.policy, envelope, now);
      if (runtimeBase.authority) {
        if (runtimeBase.authority.sessionId !== undefined && runtimeBase.authority.sessionId !== runtimeBase.sessionId) throw new Error("AUTHORITY_SESSION_MISMATCH");
        const capsuleBinding = runtimeBase.authority.capsule.authorityBinding;
        const suppliedBinding = runtimeBase.authority.binding;
        if (capsuleBinding) {
          assertAuthorityBinding(capsuleBinding);
          if (!suppliedBinding) throw new Error("AUTHORITY_BINDING_REQUIRED");
          assertAuthorityBinding(suppliedBinding);
          if (suppliedBinding.bindingDigest !== capsuleBinding.bindingDigest) throw new Error("AUTHORITY_BINDING_MISMATCH");
          if (runtimeBase.principal.agentId !== capsuleBinding.agentId) throw new Error("AUTHORITY_AGENT_MISMATCH");
          if (runtimeBase.sessionId !== capsuleBinding.sessionId) throw new Error("AUTHORITY_SESSION_MISMATCH");
          if (runtimeBase.projectId !== capsuleBinding.projectId) throw new Error("AUTHORITY_PROJECT_MISMATCH");
          if (capsuleBinding.policyVersionId !== this.policy.policyVersionId || capsuleBinding.policyDigest !== this.policy.policyDigest) throw new Error("AUTHORITY_POLICY_MISMATCH");
        } else if (suppliedBinding || runtimeBase.authority.request.authorityBindingDigest !== undefined) {
          throw new Error("AUTHORITY_BINDING_UNEXPECTED");
        }
        const resources = {
          paths: envelope.resources.filter(item => item.kind === "path").map(item => item.absolutePath),
          domains: envelope.resources.filter(item => item.kind === "url").map(item => item.hostname),
          recipients: envelope.resources.filter(item => item.kind === "recipient").map(item => item.normalized),
        };
        if (capsuleBinding && (capsuleBinding.registryVersion !== envelope.target.registryVersion || capsuleBinding.toolSchemaDigest !== envelope.target.toolSchemaDigest)) throw new Error("AUTHORITY_TOOL_CONTEXT_MISMATCH");
        if (runtimeBase.authority.request.authorityBindingDigest !== undefined && runtimeBase.authority.request.authorityBindingDigest !== capsuleBinding?.bindingDigest) throw new Error("AUTHORITY_BINDING_MISMATCH");
        authoritativeSessionId = runtimeBase.authority.sessionId ?? runtimeBase.sessionId;
        if (!authoritativeSessionId) throw new Error("AUTHORITY_SESSION_REQUIRED");
        authoritativeLeases = this.store.authorizeAuthorityState(runtimeBase.authority.capsule, runtimeBase.authority.leases, authoritativeSessionId, now, this.options.trustedApproverKeys);
        const actualRequest: AuthorityRequest = { ...runtimeBase.authority.request, runtimeSubject: runtimeBase.principal.agentId ?? runtimeBase.principal.principalId, tool: envelope.target.toolName, capabilities: envelope.capabilities, effects: envelope.effects, resources, dataLabels: envelope.labels, bytes: envelope.raw.argumentBytes, ...(capsuleBinding ? { authorityBindingDigest: capsuleBinding.bindingDigest } : {}) };
        const authority = evaluateMonotonicAuthority(runtimeBase.authority.capsule, authoritativeLeases, actualRequest, now, this.options.trustedApproverKeys);
        receiptMetadata = { ...receiptMetadata, intentCapsuleDigest: runtimeBase.authority.capsule.digest, capabilityLeaseChainDigest: digestJson(authoritativeLeases.map(lease => lease.digest)), effectiveAuthorityDigest: authority.effectiveDigest, ...(capsuleBinding ? { authorityBindingDigest: capsuleBinding.bindingDigest } : {}) };
        if (!authority.allowed) decision = blockedDecision(decision, "EFFECTIVE_AUTHORITY_DENIED");
        else if (authoritativeLeases.length > 0) authorityLeaseToConsume = authoritativeLeases[authoritativeLeases.length - 1];
      }
    } catch (error) {
      envelope = failureEnvelope(request, context, error);
      const reason = error instanceof Error && error.message.includes("UNMODELED_ARGUMENT") ? "UNMODELED_ARGUMENT" : error instanceof Error && error.message.includes("TOOL_QUARANTINED") ? "TOOL_QUARANTINED" : error instanceof Error && error.message.includes("UNKNOWN_TOOL_DESCRIPTOR") ? "UNKNOWN_TOOL" : error instanceof Error && error.message.includes("UNKNOWN_NORMALIZER") ? "UNKNOWN_NORMALIZER" : "NORMALIZATION_FAILED";
      const identityReason = error instanceof Error && (/^IDENTITY_/u.test(error.message) || /Identity evidence|identityDigest|sessionDigest|projectDigest|agentDigest|bindingDigest/u.test(error.message)) ? "IDENTITY_BINDING_INVALID" : reason;
      const strictAuthorityReason = error instanceof Error && /^STRICT_/u.test(error.message) ? error.message.slice(0, 128) : undefined;
      const boundAuthorityReason = runtimeBase.authority?.capsule.authorityBinding && error instanceof Error && /^(AUTHORITY_|LEASE_)/u.test(error.message) ? error.message.slice(0, 128) : identityReason;
      decision = blockedDecision(evaluatePolicy(this.policy, envelope, now), strictAuthorityReason ?? boundAuthorityReason);
    }
    if (decision.verdict === "APPROVAL_REQUIRED" && request.id === undefined) {
      const blocked = blockedDecision(decision, "NOTIFICATION_APPROVAL_UNSUPPORTED");
      this.store.recordInterception(envelope, blocked, now);
      const receipt = this.store.complete(envelope, blocked, false, { blocked: true, notification: true }, undefined, now, receiptMetadata);
      return { kind: "notification", decision: blocked, receiptId: receipt.payload.receiptId };
    }
    if (decision.verdict === "ALLOW") {
      if (runtimeBase.authority && authorityLeaseToConsume && authoritativeSessionId && authoritativeLeases) {
        const nextLease = this.store.consumeAuthorityLease(authorityLeaseToConsume, authoritativeSessionId, now);
        runtimeBase.authority.consume?.([...authoritativeLeases.slice(0, -1), nextLease]);
      }
      this.store.recordInterception(envelope, decision, now);
      const canonicalArguments = JSON.parse(canonicalize(request.params.arguments ?? {})) as Record<string, unknown>;
      const approvalId = request.params._meta?.["io.invock/approval-id"];
      const authorizedRequest = { ...request, params: { name: request.params.name, arguments: canonicalArguments, ...(typeof approvalId === "string" ? { _meta: { "io.invock/approval-id": approvalId } } : {}) } };
      return { kind: "forward", request: authorizedRequest, envelope, decision, receiptMetadata, containmentRequired: this.options.requireContainment === true };
    }
    if (decision.verdict === "BLOCK") {
      this.store.recordInterception(envelope, decision, now); const receipt = this.store.complete(envelope, decision, false, { blocked: true }, undefined, now, receiptMetadata);
      if (request.id === undefined) return { kind: "notification", decision, receiptId: receipt.payload.receiptId };
      return { kind: "respond", response: { jsonrpc: "2.0", id: request.id, result: errorResult(`Invock blocked this action: ${decision.reasonCodes.join(", ") || "policy denied"}.`, "BLOCK", receipt.payload.receiptId, decision.reasonCodes) } };
    }
    const suppliedApproval = request.params._meta?.["io.invock/approval-id"];
    if (typeof suppliedApproval === "string") {
      const allowed = approvedDecision(decision);
      if (this.store.consumeApproval(suppliedApproval, envelope, decision, allowed, now)) {
        if (runtimeBase.authority && authorityLeaseToConsume && authoritativeSessionId && authoritativeLeases) {
          const nextLease = this.store.consumeAuthorityLease(authorityLeaseToConsume, authoritativeSessionId, now);
          runtimeBase.authority.consume?.([...authoritativeLeases.slice(0, -1), nextLease]);
        }
        const canonicalArguments = JSON.parse(canonicalize(request.params.arguments ?? {})) as Record<string, unknown>;
        return { kind: "forward", request: { ...request, params: { name: request.params.name, arguments: canonicalArguments, _meta: { "io.invock/approval-id": suppliedApproval } } }, envelope, decision: allowed, approvalId: suppliedApproval, receiptMetadata, containmentRequired: this.options.requireContainment === true };
      }
      const denied = blockedDecision(decision, "APPROVAL_INVALID_OR_CONSUMED"); this.store.recordInterception(envelope, denied, now); const receipt = this.store.complete(envelope, denied, false, { approval: "invalid" }, suppliedApproval, now, receiptMetadata);
      if (request.id === undefined) return { kind: "notification", decision: denied, receiptId: receipt.payload.receiptId };
      return { kind: "respond", response: { jsonrpc: "2.0", id: request.id, result: errorResult("Invock blocked this action: the approval is expired, modified, or already consumed.", "BLOCK", receipt.payload.receiptId, denied.reasonCodes) } };
    }
    const approval = this.store.recordInterception(envelope, decision, now)!;
    const receipt = this.store.complete(envelope, decision, false, { approval: "required" }, approval.approvalId, now, receiptMetadata);
    if (request.id === undefined) return { kind: "notification", decision, receiptId: receipt.payload.receiptId };
    return { kind: "respond", response: { jsonrpc: "2.0", id: request.id, result: errorResult("Invock requires a one-time approval for this exact action.", "APPROVAL_REQUIRED", receipt.payload.receiptId, decision.reasonCodes, approval) } };
  }

  async intercept(request: ToolCallRequest): Promise<GateOutcome> { return this.authorizeInvocation(request); }
  observeToolsList(value: unknown): void { this.descriptors.observeToolsList?.(value); }
  /** True when every successful forward must carry a verified containment run. */
  requiresContainment(): boolean { return this.options.requireContainment === true; }

  /**
   * Bind a verified, persisted containment run to one already-authorized
   * forward. This is deliberately explicit: adapters that do not call this
   * method remain outside the containment proof boundary.
   */
  attachContainmentRun(forwarded: ForwardedCall, record: ContainmentRunRecord): ForwardedCall {
    if (forwarded.kind !== "forward") throw new Error("CONTAINMENT_FORWARD_REQUIRED");
    const trusted = this.testEscape ? undefined : this.options.trustedContainmentKeys;
    if (!verifyContainmentRun(record, trusted)) throw new Error("CONTAINMENT_SIGNER_UNTRUSTED");
    if (record.result.status !== "completed" || record.result.cleanup !== "completed" || record.invocationId !== forwarded.envelope.invocationId || record.sessionId !== forwarded.envelope.sessionId || record.authorizedRequestDigest !== forwarded.envelope.integrity.requestDigest || record.profileDigest === undefined) throw new Error("CONTAINMENT_RUN_BINDING_INVALID");
    if (!this.testEscape) {
      const approved = this.options.approvedContainmentProfiles?.find(profile => profile.profileDigest === record.profileDigest);
      if (!approved) throw new Error("CONTAINMENT_PROFILE_UNAPPROVED");
      if (canonicalize(record.result.capabilities) !== canonicalize(approved.capabilities)) throw new Error("CONTAINMENT_CAPABILITIES_MISMATCH");
    }
    const existing = forwarded.receiptMetadata?.containmentRunId;
    if (existing !== undefined && existing !== record.runId) throw new Error("CONTAINMENT_RUN_REBIND_FORBIDDEN");
    this.store.saveExpansionRecord({ recordId: record.runId, recordType: "containment_run", digest: digestJson(record), payload: record, status: record.result.status });
    return { ...forwarded, containmentRequired: false, receiptMetadata: { ...(forwarded.receiptMetadata ?? {}), containmentRunId: record.runId, containmentRequestDigest: record.requestDigest, containmentProfileDigest: record.profileDigest } };
  }

  /** Convert an ALLOW that cannot obtain its required containment proof into a durable fail-closed denial. */
  rejectForward(forwarded: ForwardedCall, reason = "CONTAINMENT_REQUIRED"): RespondedCall | NotificationOutcome {
    const denied = blockedDecision(forwarded.decision, reason);
    const receipt = this.store.complete(forwarded.envelope, denied, false, { blocked: true, reason }, forwarded.approvalId, this.contextBase.now?.() ?? new Date(), forwarded.receiptMetadata);
    if (forwarded.request.id === undefined) return { kind: "notification", decision: denied, receiptId: receipt.payload.receiptId };
    return { kind: "respond", response: { jsonrpc: "2.0", id: forwarded.request.id, result: errorResult("Invock refused to forward this action because no signed containment proof was supplied.", "BLOCK", receipt.payload.receiptId, denied.reasonCodes) } };
  }

  private assertContainment(forwarded: ForwardedCall): void {
    if (this.options.requireContainment && forwarded.receiptMetadata?.containmentRunId === undefined) throw new Error("CONTAINMENT_REQUIRED");
  }

  finish(forwarded: ForwardedCall, result: ToolResult, now = this.contextBase.now?.() ?? new Date()): string {
    this.assertContainment(forwarded);
    // A source that was not path-labelled can still return sensitive data.
    // Fingerprint every bounded successful result and carry an explicit
    // unknown/untrusted label when no stronger classification is available;
    // this prevents natural-source lineage from failing open.
    const labels = forwarded.envelope.labels.filter(label => label !== "public");
    const taintLabels = labels.length > 0 ? labels : ["unknown", "untrusted_content"] as const;
    if (!result.isError) {
      const fingerprints = extractTextArguments(result).flatMap(value => fingerprintSensitiveValue(value, this.store.taintKey));
      this.store.recordTaint(forwarded.envelope.invocationId, forwarded.envelope.sessionId, [...taintLabels], fingerprints, now);
    }
    return this.store.complete(forwarded.envelope, forwarded.decision, true, result, forwarded.approvalId, now, forwarded.receiptMetadata).payload.receiptId;
  }
  finishNotification(forwarded: ForwardedCall, now = this.contextBase.now?.() ?? new Date()): string { this.assertContainment(forwarded); return this.store.complete(forwarded.envelope, forwarded.decision, true, { notification: true }, forwarded.approvalId, now, forwarded.receiptMetadata).payload.receiptId; }
  fail(forwarded: ForwardedCall, message: string, now = this.contextBase.now?.() ?? new Date()): string { this.assertContainment(forwarded); return this.store.complete(forwarded.envelope, forwarded.decision, true, { upstreamError: message }, forwarded.approvalId, now, forwarded.receiptMetadata).payload.receiptId; }
}

export class StaticDescriptorRegistry implements DescriptorRegistry {
  constructor(private readonly descriptors: Record<string, NormalizationDescriptor>) {}
  get(toolName: string): NormalizationDescriptor | undefined { return this.descriptors[toolName]; }
  schemaDigest(toolName: string): string { return digestJson({ toolName, descriptor: this.descriptors[toolName] ?? null }); }
  descriptorDigest(toolName: string): string { return this.schemaDigest(toolName); }
  registryVersion(toolName: string): string { return `registry_${this.schemaDigest(toolName).slice(0, 16)}`; }
}
