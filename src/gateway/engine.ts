import { canonicalize, digestJson, newId } from "../core/canonical.js";
import { fingerprintSensitiveValue, matchSensitiveValue } from "../core/lineage.js";
import { normalizeInvocation, type NormalizationContext, type NormalizationDescriptor } from "../core/normalize.js";
import { evaluatePolicy, type CompiledPolicy } from "../core/policy.js";
import type { ActionEnvelope, PolicyDecision, ToolCallRequest, ToolResult } from "../core/types.js";
import { InvockStore, type PendingApproval } from "../storage/store.js";
import { evaluateMonotonicAuthority } from "../authority/evaluate.js";
import { consumeCapabilityLease } from "../authority/lease.js";
import type { AuthorityRequest, CapabilityLease, IntentCapsule } from "../authority/types.js";

export interface DescriptorRegistry { get(toolName: string): NormalizationDescriptor | undefined; schemaDigest(toolName: string): string; descriptorDigest(toolName: string): string; registryVersion?(toolName: string): string; isQuarantined?(toolName: string): boolean; observeToolsList?(value: unknown): void; }
export interface ForwardedCall { kind: "forward"; request: ToolCallRequest; envelope: ActionEnvelope; decision: PolicyDecision; approvalId?: string; receiptMetadata?: Parameters<InvockStore["complete"]>[6]; }
export interface RespondedCall { kind: "respond"; response: { jsonrpc: "2.0"; id: string | number; result: ToolResult }; }
export interface NotificationOutcome { kind: "notification"; decision: PolicyDecision; receiptId: string; request?: ToolCallRequest; }
export type GateOutcome = ForwardedCall | RespondedCall | NotificationOutcome;
export interface InvocationRuntimeOverrides { sessionId?: string; protocolEra?: string; authority?: { capsule: IntentCapsule; leases: readonly CapabilityLease[]; request: AuthorityRequest; sessionId?: string; consume?: (leases: readonly CapabilityLease[]) => void }; receiptMetadata?: Parameters<InvockStore["complete"]>[6]; }

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
  constructor(private readonly policy: CompiledPolicy, private readonly descriptors: DescriptorRegistry, private readonly store: InvockStore, private readonly contextBase: Omit<NormalizationContext, "lineage" | "schemaDigest" | "descriptorDigest" | "policyVersionId">) {}

  /** Canonical, non-bypassable authorization entry point for every supported tools/call. */
  async authorizeInvocation(request: ToolCallRequest, overrides: InvocationRuntimeOverrides = {}): Promise<GateOutcome> {
    const runtimeBase = { ...this.contextBase, ...overrides };
    if (!this.store.isReady()) {
      const now = runtimeBase.now?.() ?? new Date();
      const context: NormalizationContext = { ...runtimeBase, lineage: [], policyVersionId: this.policy.policyVersionId, schemaDigest: this.descriptors.schemaDigest(request.params.name), descriptorDigest: this.descriptors.descriptorDigest(request.params.name), registryVersion: this.descriptors.registryVersion?.(request.params.name) ?? "registry_unknown" };
      const envelope = failureEnvelope(request, context, new Error("RECEIPT_CHAIN_CORRUPT"));
      const decision = blockedDecision(evaluatePolicy(this.policy, envelope, now), "RECEIPT_CHAIN_CORRUPT");
      if (request.id === undefined) return { kind: "notification", decision, receiptId: "unavailable" };
      return { kind: "respond", response: { jsonrpc: "2.0", id: request.id, result: errorResult("Invock is not ready because receipt integrity verification failed.", "BLOCK", "unavailable", decision.reasonCodes) } };
    }
    const descriptor = this.descriptors.get(request.params.name);
    const now = runtimeBase.now?.() ?? new Date();
    const lineage = extractTextArguments(request.params.arguments ?? {}).flatMap(value => matchSensitiveValue(value, this.store.taintKey, this.store.activeFingerprints(runtimeBase.sessionId, now)));
    const context: NormalizationContext = { ...runtimeBase, lineage, policyVersionId: this.policy.policyVersionId, schemaDigest: this.descriptors.schemaDigest(request.params.name), descriptorDigest: this.descriptors.descriptorDigest(request.params.name), registryVersion: this.descriptors.registryVersion?.(request.params.name) ?? "registry_static" };
    let envelope: ActionEnvelope;
    let decision: PolicyDecision;
    let authorityLeaseToConsume: CapabilityLease | undefined;
    let receiptMetadata = { ...runtimeBase.receiptMetadata, ...(runtimeBase.protocolEra ? { protocolProfileId: runtimeBase.protocolEra } : {}) };
    try {
      validateToolParameters(request);
      if (!descriptor) throw new Error("UNKNOWN_TOOL_DESCRIPTOR");
      if (this.descriptors.isQuarantined?.(request.params.name)) throw new Error("TOOL_QUARANTINED");
      envelope = await normalizeInvocation(request, descriptor, context);
      decision = evaluatePolicy(this.policy, envelope, now);
      if (runtimeBase.authority) {
        if (runtimeBase.authority.sessionId !== undefined && runtimeBase.authority.sessionId !== runtimeBase.sessionId) throw new Error("AUTHORITY_SESSION_MISMATCH");
        const resources = {
          paths: envelope.resources.filter(item => item.kind === "path").map(item => item.absolutePath),
          domains: envelope.resources.filter(item => item.kind === "url").map(item => item.hostname),
          recipients: envelope.resources.filter(item => item.kind === "recipient").map(item => item.normalized),
        };
        const actualRequest: AuthorityRequest = { ...runtimeBase.authority.request, tool: envelope.target.toolName, capabilities: envelope.capabilities, effects: envelope.effects, resources, dataLabels: envelope.labels, bytes: envelope.raw.argumentBytes };
        const authority = evaluateMonotonicAuthority(runtimeBase.authority.capsule, runtimeBase.authority.leases, actualRequest, now);
        receiptMetadata = { ...receiptMetadata, intentCapsuleDigest: runtimeBase.authority.capsule.digest, capabilityLeaseChainDigest: digestJson(runtimeBase.authority.leases.map(lease => lease.digest)), effectiveAuthorityDigest: authority.effectiveDigest };
        if (!authority.allowed) decision = blockedDecision(decision, "EFFECTIVE_AUTHORITY_DENIED");
        else if (runtimeBase.authority.leases.length > 0) authorityLeaseToConsume = runtimeBase.authority.leases[runtimeBase.authority.leases.length - 1];
      }
    } catch (error) {
      envelope = failureEnvelope(request, context, error);
      const reason = error instanceof Error && error.message.includes("UNMODELED_ARGUMENT") ? "UNMODELED_ARGUMENT" : error instanceof Error && error.message.includes("TOOL_QUARANTINED") ? "TOOL_QUARANTINED" : error instanceof Error && error.message.includes("UNKNOWN_TOOL_DESCRIPTOR") ? "UNKNOWN_TOOL" : "NORMALIZATION_FAILED";
      decision = blockedDecision(evaluatePolicy(this.policy, envelope, now), reason);
    }
    if (decision.verdict === "APPROVAL_REQUIRED" && request.id === undefined) {
      const blocked = blockedDecision(decision, "NOTIFICATION_APPROVAL_UNSUPPORTED");
      this.store.recordInterception(envelope, blocked, now);
      const receipt = this.store.complete(envelope, blocked, false, { blocked: true, notification: true }, undefined, now, receiptMetadata);
      return { kind: "notification", decision: blocked, receiptId: receipt.payload.receiptId };
    }
    if (decision.verdict === "ALLOW") {
      if (runtimeBase.authority && authorityLeaseToConsume) runtimeBase.authority.consume?.([...runtimeBase.authority.leases.slice(0, -1), consumeCapabilityLease(authorityLeaseToConsume, {}, now)]);
      this.store.recordInterception(envelope, decision, now);
      const canonicalArguments = JSON.parse(canonicalize(request.params.arguments ?? {})) as Record<string, unknown>;
      const approvalId = request.params._meta?.["io.invock/approval-id"];
      const authorizedRequest = { ...request, params: { name: request.params.name, arguments: canonicalArguments, ...(typeof approvalId === "string" ? { _meta: { "io.invock/approval-id": approvalId } } : {}) } };
      return { kind: "forward", request: authorizedRequest, envelope, decision, receiptMetadata };
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
        if (runtimeBase.authority && authorityLeaseToConsume) runtimeBase.authority.consume?.([...runtimeBase.authority.leases.slice(0, -1), consumeCapabilityLease(authorityLeaseToConsume, {}, now)]);
        const canonicalArguments = JSON.parse(canonicalize(request.params.arguments ?? {})) as Record<string, unknown>;
        return { kind: "forward", request: { ...request, params: { name: request.params.name, arguments: canonicalArguments, _meta: { "io.invock/approval-id": suppliedApproval } } }, envelope, decision: allowed, approvalId: suppliedApproval, receiptMetadata };
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

  finish(forwarded: ForwardedCall, result: ToolResult, now = this.contextBase.now?.() ?? new Date()): string {
    const labels = forwarded.envelope.labels.filter(label => label === "secret" || label === "credential" || label === "private_key");
    if (labels.length > 0 && !result.isError) {
      const fingerprints = result.content.filter(item => item.type === "text").flatMap(item => fingerprintSensitiveValue(item.text, this.store.taintKey));
      this.store.recordTaint(forwarded.envelope.invocationId, forwarded.envelope.sessionId, labels, fingerprints, now);
    }
    return this.store.complete(forwarded.envelope, forwarded.decision, true, result, forwarded.approvalId, now, forwarded.receiptMetadata).payload.receiptId;
  }
  finishNotification(forwarded: ForwardedCall, now = this.contextBase.now?.() ?? new Date()): string { return this.store.complete(forwarded.envelope, forwarded.decision, true, { notification: true }, forwarded.approvalId, now, forwarded.receiptMetadata).payload.receiptId; }
  fail(forwarded: ForwardedCall, message: string, now = this.contextBase.now?.() ?? new Date()): string { return this.store.complete(forwarded.envelope, forwarded.decision, true, { upstreamError: message }, forwarded.approvalId, now, forwarded.receiptMetadata).payload.receiptId; }
}

export class StaticDescriptorRegistry implements DescriptorRegistry {
  constructor(private readonly descriptors: Record<string, NormalizationDescriptor>) {}
  get(toolName: string): NormalizationDescriptor | undefined { return this.descriptors[toolName]; }
  schemaDigest(toolName: string): string { return digestJson({ toolName, descriptor: this.descriptors[toolName] ?? null }); }
  descriptorDigest(toolName: string): string { return this.schemaDigest(toolName); }
  registryVersion(toolName: string): string { return `registry_${this.schemaDigest(toolName).slice(0, 16)}`; }
}
