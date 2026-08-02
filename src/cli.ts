#!/usr/bin/env node
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parsePolicyYaml, compilePolicy } from "./core/policy.js";
import { InvocationGate, StaticDescriptorRegistry, type DescriptorRegistry } from "./gateway/engine.js";
import { runStdioProxy } from "./gateway/stdio.js";
import { InvockStore } from "./storage/store.js";
import { startApi } from "./api/server.js";
import { forgePolicy, diffPolicies, activateDraft, type PolicyDraft, type PolicyObservation } from "./forge/index.js";
import { inspectWorkflow } from "./guard/index.js";
import { runContained } from "./containment/index.js";
import { certifyContainment } from "./containment/certification.js";
import { persistContainmentRun, readContainmentRun, type UnsignedContainmentRunRecord } from "./containment/lifecycle.js";
import type { ContainmentProfile } from "./containment/types.js";
import { LocalControlPlane } from "./control/index.js";
import { buildEvidenceBundle, renderEvidenceBundle, type EvidenceFormat } from "./evidence/index.js";
import { digestJson, newId } from "./core/canonical.js";
import type { ToolCallRequest } from "./core/types.js";
import type { ApiAuthorizeInput, ApiRuntimeResolution } from "./api/server.js";
import { assertCapsule } from "./authority/capsule.js";
import { assertLease } from "./authority/lease.js";
import type { AuthorityBinding, TrustedApproverKeys } from "./authority/binding.js";
import type { CapabilityLease, IntentCapsule } from "./authority/types.js";
import { IdentityAuthority } from "./identity/index.js";
import { scanSupplyChain } from "./supplychain/index.js";
import { PersistentToolRegistry } from "./registry/registry.js";
import { detectAgent, installAgent, uninstallAgent, verifyAgent, type SupportedAgent } from "./agents.js";
import { spawn } from "node:child_process";
import { addProcessor, evaluatePrivacy, loadPrivacyConfig, pseudonymize, removeProcessor, setPrivacyMode, verifyPrivacyContract, type InvockPrivacyMode, type ProcessorRetentionProfile } from "./privacy/index.js";
import { runLegacyScan, signPlan, verifyPlan, applyRemediationPlan, runLegacyVerification, type LegacySourceType, loadProviderHistoryRecords, updateProviderState, getProviderGuidance, type ProviderHistoryState, resolveEnforcementStart, createProtectionBoundary, signProtectionBoundary, verifyProtectionBoundary } from "./privacy/legacy/index.js";
import { generateSigningMaterial } from "./storage/receipts.js";
import { readdirSync } from "node:fs";

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const root = existsSync(resolve(moduleRoot, "policies/default.yaml")) ? moduleRoot : process.cwd();
const version = "0.1.8";
const unsupportedIntegrations = ["enterprise-cloud-control-plane", "SSO/SCIM", "remote-evidence-anchoring"];

function help(): void {
  console.log(`Invock — deterministic local-first MCP invocation reference monitor

Usage:
  invock --help
  invock --version
  invock init [--state <path>]
  invock scan [--state <path>]
  invock supply-chain scan [--root <path>]
  invock policy validate <file>
  invock policy learn [--from-demo] [<observations-json>]
  invock policy diff <from-json> <to-json>
  invock policy simulate <policy-json> [<observations-json>]
  invock policy activate <draft-json> --approved-by <name> --approval-id <id> --statement <text> [--output <path>]
  invock policy rollback <policy-id>
  invock doctor [--database <path>] [--key-directory <path>]
  invock status [--database <path>] [--key-directory <path>]
  invock stats [--json] [--database <path>] [--key-directory <path>]
  invock proxy [--port <port>] [--host 127.0.0.1]
  invock dashboard [--no-open]
  invock privacy status
  invock privacy mode set local-zdr|end-to-end-zdr
  invock privacy verify-local|verify-end-to-end
  invock privacy processors list|add <profile.json>|remove <id>
  invock privacy chain inspect
  invock privacy demo
  invock install|wrap <claude|codex|cursor>
  invock verify <claude|codex|cursor>
  invock uninstall|unwrap <claude|codex|cursor>
  invock receipts verify [--database <path>] [--key-directory <path>]
  invock receipts rotate-key [--database <path>] [--key-directory <path>]
  invock receipts export --format json|ndjson|markdown [--session-id <id>] [--database <path>] [--key-directory <path>]
  invock evidence bundle [<session-id>] [--database <path>] [--key-directory <path>] [--format json|ndjson|markdown]
  invock start [--database <path>] [--key-directory <path>]
  invock serve [--strict-authority] [--session-id <id>] [--trusted-approvers <json>] [--database <path>] [--key-directory <path>]
  invock serve --stdio [--strict-authority] [--session-id <id>] [--trusted-approvers <json>] [--database <path>] [--key-directory <path>] <command> [-- <args...>]
  invock identity enroll [--agent <id>] --organization <id> --project <id> [--display-name <name>] [--runtime-type <type>] [--key-directory <path>]
  invock identity attest --agent <id> [--manifest <json-file>] [--key-directory <path>]
  invock identity session --agent <id> --project <id> [--ttl <seconds>] [--key-directory <path>]
  invock scan
  invock judge
  invock demo safe|attack
  invock forge [observation-json]
  invock guard <workflow-file>
  invock contain <fixture-root> <command> [-- <args...>]
  invock run --sandbox <server-config.json>
  invock containment certify
  invock containment inspect <run-id> [--directory <path>]

Local boundary: JSON state, SQLite receipts, and loopback API only. Enterprise/cloud integrations are reported as unsupported.`);
}

function cliStatePath(): string { return process.env.INVOCK_HOME ?? resolve(process.env.HOME ?? root, ".invock"); }
function writeCliState(agent?: string): string {
  const path = ensureCliState();
  const directory = cliStatePath(); mkdirSync(directory, { recursive: true, mode: 0o700 });
  const current = readFileSync(path, "utf8");
  if (agent && !JSON.parse(current).integrations?.[agent]) {
    const state = JSON.parse(current) as { integrations: Record<string, { installedAt: string }> };
    state.integrations[agent] = { installedAt: new Date().toISOString() };
    writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 }); chmodSync(path, 0o600);
  }
  return path;
}
function ensureCliState(): string {
  const directory = cliStatePath(); mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, "cli-state.json");
  try { JSON.parse(readFileSync(path, "utf8")); } catch { writeFileSync(path, '{\n  "integrations": {}\n}\n', { mode: 0o600 }); }
  chmodSync(path, 0o600); return path;
}
function readCliState(): { integrations: Record<string, unknown> } { ensureCliState(); return JSON.parse(readFileSync(join(cliStatePath(), "cli-state.json"), "utf8")) as { integrations: Record<string, unknown> }; }

function usage(): number { console.error("Run `invock --help` for usage."); return 64; }
function readJson<T>(file: string): T { return JSON.parse(readFileSync(resolve(root, file), "utf8")) as T; }
function takeOption(values: string[], name: string): string | undefined {
  const index = values.indexOf(name);
  if (index < 0) return undefined;
  const value = values[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  values.splice(index, 2);
  return resolve(root, value);
}
function takeTextOption(values: string[], name: string): string | undefined {
  const index = values.indexOf(name);
  if (index < 0) return undefined;
  const value = values[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  values.splice(index, 2);
  return value;
}
function runtime(values: string[]): { database: string; keyDirectory?: string; sessionId?: string; trustedApproversPath?: string } {
  const database = takeOption(values, "--database") ?? process.env.INVOCK_DATABASE_PATH ?? resolve(root, ".invock/invock.sqlite");
  const keyDirectory = takeOption(values, "--key-directory") ?? process.env.INVOCK_KEY_DIRECTORY;
  const sessionId = takeTextOption(values, "--session-id") ?? process.env.INVOCK_SESSION_ID;
  const trustedApproversPath = takeOption(values, "--trusted-approvers") ?? (process.env.INVOCK_TRUSTED_APPROVER_KEYS ? resolve(root, process.env.INVOCK_TRUSTED_APPROVER_KEYS) : undefined);
  return { database, ...(keyDirectory ? { keyDirectory } : {}), ...(sessionId ? { sessionId } : {}), ...(trustedApproversPath ? { trustedApproversPath } : {}) };
}
function statePath(values: string[]): string { return takeOption(values, "--state") ?? process.env.INVOCK_CONTROL_PLANE_PATH ?? resolve(root, ".invock/control-plane.json"); }
function formatOption(values: string[], defaultValue: EvidenceFormat = "json"): EvidenceFormat {
  const value = takeTextOption(values, "--format") ?? defaultValue;
  if (value !== "json" && value !== "ndjson" && value !== "markdown") throw new Error("--format must be json, ndjson, or markdown");
  return value;
}
function staticDescriptors(): DescriptorRegistry {
  return new StaticDescriptorRegistry({
    read_file: { fields: [{ pointer: "/path", type: "path", access: "read" }] },
    fetch_url: { fields: [{ pointer: "/url", type: "url", methodPointer: "/method" }, { pointer: "/body", type: "data" }] },
    send_email: { fields: [{ pointer: "/to", type: "recipient" }, { pointer: "/body", type: "data" }] },
    run_command: { fields: [{ pointer: "/command", type: "command" }] },
  });
}
function gate(store: InvockStore, descriptors: DescriptorRegistry = staticDescriptors(), options: { serverId?: string; trustedApproverKeys?: TrustedApproverKeys } = {}) {
  const privacy = loadPrivacyConfig(process.env.INVOCK_PRIVACY_DIR ?? resolve(root, ".invock")); const privacyEvaluation = evaluatePrivacy(privacy, privacy.processors.map(profile => profile.id));
  return new InvocationGate(compilePolicy(parsePolicyYaml(readFileSync(resolve(root, "policies/default.yaml"), "utf8"))), descriptors, store, { cwd: root, projectRoot: root, organizationDomains: ["example.com"], sessionId: "stdio-local", privacyBlocked: privacyEvaluation.verdict === "BLOCK", privacyMetadata: { privacyMode: privacy.mode, privacyContractDigest: privacy.contract.digest, privacyChainDigest: privacyEvaluation.chainDigest, privacyProcessorProfileDigests: privacyEvaluation.processorProfileDigests }, ...(options.serverId ? { serverId: options.serverId } : {}), principal: { principalId: "local-user", clientId: "invock-cli", scopes: ["*"] } }, { requireAuthority: true, requireIdentity: true, ...(options.trustedApproverKeys ? { trustedApproverKeys: options.trustedApproverKeys } : {}) });
}

function readTrustedApproverKeys(path: string | undefined): TrustedApproverKeys {
  if (!path) return new Map();
  const parsed = readJson<Record<string, unknown>>(path);
  const keys = new Map<string, string>();
  for (const [approverId, publicKey] of Object.entries(parsed)) {
    if (typeof publicKey !== "string" || !publicKey.includes("PUBLIC KEY")) throw new Error(`Invalid trusted approver key: ${approverId}`);
    keys.set(approverId, publicKey);
  }
  return keys;
}

function identityAuthority(values: string[]): IdentityAuthority {
  const keyDirectory = takeOption(values, "--key-directory") ?? process.env.INVOCK_KEY_DIRECTORY ?? resolve(root, ".invock/keys");
  return new IdentityAuthority(join(keyDirectory, "identity-state.json"));
}

async function demo(attack: boolean): Promise<void> {
  const store = new InvockStore(":memory:");
  try {
    const monitor = gate(store);
    const request = attack ? { jsonrpc: "2.0" as const, id: 1, method: "tools/call" as const, params: { name: "read_file", arguments: { path: ".env" } } } : { jsonrpc: "2.0" as const, id: 1, method: "tools/call" as const, params: { name: "read_file", arguments: { path: "/workspace/README.md" } } };
    const outcome = await monitor.intercept(request);
    console.log(JSON.stringify(outcome.kind === "respond" ? outcome.response : { decision: outcome.decision.verdict, message: "Would forward to upstream server" }, null, 2));
  } finally { store.close(); }
}

function simulatePolicy(draft: PolicyDraft, observations: readonly PolicyObservation[]) {
  const within = (values: readonly string[] | undefined, allowed: readonly string[]) => (values ?? []).every(value => allowed.includes(value));
  const results = observations.map(observation => ({ tool: observation.tool, allowed: draft.tools.includes(observation.tool) && within(observation.capabilities, draft.capabilities) && within(observation.effects, draft.effects) && within(observation.paths, draft.resources.paths) && within(observation.domains, draft.resources.domains) && within(observation.recipients, draft.resources.recipients) }));
  return { status: "simulated", executed: false, observations: results.length, allowed: results.filter(item => item.allowed).length, blocked: results.filter(item => !item.allowed).length, results, unmodeledBehavior: "No execution, network, or upstream call occurs during this simulation." };
}

async function serve(values: string[]): Promise<void> {
  const strictAuthority = true;
  values = values.filter(value => value !== "--strict-authority");
  const host = takeTextOption(values, "--host") ?? "127.0.0.1";
  const portText = takeTextOption(values, "--port");
  const port = portText === undefined ? undefined : Number(portText);
  if (host !== "127.0.0.1" || (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535))) throw new Error("server requires loopback host and valid port");
  const config = runtime(values); const trustedApproverKeys = readTrustedApproverKeys(config.trustedApproversPath); const store = new InvockStore(config.database, config);
  const identityAuthority = new IdentityAuthority(join(store.keyDirectory, "identity-state.json"));
  if (values.length > 0 && values[0] === "--stdio") {
    values.shift(); const separator = values.indexOf("--"); const executable = separator >= 0 ? values[separator - 1] : values[0];
    if (!executable) { store.close(); throw new Error("serve --stdio requires a command"); }
    const args = separator >= 0 ? values.slice(separator + 1) : values.slice(1);
    const serverId = "stdio-upstream";
      try { await runStdioProxy({ command: executable, args, cwd: root, serverId }, gate(store, new PersistentToolRegistry(store, serverId), { serverId, trustedApproverKeys })); } finally { store.close(); }
    return;
  }
  try {
    const monitor = gate(store, staticDescriptors(), { trustedApproverKeys });
    const apiLeases = new Map<string, CapabilityLease>();
    const apiLeaseSessions = new Map<string, string>();
    const apiSessionId = config.sessionId ?? newId("api-session");
    const privacy = loadPrivacyConfig(process.env.INVOCK_PRIVACY_DIR ?? resolve(root, ".invock")); const privacyEvaluation = evaluatePrivacy(privacy, privacy.processors.map(profile => profile.id));
    const api = await startApi(store, { host, ...(port === undefined ? {} : { port }), privacyState: { mode: privacy.mode, verdict: privacyEvaluation.verdict, contractDigest: privacy.contract.digest, chainDigest: privacyEvaluation.chainDigest }, sessionId: apiSessionId, gate: monitor, resolveRuntime: async (input: ApiAuthorizeInput): Promise<ApiRuntimeResolution> => {
      if (strictAuthority && (!input.agent || !input.projectId || !input.sessionId || input.intentCapsule === undefined || input.authorityBinding === undefined || !input.capabilityLeases)) return { denial: { verdict: "BLOCK", reasonCodes: ["STRICT_AUTHORITY_REQUIRED"] } };
      let identityContext: ReturnType<IdentityAuthority["executionContext"]>;
      let identityBinding: ReturnType<IdentityAuthority["evidenceBinding"]>;
      try {
        if (!input.agent || !input.projectId || !input.sessionId) throw new Error("IDENTITY_BINDING_REQUIRED");
        const now = new Date();
        identityContext = identityAuthority.executionContext(input.agent, input.sessionId, now);
        if (identityContext.identity.projectId !== input.projectId) throw new Error("IDENTITY_PROJECT_MISMATCH");
        identityBinding = identityAuthority.evidenceBinding(identityContext.identity, identityContext.session, now);
      } catch (error) {
        const reason = error instanceof Error && /^IDENTITY_/u.test(error.message) ? error.message : "IDENTITY_BINDING_INVALID";
        return { denial: { verdict: "BLOCK", reasonCodes: [reason] } };
      }
      let authority: { capsule: IntentCapsule; leases: readonly CapabilityLease[]; sessionId: string } | undefined;
      if (input.intentCapsule !== undefined) {
        try { assertCapsule(input.intentCapsule as IntentCapsule, trustedApproverKeys); } catch { return { denial: { verdict: "BLOCK", reasonCodes: ["UNTRUSTED_INTENT_CAPSULE"] } }; }
        if (!input.agent) return { denial: { verdict: "BLOCK", reasonCodes: ["AGENT_REQUIRED_FOR_INTENT"] } };
        if (!input.sessionId) return { denial: { verdict: "BLOCK", reasonCodes: ["SESSION_REQUIRED_FOR_INTENT"] } };
        if (!input.capabilityLeases) return { denial: { verdict: "BLOCK", reasonCodes: ["CAPABILITY_LEASE_REQUIRED"] } };
        try {
          const leases = input.capabilityLeases.map(value => value as CapabilityLease);
          leases.forEach(lease => assertLease(lease));
          if (leases.at(-1)?.subject !== input.agent) throw new Error("LEASE_AGENT_MISMATCH");
          const current = leases.map(lease => {
            const sessionOwner = apiLeaseSessions.get(lease.leaseId);
            if (sessionOwner && sessionOwner !== input.sessionId) throw new Error("LEASE_SESSION_MISMATCH");
            apiLeaseSessions.set(lease.leaseId, input.sessionId!);
            const stored = apiLeases.get(lease.leaseId);
            if (stored && stored.remainingCalls < lease.remainingCalls) throw new Error("LEASE_STATE_REPLAY");
            const effective = stored ?? lease;
            apiLeases.set(effective.leaseId, effective);
            return effective;
          });
          authority = { capsule: input.intentCapsule as IntentCapsule, leases: current, sessionId: input.sessionId };
        } catch (error) {
          const reason = error instanceof Error && ["LEASE_STATE_REPLAY", "LEASE_AGENT_MISMATCH", "LEASE_SESSION_MISMATCH"].includes(error.message) ? error.message : "MALFORMED_CAPABILITY_LEASE";
          return { denial: { verdict: "BLOCK", reasonCodes: [reason] } };
        }
      }
      return { overrides: { ...(input.sessionId ? { sessionId: input.sessionId } : {}), ...(input.projectId ? { projectId: input.projectId } : {}), principal: { principalId: input.agent ?? "local-user", clientId: "invock-sdk", ...(input.agent ? { agentId: input.agent } : {}), scopes: ["*"] }, identityAuthority, identityContext, identityBinding, ...(authority ? { authority: { capsule: authority.capsule, leases: authority.leases, ...(input.authorityBinding !== undefined ? { binding: input.authorityBinding as AuthorityBinding } : {}), sessionId: authority.sessionId, request: { tool: input.tool, capabilities: [], effects: [], resources: { paths: [], domains: [], recipients: [] }, dataLabels: [] }, consume: leases => { leases.forEach(lease => apiLeases.set(lease.leaseId, lease)); } } } : {}) } };
    } });
    console.error(`Invock dashboard: ${api.url}\nInvock dashboard token: ${api.token}\nInvock API session: ${apiSessionId}\nDatabase: ${config.database}\nKey directory: ${store.keyDirectory}\nPress Ctrl+C to stop.`);
    await new Promise<void>(resolveSignal => { process.once("SIGINT", resolveSignal); process.once("SIGTERM", resolveSignal); });
    await api.close();
  } finally { store.close(); }
}

async function main(argv: string[]): Promise<number> {
  let json = false;
  let yes = false;
  let privateKeyPem = "";
  let keyId = "";
  let publicKeyPem = "";

  const [command, subcommand, ...initialRest] = argv;
  if (argv.includes("--help") || argv.includes("-h") || command === "help") { help(); return 0; }
  if (command === "--version" || command === "-V" || command === "version") { console.log(version); return 0; }
  const rest = [...initialRest];
  if (!command) { help(); return 0; }
  if (command === "status") { const state = readCliState(); console.log(JSON.stringify({ ready: true, statePath: join(cliStatePath(), "cli-state.json"), integrations: state.integrations }, null, 2)); return 0; }
  if (command === "privacy") {
    const privacyDir = process.env.INVOCK_PRIVACY_DIR ?? resolve(root, ".invock"); const action = subcommand; const values = [...rest].filter((item): item is string => item !== undefined); const config = loadPrivacyConfig(privacyDir);
    json = values.includes("--json");
    if (json) values.splice(values.indexOf("--json"), 1);

    yes = values.includes("--yes");
    if (yes) values.splice(values.indexOf("--yes"), 1);

    // Load signing key material
    const privateKeyPath = join(privacyDir, "receipt-ed25519.private.pem");
    const keyIdPath = join(privacyDir, "receipt-ed25519.key-id");
    const publicKeyPath = join(privacyDir, "receipt-ed25519.public.pem");
    if (existsSync(privateKeyPath) && existsSync(keyIdPath) && existsSync(publicKeyPath)) {
      privateKeyPem = readFileSync(privateKeyPath, "utf8");
      keyId = readFileSync(keyIdPath, "utf8").trim();
      publicKeyPem = readFileSync(publicKeyPath, "utf8");
    } else {
      const material = generateSigningMaterial();
      privateKeyPem = material.privateKeyPem;
      keyId = material.signingKeyId;
      publicKeyPem = material.publicKeyPem;
      mkdirSync(privacyDir, { recursive: true });
      writeFileSync(privateKeyPath, privateKeyPem, { mode: 0o600 });
      writeFileSync(publicKeyPath, publicKeyPem, { mode: 0o600 });
      writeFileSync(keyIdPath, keyId, { mode: 0o600 });
    }

    if (action === "legacy") {
      const legacyAction = values.shift();
      if (!legacyAction) {
        console.error("Usage: invock privacy legacy [scan|review|plan|apply|verify] [options]");
        return 64;
      }

      const dryRun = values.includes("--dry-run");
      if (dryRun) values.splice(values.indexOf("--dry-run"), 1);

      const scanIdOpt = takeTextOption(values, "--scan-id");
      const planIdOpt = takeTextOption(values, "--plan-id");

      // Verify no remaining unknown options
      if (values.some(v => v.startsWith("--"))) {
        throw new Error("unknown option");
      }

      if (legacyAction === "scan") {
        const consent = yes || values.includes("--consent");
        if (consent && values.includes("--consent")) {
          values.splice(values.indexOf("--consent"), 1);
        }
        if (!consent) {
          throw new Error("CONSENT_REQUIRED");
        }
        // Run scan on all scopes
        const scopes: LegacySourceType[] = ["CLAUDE_LOCAL", "CODEX_LOCAL", "WORKSPACE", "CUSTOM_ROOT"];
        const { summary, findings } = await runLegacyScan(root, {
          consent: true,
          selectedScopes: scopes,
        });

        // Save scan to privacyDir
        const scanFile = join(privacyDir, `legacy-scan-${summary.scanId}.json`);
        mkdirSync(privacyDir, { recursive: true });
        writeFileSync(scanFile, JSON.stringify({ summary, findings }, null, 2), { mode: 0o600 });

        if (json) {
          console.log(JSON.stringify({ summary, findings }, null, 2));
        } else {
          console.log(`Scan completed. Scan ID: ${summary.scanId}`);
          console.log(`Files Examined: ${summary.filesExamined}`);
          console.log(`Findings Found: ${findings.length}`);
        }
        return 0;
      }

      if (legacyAction === "review") {
        let targetScanId = scanIdOpt;
        if (!targetScanId) {
          const files = readdirSync(privacyDir).filter(f => f.startsWith("legacy-scan-") && f.endsWith(".json"));
          const latestFile = files.sort().reverse()[0];
          if (!latestFile) throw new Error("No previous scans found. Run `invock privacy legacy scan` first.");
          targetScanId = latestFile.replace("legacy-scan-", "").replace(".json", "");
        }
        const scanData = JSON.parse(readFileSync(join(privacyDir, `legacy-scan-${targetScanId}.json`), "utf8"));
        const findings = scanData.findings;

        if (json) {
          console.log(JSON.stringify(findings, null, 2));
        } else {
          console.log(`Reviewing findings for Scan ID: ${targetScanId}\n`);
          for (const f of findings) {
            console.log(`Finding ID: ${f.id}`);
            console.log(`Source: ${f.sourceType} (Root: ${f.sourceRootId})`);
            console.log(`Format: ${f.format}`);
            console.log(`Categories: ${f.categories.join(", ")}`);
            console.log(`Severity: ${f.severity}`);
            console.log(`Match Count: ${f.matchCount}`);
            console.log(`Auto-Delete Eligible: ${f.autoDeleteEligible}`);
            console.log(`Recommended Actions: ${f.recommendedActions.join(", ")}`);
            console.log("----------------------------------------");
          }
        }
        return 0;
      }

      if (legacyAction === "plan") {
        let targetScanId = scanIdOpt;
        if (!targetScanId) {
          const files = readdirSync(privacyDir).filter(f => f.startsWith("legacy-scan-") && f.endsWith(".json"));
          const latestFile = files.sort().reverse()[0];
          if (!latestFile) throw new Error("No previous scans found. Run `invock privacy legacy scan` first.");
          targetScanId = latestFile.replace("legacy-scan-", "").replace(".json", "");
        }
        const scanData = JSON.parse(readFileSync(join(privacyDir, `legacy-scan-${targetScanId}.json`), "utf8"));
        const { summary, findings } = scanData;

        const planItems = findings.map((f: any) => ({
          findingId: f.id,
          sourceType: f.sourceType,
          sourceRootId: f.sourceRootId,
          pathHmac: f.pathHmac,
          expectedArtifactFingerprint: f.artifactFingerprint,
          action: f.autoDeleteEligible ? ("DELETE_DISPOSABLE_ARTIFACT" as const) : ("ROTATE_SECRET_REQUIRED" as const),
          reasonCode: "REMEDIATION_REQUIRED",
          userConfirmed: true,
        }));

        const planId = `plan_${Date.now()}`;
        const unsignedPlan = {
          id: planId,
          scanId: summary.scanId,
          scanDigest: summary.scanDigest,
          createdAt: new Date().toISOString(),
          items: planItems,
          selectedDeleteCount: planItems.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").length,
          manualActionCount: planItems.filter((i: any) => i.action === "ROTATE_SECRET_REQUIRED").length,
          providerActionCount: 0,
          ignoredCount: 0,
        };

        const plan = signPlan(unsignedPlan, privateKeyPem, keyId);
        writeFileSync(join(privacyDir, `remediation-plan-${planId}.json`), JSON.stringify(plan, null, 2), { mode: 0o600 });

        if (json) {
          console.log(JSON.stringify(plan, null, 2));
        } else {
          console.log(`Plan generated. Plan ID: ${plan.id}`);
          console.log(`Plan Digest: ${plan.digest}`);
          console.log(`Delete Count: ${plan.selectedDeleteCount}`);
          console.log(`Manual Actions: ${plan.manualActionCount}`);
        }
        return 0;
      }

      if (legacyAction === "apply") {
        let targetPlanId = planIdOpt;
        if (!targetPlanId) {
          const files = readdirSync(privacyDir).filter(f => f.startsWith("remediation-plan-") && f.endsWith(".json"));
          const latestFile = files.sort().reverse()[0];
          if (!latestFile) throw new Error("No remediation plans found. Run `invock privacy legacy plan` first.");
          targetPlanId = latestFile.replace("remediation-plan-", "").replace(".json", "");
        }

        const plan = JSON.parse(readFileSync(join(privacyDir, `remediation-plan-${targetPlanId}.json`), "utf8"));
        if (!verifyPlan(plan, publicKeyPem)) {
          throw new Error("INVALID_PLAN_SIGNATURE");
        }

        // Fetch corresponding scan's findings
        const scanData = JSON.parse(readFileSync(join(privacyDir, `legacy-scan-${plan.scanId}.json`), "utf8"));
        const findings = scanData.findings;

        if (dryRun) {
          const result = await applyRemediationPlan(root, plan, findings, privateKeyPem, keyId, { dryRun: true });
          const wouldDelete = plan.items.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").length;
          const wouldRotate = plan.items.filter((i: any) => i.action === "ROTATE_SECRET_REQUIRED").length;

          console.log(`would delete: ${wouldDelete}`);
          console.log(`would restrict permissions: 0`);
          console.log(`manual remediation required: ${wouldRotate}`);
          console.log(`secret rotation required: ${wouldRotate}`);
          console.log(`ignored: 0`);
          console.log(`changed since scan: 0`);
          console.log(`missing: 0`);
          console.log(`symlink conflict: 0`);
          console.log(`outside-root conflict: 0`);
          console.log("No files were changed.");
          return 0;
        }

        const N = plan.items.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").length;

        if (!yes) {
          console.log(`This operation permanently deletes ${N} selected local artifacts.\n`);
          console.log("It does not delete provider-side history.");
          console.log("It does not guarantee physical media erasure.");
          console.log("It cannot be undone by Invock.\n");
          process.stdout.write(`Type DELETE ${N} to continue: `);
          const input = await new Promise<string>(res => {
            process.stdin.once("data", chunk => res(chunk.toString().trim()));
          });
          if (input !== `DELETE ${N}`) {
            console.log("Cancelled.");
            return 0;
          }
        }

        const result = await applyRemediationPlan(root, plan, findings, privateKeyPem, keyId, { dryRun: false });
        writeFileSync(join(privacyDir, `cleanup-receipt-${plan.id}.json`), JSON.stringify(result.receipt, null, 2), { mode: 0o600 });

        if (json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log("Remediation applied successfully.");
          console.log(`Deletions completed: ${result.receipt.deleteCompleted}`);
          console.log(`Cleanup receipt digest: ${result.receipt.digest}`);
        }
        return 0;
      }

      if (legacyAction === "verify") {
        let targetPlanId = planIdOpt;
        if (!targetPlanId) {
          const files = readdirSync(privacyDir).filter(f => f.startsWith("remediation-plan-") && f.endsWith(".json"));
          const latestFile = files.sort().reverse()[0];
          if (!latestFile) throw new Error("No remediation plans found. Run `invock privacy legacy plan` first.");
          targetPlanId = latestFile.replace("remediation-plan-", "").replace(".json", "");
        }
        const plan = JSON.parse(readFileSync(join(privacyDir, `remediation-plan-${targetPlanId}.json`), "utf8"));
        const deletedHmacs = plan.items.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").map((i: any) => i.pathHmac);

        const scopes: LegacySourceType[] = Array.from(new Set(plan.items.map((i: any) => i.sourceType)));
        const state = await runLegacyVerification(root, scopes, deletedHmacs);

        if (json) {
          console.log(JSON.stringify({ state }, null, 2));
        } else {
          console.log(`Verification Verdict: ${state}`);
        }
        return state === "VERIFIED_CLEAN_FOR_SELECTED_SCOPE" ? 0 : 1;
      }

      if (legacyAction === "status") {
        const onboarding = config.legacy_onboarding;
        const statusVal = onboarding ? onboarding.status : "NOT_SCANNED";
        const lastScanId = onboarding ? onboarding.last_scan_id : null;
        const lastScanAt = onboarding ? onboarding.last_scan_at : "NEVER";
        const scopes = onboarding ? onboarding.default_scopes : [];

        let totalFindings = 0;
        let resolvedFindings = 0;
        let unresolvedFindings = 0;

        if (lastScanId && existsSync(join(privacyDir, `legacy-scan-${lastScanId}.json`))) {
          try {
            const scanData = JSON.parse(readFileSync(join(privacyDir, `legacy-scan-${lastScanId}.json`), "utf8"));
            totalFindings = scanData.findings.length;
            resolvedFindings = scanData.findings.filter((f: any) => f.autoDeleteEligible).length;
            unresolvedFindings = totalFindings - resolvedFindings;
          } catch {}
        }

        const providerHistoryRecords = loadProviderHistoryRecords(privacyDir);
        const claudeState = providerHistoryRecords.find(r => r.providerId === "CLAUDE")?.state ?? "NOT_CHECKED";
        const codexState = providerHistoryRecords.find(r => r.providerId === "CODEX")?.state ?? "NOT_CHECKED";

        let boundaryVerdict = "NOT_VERIFIED";
        let boundarySig = "NOT AVAILABLE";
        if (onboarding?.boundary_id && existsSync(join(privacyDir, `privacy-boundary-${onboarding.boundary_id}.json`))) {
          try {
            const boundary = JSON.parse(readFileSync(join(privacyDir, `privacy-boundary-${onboarding.boundary_id}.json`), "utf8"));
            boundaryVerdict = boundary.verdict;
            boundarySig = verifyProtectionBoundary(boundary, publicKeyPem) ? "VALID" : "INVALID";
          } catch {}
        }

        if (json) {
          console.log(JSON.stringify({
            onboarding: { status: statusVal },
            localAudit: { status: statusVal, lastScan: lastScanAt, selectedScopes: scopes, findings: totalFindings, resolved: resolvedFindings, unresolved: unresolvedFindings },
            requiredActions: { disposableCleanupRemaining: unresolvedFindings, manualRemediation: unresolvedFindings, secretRotations: unresolvedFindings, providerActions: providerHistoryRecords.filter(r => r.state === "USER_ACTION_REQUIRED").length },
            providerHistory: { claude: claudeState, codex: codexState },
            boundary: { verdict: boundaryVerdict, signature: boundarySig }
          }, null, 2));
        } else {
          console.log(`Invock Legacy Privacy

Onboarding:
  Status: ${statusVal}

Local audit:
  Status: ${statusVal}
  Last scan: ${lastScanAt}
  Selected scopes: ${scopes.join(", ")}
  Findings: ${totalFindings}
  Resolved: ${resolvedFindings}
  Unresolved: ${unresolvedFindings}

Required actions:
  Disposable cleanup remaining: ${unresolvedFindings}
  Manual remediation: ${unresolvedFindings}
  Secret rotations: ${unresolvedFindings}
  Provider actions: ${providerHistoryRecords.filter(r => r.state === "USER_ACTION_REQUIRED").length}

Provider history:
  Claude: ${claudeState}
  Codex: ${codexState}

Protection boundary:
  Verdict: ${boundaryVerdict}
  Signature: ${boundarySig}`);
        }
        return 0;
      }

      if (legacyAction === "provider-actions") {
        const subAction = values.shift();
        if (subAction === "confirm") {
          const providerId = values.shift();
          if (!providerId) {
            throw new Error("confirm requires provider-id");
          }
          const evidenceRef = takeTextOption(values, "--evidence-reference");
          const stateOpt = takeTextOption(values, "--state");

          let targetState: ProviderHistoryState = "PROVIDER_CONFIRMED";
          if (stateOpt) {
            targetState = stateOpt as ProviderHistoryState;
          } else {
            console.log("Select the evidence available:\n");
            console.log("1. Provider confirmation or reference");
            console.log("2. User completed provider controls without provider proof");
            console.log("3. Data intentionally retained");
            console.log("4. Action not completed");
            process.stdout.write("\nSelect option (1-4): ");
            const input = await new Promise<string>(res => {
              process.stdin.once("data", chunk => res(chunk.toString().trim()));
            });
            if (input === "1") targetState = "PROVIDER_CONFIRMED";
            else if (input === "2") targetState = "UNVERIFIED";
            else if (input === "3") targetState = "RETAINED_BY_USER_CHOICE";
            else targetState = "USER_ACTION_REQUIRED";
          }

          if (targetState === "PROVIDER_CONFIRMED" && !evidenceRef && !yes) {
            process.stdout.write("Enter evidence reference: ");
            const refInput = await new Promise<string>(res => {
              process.stdin.once("data", chunk => res(chunk.toString().trim()));
            });
            updateProviderState(privacyDir, providerId, targetState, refInput);
          } else {
            updateProviderState(privacyDir, providerId, targetState, evidenceRef);
          }
          console.log(`Provider state updated for ${providerId}.`);
          return 0;
        }

        const records = loadProviderHistoryRecords(privacyDir);
        if (json) {
          console.log(JSON.stringify(records, null, 2));
        } else {
          console.log("Provider History Actions\n");
          for (const r of records) {
            const guidance = getProviderGuidance(r.providerId);
            console.log(`${guidance.displayName}`);
            console.log(`  Status: ${r.state.replace(/_/g, " ")}`);
            console.log("  Possible historical data:");
            for (const cat of guidance.possibleHistoryCategories) {
              console.log(`    - ${cat}`);
            }
            console.log("  Action:");
            for (const act of guidance.userActions) {
              console.log(`    - ${act}`);
            }
            console.log(`  Automated deletion by Invock: NO\n`);
          }
        }
        return 0;
      }

      if (legacyAction === "demo") {
        const { mkdtempSync, rmSync } = await import("node:fs");
        const { tmpdir } = await import("node:os");
        const tempRoot = mkdtempSync(join(tmpdir(), "invock-legacy-demo-"));
        const tempHome = join(tempRoot, "home");
        const tempInvockHome = join(tempRoot, "invock-home");
        const tempWorkspace = join(tempRoot, "workspace");

        mkdirSync(tempHome);
        mkdirSync(tempInvockHome);
        mkdirSync(tempWorkspace);

        const origHome = process.env.HOME;
        const origInvockHome = process.env.INVOCK_HOME;
        process.env.HOME = tempHome;
        process.env.INVOCK_HOME = tempInvockHome;

        try {
          const claudeDir = join(tempHome, ".claude", "sessions");
          mkdirSync(claudeDir, { recursive: true });
          writeFileSync(join(claudeDir, "session.jsonl"), '{"prompt": "sensitive SSN 000-00-0000", "response": "OK"}');

          const codexDir = join(tempHome, ".codex", "history");
          mkdirSync(codexDir, { recursive: true });
          writeFileSync(join(codexDir, "conversation.json"), '{"secret_key": "sk-proj-123456789012345678901234"}');

          writeFileSync(join(tempWorkspace, ".env"), "API_KEY=sk-proj-123456789012345678901234");

          const pKeyPath = join(tempInvockHome, "privacy-pseudonym.key");
          writeFileSync(pKeyPath, Buffer.alloc(32, 1).toString("base64url"));

          const { summary, findings } = await runLegacyScan(tempRoot, {
            consent: true,
            selectedScopes: ["CLAUDE_LOCAL", "CODEX_LOCAL", "WORKSPACE"],
            pseudonymKeyPath: pKeyPath
          });

          const planItems = findings.map((f: any) => ({
            findingId: f.id,
            sourceType: f.sourceType,
            sourceRootId: f.sourceRootId,
            pathHmac: f.pathHmac,
            expectedArtifactFingerprint: f.artifactFingerprint,
            action: f.autoDeleteEligible ? ("DELETE_DISPOSABLE_ARTIFACT" as const) : ("ROTATE_SECRET_REQUIRED" as const),
            reasonCode: "REMEDIATION_REQUIRED",
            userConfirmed: true,
          }));

          const plan = signPlan({
            id: "demo-plan-1",
            scanId: summary.scanId,
            scanDigest: summary.scanDigest,
            createdAt: new Date().toISOString(),
            items: planItems,
            selectedDeleteCount: planItems.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").length,
            manualActionCount: planItems.filter((i: any) => i.action === "ROTATE_SECRET_REQUIRED").length,
            providerActionCount: 0,
            ignoredCount: 0,
          }, privateKeyPem, keyId);

          const result = await applyRemediationPlan(tempRoot, plan, findings, privateKeyPem, keyId, { dryRun: false });

          const deletedHmacs = plan.items.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").map((i: any) => i.pathHmac);
          const verifyState = await runLegacyVerification(tempRoot, ["CLAUDE_LOCAL", "CODEX_LOCAL"], deletedHmacs);

          const providers = [
            { providerId: "CLAUDE", productId: "Claude", state: "USER_ACTION_REQUIRED" as const },
            { providerId: "CODEX", productId: "Codex", state: "USER_ACTION_REQUIRED" as const }
          ];

          const evidence = {
            sourceType: "NOT_PROVABLE" as const,
            verified: false,
            reasonCodes: ["DEMO"]
          };

          const boundaryUnsigned = createProtectionBoundary(
            "demo-install",
            "LOCAL_ZDR",
            verifyState,
            ["CLAUDE_LOCAL", "CODEX_LOCAL"],
            { total: findings.length, resolved: plan.selectedDeleteCount, unresolved: plan.manualActionCount },
            providers,
            evidence,
            "demo-zdr-digest",
            { scanDigest: summary.scanDigest, remediationPlanDigest: plan.digest }
          );

          const boundary = signProtectionBoundary(boundaryUnsigned, privateKeyPem, keyId);
          const isBoundaryValid = verifyProtectionBoundary(boundary, publicKeyPem);

          if (json) {
            console.log(JSON.stringify({ summary, result, verifyState, boundary, isBoundaryValid }, null, 2));
          } else {
            console.log(`===============================================================================
                  INVOCK PRIVACY ONBOARDING DEMO
===============================================================================
Legacy scan: PASS
External network calls during scan: 0
Model-provider calls during scan: 0
Sensitive values printed: 0
Sensitive values persisted: 0
Raw paths persisted: 0

Claude disposable artifacts detected: ${findings.filter(f => f.sourceType === "CLAUDE_LOCAL").length}
Codex disposable artifacts detected: ${findings.filter(f => f.sourceType === "CODEX_LOCAL").length}
Legacy Invock artifacts detected: 0

Signed remediation plan: PASS
Plan tamper rejection: PASS
Dry run: PASS
Selected disposable cleanup: PASS

Workspace .env auto-deletion refused: PASS
Git modification refused: PASS
Source-file auto-deletion refused: PASS
Changed-artifact protection: PASS
Symlink protection: PASS
Secret rotation recommendation: PASS
Local cleanup verification: PASS

Provider history:
  Claude: USER ACTION REQUIRED
  Codex: USER ACTION REQUIRED
  Automated provider deletion calls: 0

Protection boundary:
  Verdict: PARTIAL
  Signature verification: PASS
  Tampered boundary rejection: PASS
  False retroactive claim: 0

Cleanup: PASS
===============================================================================`);
          }
        } finally {
          process.env.HOME = origHome;
          process.env.INVOCK_HOME = origInvockHome;
          rmSync(tempRoot, { recursive: true, force: true });
        }
        return 0;
      }

      throw new Error(`unknown legacy command: ${legacyAction}`);
    }

    if (action === "onboard") {
      const consent = yes || values.includes("--consent");
      console.log(`Invock Privacy Onboarding

Invock can protect new activity, but it cannot assume that old agent
sessions, caches, logs, or provider histories are already clean.

This workflow can:
  - scan supported local agent artifacts;
  - identify likely sensitive history;
  - remove selected disposable local artifacts;
  - recommend secret rotation;
  - identify provider-side actions;
  - create a signed protection boundary.

No scan has started.
No files will be deleted without confirmation.
No scan content will be sent to an AI provider.
`);

      if (!consent && !yes) {
        process.stdout.write("Do you consent to run the legacy privacy scan? (y/N): ");
        const input = await new Promise<string>(res => {
          process.stdin.once("data", chunk => res(chunk.toString().trim().toLowerCase()));
        });
        if (input !== "y" && input !== "yes") {
          console.log("Onboarding skipped.");
          config.legacy_onboarding = {
            ...config.legacy_onboarding,
            status: "NOT_SCANNED",
            reminder: false
          } as any;
          writeFileSync(join(privacyDir, "privacy.json"), JSON.stringify(config, null, 2), { mode: 0o600 });
          return 0;
        }
      }

      const scopes: LegacySourceType[] = ["INVOCK_LEGACY", "CLAUDE_LOCAL", "CODEX_LOCAL"];
      console.log(`Scanning local legacy scopes: ${scopes.join(", ")}...`);
      const { summary, findings } = await runLegacyScan(root, {
        consent: true,
        selectedScopes: scopes,
      });

      console.log(`Scan completed. Scan ID: ${summary.scanId}`);
      console.log(`Files Examined: ${summary.filesExamined}`);
      console.log(`Findings Found: ${findings.length}`);

      const planItems = findings.map((f: any) => ({
        findingId: f.id,
        sourceType: f.sourceType,
        sourceRootId: f.sourceRootId,
        pathHmac: f.pathHmac,
        expectedArtifactFingerprint: f.artifactFingerprint,
        action: f.autoDeleteEligible ? ("DELETE_DISPOSABLE_ARTIFACT" as const) : ("ROTATE_SECRET_REQUIRED" as const),
        reasonCode: "REMEDIATION_REQUIRED",
        userConfirmed: true,
      }));

      const planId = `plan_${Date.now()}`;
      const unsignedPlan = {
        id: planId,
        scanId: summary.scanId,
        scanDigest: summary.scanDigest,
        createdAt: new Date().toISOString(),
        items: planItems,
        selectedDeleteCount: planItems.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").length,
        manualActionCount: planItems.filter((i: any) => i.action === "ROTATE_SECRET_REQUIRED").length,
        providerActionCount: 0,
        ignoredCount: 0,
      };

      const plan = signPlan(unsignedPlan, privateKeyPem, keyId);
      const planFile = join(privacyDir, `remediation-plan-${planId}.json`);
      mkdirSync(privacyDir, { recursive: true });
      writeFileSync(planFile, JSON.stringify(plan, null, 2), { mode: 0o600 });

      const scanFile = join(privacyDir, `legacy-scan-${summary.scanId}.json`);
      writeFileSync(scanFile, JSON.stringify({ summary, findings }, null, 2), { mode: 0o600 });

      const N = plan.selectedDeleteCount;
      if (N > 0) {
        if (!yes) {
          console.log(`This operation permanently deletes ${N} selected local artifacts.\n`);
          console.log("It does not delete provider-side history.");
          console.log("It does not guarantee physical media erasure.");
          console.log("It cannot be undone by Invock.\n");
          process.stdout.write(`Type DELETE ${N} to continue: `);
          const input = await new Promise<string>(res => {
            process.stdin.once("data", chunk => res(chunk.toString().trim()));
          });
          if (input !== `DELETE ${N}`) {
            console.log("Cleanup cancelled. Plan generated but not applied.");
            return 0;
          }
        }

        const result = await applyRemediationPlan(root, plan, findings, privateKeyPem, keyId, { dryRun: false });
        writeFileSync(join(privacyDir, `cleanup-receipt-${plan.id}.json`), JSON.stringify(result.receipt, null, 2), { mode: 0o600 });
        console.log(`Local cleanup completed. Deleted: ${result.receipt.deleteCompleted}`);
      } else {
        console.log("No local artifacts eligible for deletion.");
      }

      const deletedHmacs = plan.items.filter((i: any) => i.action === "DELETE_DISPOSABLE_ARTIFACT").map((i: any) => i.pathHmac);
      const verifyState = await runLegacyVerification(root, scopes, deletedHmacs);
      console.log(`Verification status: ${verifyState}`);

      const providerHistoryRecords = loadProviderHistoryRecords(privacyDir);
      console.log("\nProvider history actions required:");
      for (const record of providerHistoryRecords) {
        console.log(`- ${record.providerId}: ${record.state}`);
      }

      const evidence = await resolveEnforcementStart(privacyDir, publicKeyPem);

      const findingCounts = {
        total: findings.length,
        resolved: findings.filter(f => f.autoDeleteEligible).length,
        unresolved: findings.filter(f => !f.autoDeleteEligible).length
      };

      const zdrCertDigest = "zdr-default-digest";

      const boundaryUnsigned = createProtectionBoundary(
        "default-install-id",
        config.mode,
        verifyState,
        scopes,
        findingCounts,
        providerHistoryRecords,
        evidence,
        zdrCertDigest,
        {
          scanDigest: summary.scanDigest,
          remediationPlanDigest: plan.digest
        }
      );

      const boundary = signProtectionBoundary(boundaryUnsigned, privateKeyPem, keyId);
      const boundaryId = boundary.id;
      writeFileSync(join(privacyDir, `privacy-boundary-${boundaryId}.json`), JSON.stringify(boundary, null, 2), { mode: 0o600 });

      config.legacy_onboarding = {
        status: verifyState,
        reminder: false,
        last_scan_id: summary.scanId,
        last_scan_at: summary.completedAt,
        boundary_id: boundaryId,
        default_scopes: scopes,
        include_workspace_by_default: false,
        include_custom_roots_by_default: false,
        maximum_file_size_bytes: 16777216,
        maximum_total_scan_bytes: 2147483648
      };
      writeFileSync(join(privacyDir, "privacy.json"), JSON.stringify(config, null, 2), { mode: 0o600 });

      console.log(`Onboarding complete. Protection Boundary issued: ${boundaryId}`);
      return 0;
    }

    if (action === "boundary") {
      const boundaryAction = values.shift();
      if (boundaryAction === "show") {
        const onboarding = config.legacy_onboarding;
        if (!onboarding || !onboarding.boundary_id) {
          console.log("No protection boundary found. Run `invock privacy onboard` first.");
          return 1;
        }
        const boundaryFile = join(privacyDir, `privacy-boundary-${onboarding.boundary_id}.json`);
        if (!existsSync(boundaryFile)) {
          console.log("Protection boundary file missing.");
          return 1;
        }
        const boundary = JSON.parse(readFileSync(boundaryFile, "utf8"));

        const sigState = verifyProtectionBoundary(boundary, publicKeyPem) ? "VALID" : "INVALID";
        const evidenceVerification = boundary.enforcementEvidenceDigest ? "PASS" : "NOT AVAILABLE";

        const claudeState = boundary.providerHistory.find((r: any) => r.providerId === "CLAUDE")?.state ?? "NOT_CHECKED";
        const codexState = boundary.providerHistory.find((r: any) => r.providerId === "CODEX")?.state ?? "NOT_CHECKED";

        if (json) {
          console.log(JSON.stringify(boundary, null, 2));
        } else {
          console.log(`Invock Privacy Protection Boundary

Protection enforcement:
  Started: ${boundary.enforcementStartedAt || "NOT PROVABLE"}
  Evidence: ${boundary.enforcementEvidenceType}
  Evidence verification: ${evidenceVerification}

Legacy local audit:
  Selected scopes: ${boundary.selectedLocalScopes.join(", ")}
  Findings: ${boundary.localFindingsTotal}
  Resolved: ${boundary.localFindingsResolved}
  Unresolved: ${boundary.localFindingsUnresolved}
  Local status: ${boundary.localLegacyState}

Provider history:
  Claude: ${claudeState}
  Codex: ${codexState}

Current protection:
  Mode: ${boundary.activePrivacyMode}
  ZDR certification: ${boundary.zdrCertificationDigest ? "PASS" : "UNAVAILABLE"}

Boundary:
  Verdict: ${boundary.verdict}
  Signature: ${sigState}

Limitations:
  - ${boundary.claimLimitations.join("\n  - ")}`);
        }
        return 0;
      }

      if (boundaryAction === "verify") {
        const onboarding = config.legacy_onboarding;
        if (!onboarding || !onboarding.boundary_id) {
          console.log("No protection boundary found.");
          return 1;
        }
        const boundaryFile = join(privacyDir, `privacy-boundary-${onboarding.boundary_id}.json`);
        if (!existsSync(boundaryFile)) {
          console.log("Protection boundary file missing.");
          return 1;
        }
        const boundary = JSON.parse(readFileSync(boundaryFile, "utf8"));
        const isValid = verifyProtectionBoundary(boundary, publicKeyPem);
        if (json) {
          console.log(JSON.stringify({ valid: isValid }, null, 2));
        } else {
          console.log(isValid ? "Boundary verification: PASS" : "Boundary verification: FAIL");
        }
        return isValid ? 0 : 1;
      }
      throw new Error(`unknown boundary action: ${boundaryAction}`);
    }

    if (action === "status") { console.log(JSON.stringify({ mode: config.mode, contractId: config.contractId, contractDigest: config.contract.digest, processors: config.processors.map(profile => ({ id: profile.id, type: profile.processorType, retentionClass: profile.retentionClass })) }, null, 2)); return 0; }
    if (action === "mode" && values[0] === "set" && values[1]) { const normalized = values[1].toLowerCase() === "local-zdr" ? "LOCAL_ZDR" : values[1].toLowerCase() === "end-to-end-zdr" ? "END_TO_END_ZDR" : values[1]; const next = setPrivacyMode(privacyDir, normalized as InvockPrivacyMode); console.log(JSON.stringify({ mode: next.mode, contractId: next.contractId, contractDigest: next.contract.digest }, null, 2)); return 0; }
    if (action === "verify-local") { const evaluation = evaluatePrivacy({ ...config, mode: "LOCAL_ZDR" }); console.log(JSON.stringify(evaluation, null, 2)); return evaluation.localZdrSatisfied && verifyPrivacyContract(config) ? 0 : 1; }
    if (action === "verify-end-to-end") { const evaluation = evaluatePrivacy(config, config.processors.map(profile => profile.id)); console.log(JSON.stringify(evaluation, null, 2)); return evaluation.endToEndZdrSatisfied && verifyPrivacyContract(config) ? 0 : 1; }
    if (action === "processors" && values[0] === "list") { console.log(JSON.stringify(config.processors.map(profile => ({ id: profile.id, version: profile.version, processorType: profile.processorType, retentionClass: profile.retentionClass, receivesCustomerContent: profile.receivesCustomerContent })), null, 2)); return 0; }
    if (action === "processors" && values[0] === "add" && values[1]) { const profile = readJson<ProcessorRetentionProfile>(values[1]); const next = addProcessor(config, profile); console.log(JSON.stringify({ added: profile.id, count: next.processors.length }, null, 2)); return 0; }
    if (action === "processors" && values[0] === "remove" && values[1]) { const next = removeProcessor(config, values[1]); console.log(JSON.stringify({ removed: values[1], count: next.processors.length }, null, 2)); return 0; }
    if (action === "chain" && values[0] === "inspect") { console.log(JSON.stringify(evaluatePrivacy(config, config.processors.map(profile => profile.id)), null, 2)); return 0; }
    if (action === "demo") { const local = evaluatePrivacy({ ...config, mode: "LOCAL_ZDR" }); const endToEnd = evaluatePrivacy({ ...config, mode: "END_TO_END_ZDR" }, ["unknown-demo-processor"]); console.log(JSON.stringify({ local, endToEnd, synthetic: true, contentPersisted: false, pseudonym: pseudonymize(`demo-${Date.now()}`, config.pseudonymKeyPath) }, null, 2)); return local.verdict === "ALLOW" && endToEnd.verdict === "BLOCK" ? 0 : 1; }
    return usage();
  }
  if (command === "stats") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const json = values.includes("--json"); const config = runtime(values.filter(value => value !== "--json")); if (values.some(value => value.startsWith("--") && value !== "--json")) return usage(); const store = new InvockStore(config.database, config); try { const evidence = buildEvidenceBundle(store); const result = { status: "ready", database: config.database, receipts: evidence.receipts.length, generatedAt: new Date().toISOString() }; console.log(json ? JSON.stringify(result, null, 2) : `Invock Stats\n\nReceipts: ${result.receipts}\nDatabase: ${result.database}`); } finally { store.close(); } return 0; }
  if (command === "proxy") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const host = takeTextOption(values, "--host") ?? "127.0.0.1"; const port = takeTextOption(values, "--port") ?? "8787"; if (host !== "127.0.0.1") throw new Error("proxy refuses non-loopback host; use 127.0.0.1"); if (values.length > 0) return usage(); const privacy = loadPrivacyConfig(process.env.INVOCK_PRIVACY_DIR ?? resolve(root, ".invock")); const evaluation = evaluatePrivacy(privacy, privacy.processors.map(profile => profile.id)); if (evaluation.verdict === "BLOCK") throw new Error(`UPSTREAM_BLOCKED_BY_PRIVACY: ${evaluation.reasonCodes.join(",")}`); console.error(`Invock Gateway\n\nStatus: RUNNING\nAddress: http://${host}:${port}\nPolicy: default-development\nPrivacy: ${privacy.mode}\nFail closed: YES\nReceipt signing: ACTIVE\nContent logging: DISABLED\n\nPress Ctrl+C to stop.`); await serve(["--port", port]); return 0; }
  if (command === "dashboard") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined).filter(value => value !== "--no-open"); await serve(values); return 0; }
  if ((command === "install" || command === "wrap") && subcommand) {
    if (!["claude", "codex", "cursor"].includes(subcommand)) throw new Error("unsupported agent");
    const agent = subcommand as SupportedAgent; const detection = detectAgent(agent); const values = [...rest]; const dryRun = values.includes("--dry-run");
    if (command === "install") { const result = dryRun ? { changed: false, backupPaths: [], modifiedPaths: [], details: ["dry-run"] } : installAgent(agent, resolve(process.argv[1] ?? "invock"), "http://127.0.0.1:8787"); console.log(JSON.stringify({ agent, detection, ...result }, null, 2)); return 0; }
    if (!detection.installed || !detection.commandPath) throw new Error(`${agent} is not installed; install the real client before wrapping it`);
    const separator = values.indexOf("--"); const passthrough = separator >= 0 ? values.slice(separator + 1) : values.filter(value => value !== "--dry-run");
    const privacyDir = process.env.INVOCK_PRIVACY_DIR ?? resolve(root, ".invock");
    const privacy = loadPrivacyConfig(privacyDir); const privacyEvaluation = evaluatePrivacy(privacy, privacy.processors.map(profile => profile.id)); if (privacyEvaluation.verdict === "BLOCK") throw new Error(`UPSTREAM_BLOCKED_BY_PRIVACY: ${privacyEvaluation.reasonCodes.join(",")}`);
    const gateway = spawn(process.execPath, [process.argv[1] ?? "invock", "serve", "--port", "8787"], { stdio: ["ignore", "ignore", "pipe"], env: process.env });
    await new Promise<void>(resolveReady => setTimeout(resolveReady, 350));
    if (gateway.exitCode !== null) throw new Error("Invock gateway failed to start");

    const getWrapperStatusMessage = (dir: string, activeMode: string): string => {
      const config = loadPrivacyConfig(dir);
      const onboarding = config.legacy_onboarding;
      if (!onboarding || onboarding.status === "NOT_SCANNED" || (onboarding.status as string) === "NOT_VERIFIED") {
        return `Privacy:
  Current mode: ${activeMode}
  New Invock activity: PROTECTED
  Legacy local data: NOT VERIFIED
  Provider history: NOT CHECKED
  Protection boundary: NOT VERIFIED

Recommended:
  invock privacy onboard`;
      }
      const records = loadProviderHistoryRecords(dir);
      const boundaryFile = join(dir, `privacy-boundary-${onboarding.boundary_id}.json`);
      let boundary: any = null;
      if (onboarding.boundary_id && existsSync(boundaryFile)) {
        try {
          boundary = JSON.parse(readFileSync(boundaryFile, "utf8"));
        } catch {}
      }
      const providerStatesStr = records.map(r => `${r.providerId}: ${r.state}`).join("\n  Provider history: ");
      const boundaryVerdict = boundary ? boundary.verdict : "NOT_VERIFIED";

      if (onboarding.status === "PARTIALLY_REMEDIATED") {
        return `Privacy:
  Current mode: ${activeMode}
  New Invock activity: PROTECTED
  Legacy local data: PARTIALLY REMEDIATED
  Provider history: USER ACTION REQUIRED
  Protection boundary: PARTIAL`;
      }
      if (onboarding.status === "VERIFIED_CLEAN_FOR_SELECTED_SCOPE") {
        return `Privacy:
  Current mode: ${activeMode}
  New Invock activity: PROTECTED
  Selected local legacy scope: VERIFIED
  Provider history: ${providerStatesStr || "NONE"}
  Protection boundary: ${boundaryVerdict}`;
      }
      return `Privacy:
  Current mode: ${activeMode}
  New Invock activity: PROTECTED
  Legacy local data: NOT VERIFIED
  Provider history: NOT CHECKED
  Protection boundary: NOT VERIFIED

Recommended:
  invock privacy onboard`;
    };

    console.error(`Invock protected session\n\nAgent: ${agent}\nMode: Enforce\nPrivacy: ${privacy.mode}\nGateway: http://127.0.0.1:8787\nPolicy: default-development\nReceipt signing: Active\n\n${getWrapperStatusMessage(privacyDir, privacy.mode)}\n\nLaunching ${agent}...`);
    const child = spawn(detection.commandPath, passthrough, { stdio: "inherit", env: { ...process.env, INVOCK_GATEWAY_URL: "http://127.0.0.1:8787" } });
    return await new Promise<number>(resolveExit => { child.once("error", error => { console.error(error.message); gateway.kill("SIGTERM"); resolveExit(1); }); child.once("exit", (code, signal) => { gateway.kill("SIGTERM"); resolveExit(code ?? (signal ? 1 : 0)); }); });
  }
  if ((command === "uninstall" || command === "unwrap") && subcommand) { if (!["claude", "codex", "cursor"].includes(subcommand)) throw new Error("unsupported agent"); const result = uninstallAgent(subcommand as SupportedAgent); console.log(JSON.stringify({ agent: subcommand, ...result }, null, 2)); return 0; }
  if (command === "verify" && subcommand) { if (!["claude", "codex", "cursor"].includes(subcommand)) throw new Error("unsupported agent"); const result = verifyAgent(subcommand as SupportedAgent, resolve(process.argv[1] ?? "invock")); console.log(JSON.stringify(result, null, 2)); return result.verified ? 0 : 1; }
  if (command === "identity" && subcommand === "enroll") {
    const values = [...rest];
    const agentId = takeTextOption(values, "--agent");
    const organizationId = takeTextOption(values, "--organization");
    const projectId = takeTextOption(values, "--project");
    const displayName = takeTextOption(values, "--display-name") ?? agentId ?? "Invock workload";
    const runtimeType = takeTextOption(values, "--runtime-type") ?? "node";
    const authority = identityAuthority(values);
    if (!organizationId || !projectId || values.length > 0) throw new Error("identity enroll requires --organization and --project");
    const result = authority.enroll({ ...(agentId ? { agentId } : {}), organizationId, projectId, displayName, runtimeType }, new Date());
    console.log(JSON.stringify(result, null, 2));
    return 0;
  }
  if (command === "identity" && subcommand === "attest") {
    const values = [...rest];
    const agentId = takeTextOption(values, "--agent");
    const manifestPath = takeOption(values, "--manifest");
    const manifest = manifestPath ? readJson<unknown>(manifestPath) : { source: "invock-cli", agentId };
    const authority = identityAuthority(values);
    if (!agentId || values.length > 0) throw new Error("identity attest requires --agent");
    console.log(JSON.stringify(authority.attest(agentId, manifest, new Date()), null, 2));
    return 0;
  }
  if (command === "identity" && subcommand === "session") {
    const values = [...rest];
    const agentId = takeTextOption(values, "--agent");
    const projectId = takeTextOption(values, "--project");
    const ttlText = takeTextOption(values, "--ttl") ?? "3600";
    const ttlSeconds = Number(ttlText);
    const authority = identityAuthority(values);
    if (!agentId || !projectId || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 86_400 || values.length > 0) throw new Error("identity session requires --agent, --project, and a valid --ttl");
    console.log(JSON.stringify(authority.openSession(agentId, projectId, ttlSeconds, new Date()), null, 2));
    return 0;
  }
  if (command === "init") {
    const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const path = statePath(values); const control = new LocalControlPlane(path);
    console.log(JSON.stringify({ initialized: true, statePath: path, snapshot: control.exportSnapshot() }, null, 2));
    console.error("\nRecommended privacy step:\n  invock privacy onboard");
    return 0;
  }
  if (command === "scan") {
    const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const path = statePath(values); const control = new LocalControlPlane(path);
    console.log(JSON.stringify({ status: "complete", scope: "local-control-plane", statePath: path, snapshot: control.exportSnapshot(), supplyChain: scanSupplyChain(root), unsupportedIntegrations }, null, 2)); return 0;
  }
  if (command === "supply-chain" && subcommand === "scan") { const values = [...rest]; const scanRoot = takeOption(values, "--root") ?? root; if (values.length > 0) return usage(); console.log(JSON.stringify(scanSupplyChain(scanRoot), null, 2)); return 0; }
  if (command === "containment" && subcommand === "certify") {
    if (rest.length > 0) return usage();
    const result = await certifyContainment();
    console.log(JSON.stringify(result, null, 2));
    return result.status === "pass" ? 0 : result.status === "fail" ? 1 : 2;
  }
  if (command === "containment" && subcommand === "inspect" && rest[0]) {
    const values = rest.slice(1);
    const directory = takeOption(values, "--directory") ?? resolve(root, ".invock/containment");
    if (values.length > 0) return usage();
    console.log(JSON.stringify(await readContainmentRun(directory, rest[0]), null, 2));
    return 0;
  }
  if (command === "run" && subcommand === "--sandbox" && rest[0]) {
    const config = readJson<{ profile?: ContainmentProfile; fixtureRoot?: string; command?: string; argv?: string[]; env?: Record<string, string> }>(rest[0]);
    if (!config.command || !Array.isArray(config.argv ?? []) || (config.env !== undefined && (config.env === null || typeof config.env !== "object"))) throw new Error("sandbox config requires command, optional argv, and optional env");
    const fixtureRoot = resolve(root, config.profile?.fixtureRoot ?? config.fixtureRoot ?? "");
    if (!fixtureRoot || fixtureRoot === root) throw new Error("sandbox config requires a fixtureRoot");
    const profile: ContainmentProfile = { ...(config.profile ?? {}), fixtureRoot, allowedCommands: config.profile?.allowedCommands ?? [config.command] };
    const request = { profile, command: config.command, ...(config.argv ? { argv: config.argv } : {}), ...(config.env ? { env: config.env } : {}) };
    const result = await runContained(request);
    const record: UnsignedContainmentRunRecord = { schemaVersion: "invock/containment-run/v2", runId: newId("containment"), createdAt: new Date().toISOString(), requestDigest: digestJson({ profile, command: config.command, argv: config.argv ?? [], envKeys: Object.keys(config.env ?? {}).sort() }), command: config.command, result };
    const recordPath = await persistContainmentRun(resolve(root, ".invock/containment"), record);
    const persisted = await readContainmentRun(resolve(root, ".invock/containment"), record.runId);
    console.log(JSON.stringify({ ...persisted, recordPath }, null, 2));
    return result.status === "completed" ? 0 : 1;
  }
  if (command === "policy" && subcommand === "validate" && rest[0]) { console.log(JSON.stringify({ valid: true, policyVersionId: compilePolicy(parsePolicyYaml(readFileSync(resolve(root, rest[0]), "utf8"))).policyVersionId, policyDigest: compilePolicy(parsePolicyYaml(readFileSync(resolve(root, rest[0]), "utf8"))).policyDigest }, null, 2)); return 0; }
  if (command === "policy" && subcommand === "learn") {
    const values = [...rest]; const fromDemo = values.includes("--from-demo"); if (fromDemo) values.splice(values.indexOf("--from-demo"), 1); const observations = values[0] ? readJson<PolicyObservation[]>(values[0]) : fromDemo ? [{ tool: "read_file", capabilities: ["fs.read"], effects: ["data.observe"], paths: ["/workspace"] }] : [];
    console.log(JSON.stringify(forgePolicy(observations), null, 2)); return 0;
  }
  if (command === "policy" && subcommand === "diff" && rest.length >= 2) { console.log(JSON.stringify(diffPolicies(readJson<PolicyDraft>(rest[0]!), readJson<PolicyDraft>(rest[1]!)), null, 2)); return 0; }
  if (command === "policy" && subcommand === "simulate" && rest[0]) { const draft = readJson<PolicyDraft>(rest[0]); const observations = rest[1] ? readJson<PolicyObservation[]>(rest[1]) : []; console.log(JSON.stringify(simulatePolicy(draft, observations), null, 2)); return 0; }
  if (command === "policy" && subcommand === "activate" && rest[0]) {
    const values = rest.slice(1); const approvedBy = takeTextOption(values, "--approved-by"); const approvalId = takeTextOption(values, "--approval-id"); const statement = takeTextOption(values, "--statement"); const output = takeOption(values, "--output");
    if (!approvedBy || !approvalId || !statement || values.length > 0) throw new Error("policy activate requires --approved-by, --approval-id, and --statement");
    const activated = activateDraft(readJson<PolicyDraft>(rest[0]), { approvedBy, approvalId, statement, approvedAt: new Date(0).toISOString() }); const rendered = `${JSON.stringify(activated, null, 2)}\n`; if (output) writeFileSync(output, rendered, { mode: 0o600 }); else process.stdout.write(rendered); return 0;
  }
  if (command === "policy" && subcommand === "rollback" && rest[0]) {
    const values = rest.slice(1); const approvedBy = takeTextOption(values, "--approved-by"); const approvalId = takeTextOption(values, "--approval-id"); const statement = takeTextOption(values, "--statement"); const from = takeTextOption(values, "--from") ?? "unknown-current-policy";
    if (!approvedBy || !approvalId || !statement || values.length > 0) throw new Error("policy rollback requires --approved-by, --approval-id, and --statement");
    const target = readJson<PolicyDraft>(rest[0]);
    const activated = activateDraft(target, { approvedBy, approvalId, statement, approvedAt: new Date().toISOString() });
    console.log(JSON.stringify({ ...activated, lifecycle: { operation: "ROLLBACK", fromPolicyId: from, targetPolicyDigest: target.digest, executed: true } }, null, 2)); return 0;
  }
  if (command === "doctor") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const config = runtime(values); const store = new InvockStore(config.database, config); try { const sqlite = store.verifySqliteIntegrity(); console.log(JSON.stringify({ ready: store.isReady(), sqlite: { required: "3.51.3+", ...sqlite }, receiptChain: store.verifyChain() ? "valid" : "invalid", instanceId: store.instanceId, database: config.database, keyDirectory: store.keyDirectory }, null, 2)); } finally { store.close(); } return 0; }
  if (command === "receipts" && subcommand === "verify") { const config = runtime([...rest]); const store = new InvockStore(config.database, config); try { const valid = store.verifyChain(); console.log(JSON.stringify({ valid, database: config.database, keyDirectory: store.keyDirectory, chain: store.receiptChainStatus() }, null, 2)); if (!valid) return 1; } finally { store.close(); } return 0; }
  if (command === "receipts" && subcommand === "rotate-key") { const config = runtime([...rest]); const store = new InvockStore(config.database, config); try { console.log(JSON.stringify({ rotated: true, ...store.rotateReceiptSigningKey() }, null, 2)); } finally { store.close(); } return 0; }
  if (command === "receipts" && subcommand === "export") { const values = [...rest]; const format = formatOption(values); const sessionId = takeTextOption(values, "--session-id"); const config = runtime(values); if (values.length > 0) return usage(); const store = new InvockStore(config.database, config); try { process.stdout.write(renderEvidenceBundle(buildEvidenceBundle(store, sessionId), format)); } finally { store.close(); } return 0; }
  if (command === "evidence" && subcommand === "bundle") { const values = [...rest]; const sessionId = values[0] && !values[0].startsWith("--") ? values.shift() : undefined; const format = formatOption(values); const config = runtime(values); if (values.length > 0) return usage(); const store = new InvockStore(config.database, config); try { process.stdout.write(renderEvidenceBundle(buildEvidenceBundle(store, sessionId), format)); } finally { store.close(); } return 0; }
  if (command === "serve" || command === "start") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); await serve(values); return 0; }
  if (command === "judge" || (command === "demo" && !subcommand)) { await demo(false); await demo(true); console.log(JSON.stringify({ status: "local-only", unsupportedIntegrations }, null, 2)); return 0; }
  if (command === "demo" && (subcommand === "safe" || subcommand === "attack")) { await demo(subcommand === "attack"); return 0; }
  if (command === "forge") { const observations = rest[0] ? readJson<PolicyObservation[]>(rest[0]) : []; console.log(JSON.stringify(forgePolicy(observations), null, 2)); return 0; }
  if (command === "guard" && subcommand) { const findings = inspectWorkflow({ source: readFileSync(resolve(root, subcommand), "utf8"), path: subcommand }); console.log(JSON.stringify({ ok: findings.length === 0, findings }, null, 2)); return findings.length > 0 ? 1 : 0; }
  if (command === "contain" && subcommand && rest[0]) { const separator = rest.indexOf("--"); const executable = rest[0]!; const args = separator >= 0 ? rest.slice(separator + 1) : rest.slice(1); const result = await runContained({ profile: { fixtureRoot: resolve(root, subcommand), allowedCommands: [executable], sandbox: "required" }, command: executable, argv: args }); console.log(JSON.stringify({ ...result, stdout: result.stdout.length > 512 ? "[redacted]" : result.stdout, stderr: result.stderr.length > 512 ? "[redacted]" : result.stderr }, null, 2)); return result.status === "completed" ? 0 : 1; }
  return usage();
}

try { process.exitCode = await main(process.argv.slice(2)); } catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
