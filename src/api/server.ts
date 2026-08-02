import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { newId } from "../core/canonical.js";
import { InvocationGate, type GateOutcome, type InvocationRuntimeOverrides } from "../gateway/engine.js";
import type { InvockStore } from "../storage/store.js";
import { buildReportViewModel, type ActivityRecord } from "../ui/report.js";
import type { ToolResult } from "../core/types.js";
import type { ContainmentRunRecord } from "../containment/lifecycle.js";

const MAX_BODY = 256 * 1024;
export interface ApiAuthorizeInput {
  readonly agent?: string;
  readonly projectId?: string;
  readonly tool: string;
  readonly arguments: Record<string, unknown>;
  readonly intentCapsule?: unknown;
  readonly authorityBinding?: unknown;
  readonly capabilityLeases?: readonly unknown[];
  readonly sessionId?: string;
}
export interface ApiAuthorizeResult {
  readonly verdict: "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED";
  readonly reasonCodes: readonly string[];
  readonly receiptId?: string;
  readonly approvalId?: string;
  readonly authorizedArguments?: Record<string, unknown>;
  readonly containmentRequired?: boolean;
}
export interface ApiExecutionResult {
  readonly content: ReadonlyArray<{ readonly type: "text"; readonly text: string }>;
  readonly structuredContent?: Record<string, unknown>;
  readonly isError?: boolean;
}
export interface ApiExecutionResponse extends ApiAuthorizeResult {
  readonly result?: ApiExecutionResult;
}
export interface ApiRuntimeResolution {
  readonly overrides?: InvocationRuntimeOverrides;
  readonly denial?: ApiAuthorizeResult;
}
export type ApiRuntimeResolver = (input: ApiAuthorizeInput) => Promise<ApiRuntimeResolution | undefined>;
export interface ApiContainedForwardResult { readonly result: ToolResult; readonly containment: ContainmentRunRecord; }
/** The handler receives only the canonical authorized request; raw API input is never forwarded. */
export type ApiContainedForwardHandler = (outcome: Extract<GateOutcome, { kind: "forward" }>) => Promise<ApiContainedForwardResult>;
export interface ApiOptions {
  readonly host?: string;
  readonly port?: number;
  readonly token?: string;
  /** Trusted session partition selected by the server owner, never by a request body. */
  readonly sessionId?: string;
  readonly allowRemote?: boolean;
  readonly allowedOrigins?: string[];
  /** Every authorization request is evaluated by this canonical gate. */
  readonly gate?: InvocationGate;
  /** Resolves identity/authority context; it cannot replace the canonical gate. */
  readonly resolveRuntime?: ApiRuntimeResolver;
  /** Runs only for the explicit execution endpoint when the canonical gate returns a forwardable call. */
  readonly onContainedForward?: ApiContainedForwardHandler;
  readonly privacyState?: { readonly mode: "LOCAL_ZDR" | "END_TO_END_ZDR"; readonly verdict: "ALLOW" | "BLOCK"; readonly contractDigest: string; readonly chainDigest: string };
}
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" }).end(JSON.stringify(value)); }
async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let length = 0;
  for await (const chunk of request) { const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); length += data.length; if (length > MAX_BODY) throw new Error("Request body exceeds 256 KiB"); chunks.push(data); }
  const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("JSON body must be an object");
  return value as Record<string, unknown>;
}
function authorizeInput(value: Record<string, unknown>, serverSessionId?: string): ApiAuthorizeInput {
  for (const key of Object.keys(value)) if (!["agent", "projectId", "tool", "arguments", "intentCapsule", "authorityBinding", "capabilityLeases", "sessionId"].includes(key)) throw new Error(`Unknown authorization field: ${key}`);
  if (value.agent !== undefined && (typeof value.agent !== "string" || value.agent.trim().length === 0)) throw new Error("agent must be a non-empty string");
  if (value.projectId !== undefined && (typeof value.projectId !== "string" || value.projectId.trim().length === 0)) throw new Error("projectId must be a non-empty string");
  if (value.sessionId !== undefined && (typeof value.sessionId !== "string" || value.sessionId.trim().length === 0)) throw new Error("sessionId must be a non-empty string");
  if (value.sessionId !== undefined && serverSessionId === undefined) throw new Error("sessionId must be server-bound");
  if (value.sessionId !== undefined && value.sessionId !== serverSessionId) throw new Error("sessionId does not match server binding");
  if (typeof value.tool !== "string" || value.tool.trim().length === 0) throw new Error("tool must be a non-empty string");
  if (value.arguments === null || Array.isArray(value.arguments) || typeof value.arguments !== "object") throw new Error("arguments must be an object");
  if (value.capabilityLeases !== undefined && (!Array.isArray(value.capabilityLeases) || value.capabilityLeases.length === 0)) throw new Error("capabilityLeases must be a non-empty array when supplied");
  return {
    tool: value.tool,
    arguments: value.arguments as Record<string, unknown>,
    ...(typeof value.agent === "string" ? { agent: value.agent } : {}),
    ...(typeof value.projectId === "string" ? { projectId: value.projectId } : {}),
    ...(value.intentCapsule !== undefined ? { intentCapsule: value.intentCapsule } : {}),
    ...(value.authorityBinding !== undefined ? { authorityBinding: value.authorityBinding } : {}),
    ...(Array.isArray(value.capabilityLeases) ? { capabilityLeases: [...value.capabilityLeases] } : {}),
    ...(serverSessionId !== undefined ? { sessionId: serverSessionId } : {}),
  };
}
function safeTokenMatch(actual: string | undefined, expected: string): boolean {
  if (!actual?.startsWith("Bearer ")) return false;
  const a = Buffer.from(actual.slice(7)); const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
function requestFor(input: ApiAuthorizeInput) {
  return { jsonrpc: "2.0" as const, id: newId("api"), method: "tools/call" as const, params: { name: input.tool, arguments: input.arguments } };
}
function resultFor(outcome: GateOutcome): ApiAuthorizeResult {
  if (outcome.kind === "forward") return { verdict: outcome.decision.verdict, reasonCodes: outcome.decision.reasonCodes, authorizedArguments: (outcome.request.params.arguments ?? {}) as Record<string, unknown>, containmentRequired: outcome.containmentRequired };
  if (outcome.kind === "notification") return { verdict: outcome.decision.verdict, reasonCodes: outcome.decision.reasonCodes, receiptId: outcome.receiptId };
  const structured = (outcome.response.result.structuredContent ?? {}) as Record<string, unknown>;
  const verdict = structured.verdict === "ALLOW" || structured.verdict === "BLOCK" || structured.verdict === "APPROVAL_REQUIRED"
    ? structured.verdict
    : outcome.response.result.isError ? "BLOCK" : "ALLOW";
  const reasonCodes = Array.isArray(structured.reasonCodes) && structured.reasonCodes.every(item => typeof item === "string") ? structured.reasonCodes : [];
  return { verdict, reasonCodes, ...(typeof structured.receiptId === "string" ? { receiptId: structured.receiptId } : {}), ...(typeof structured.approvalId === "string" ? { approvalId: structured.approvalId } : {}) };
}
const MAX_EXECUTION_RESULT_BYTES = 128 * 1024;
const MAX_RESULT_CONTENT_ITEMS = 128;
const MAX_RESULT_TEXT_BYTES = 64 * 1024;
const MAX_RESULT_DEPTH = 16;
const MAX_RESULT_NODES = 4096;
function boundedJson(value: unknown, depth = 0, state = { nodes: 0 }): boolean {
  if (depth > MAX_RESULT_DEPTH || ++state.nodes > MAX_RESULT_NODES) return false;
  if (value === null || typeof value === "boolean" || typeof value === "number") return typeof value !== "number" || Number.isFinite(value);
  if (typeof value === "string") return Buffer.byteLength(value, "utf8") <= MAX_RESULT_TEXT_BYTES;
  if (Array.isArray(value)) return value.length <= MAX_RESULT_CONTENT_ITEMS && value.every(item => boundedJson(item, depth + 1, state));
  if (value === null || typeof value !== "object") return false;
  const keys = Object.keys(value as Record<string, unknown>);
  return keys.length <= MAX_RESULT_NODES && keys.every(key => key.length <= 512 && boundedJson((value as Record<string, unknown>)[key], depth + 1, state));
}
function boundedExecutionResult(value: unknown): ApiExecutionResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("MALFORMED_CONTAINED_RESULT");
  const candidate = value as Record<string, unknown>;
  if (!Array.isArray(candidate.content) || candidate.content.length === 0 || candidate.content.length > MAX_RESULT_CONTENT_ITEMS) throw new Error("MALFORMED_CONTAINED_RESULT");
  const content = candidate.content.map(item => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw new Error("MALFORMED_CONTAINED_RESULT");
    const entry = item as Record<string, unknown>;
    if (entry.type !== "text" || typeof entry.text !== "string" || Object.keys(entry).some(key => key !== "type" && key !== "text") || Buffer.byteLength(entry.text, "utf8") > MAX_RESULT_TEXT_BYTES) throw new Error("MALFORMED_CONTAINED_RESULT");
    return { type: "text" as const, text: entry.text };
  });
  if (candidate.structuredContent !== undefined && (candidate.structuredContent === null || typeof candidate.structuredContent !== "object" || Array.isArray(candidate.structuredContent) || !boundedJson(candidate.structuredContent))) throw new Error("MALFORMED_CONTAINED_RESULT");
  if (candidate.isError !== undefined && typeof candidate.isError !== "boolean") throw new Error("MALFORMED_CONTAINED_RESULT");
  const result: ApiExecutionResult = { content, ...(candidate.structuredContent !== undefined ? { structuredContent: { ...(candidate.structuredContent as Record<string, unknown>) } } : {}), ...(typeof candidate.isError === "boolean" ? { isError: candidate.isError } : {}) };
  try {
    if (Buffer.byteLength(JSON.stringify(result), "utf8") > MAX_EXECUTION_RESULT_BYTES) throw new Error("EXECUTION_RESULT_TOO_LARGE");
  } catch (error) {
    if (error instanceof Error && error.message === "EXECUTION_RESULT_TOO_LARGE") throw error;
    throw new Error("MALFORMED_CONTAINED_RESULT");
  }
  return result;
}
function boundedToolResult(value: unknown): ToolResult {
  const result = boundedExecutionResult(value);
  return {
    content: result.content.map(item => ({ type: item.type, text: item.text })),
    ...(result.structuredContent !== undefined ? { structuredContent: { ...result.structuredContent } } : {}),
    ...(result.isError !== undefined ? { isError: result.isError } : {}),
  };
}
function dashboard(): string { return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invock</title>
<style>
body{margin:0;background:#07111f;color:#e7eefb;font:15px system-ui,sans-serif}
main{max-width:1100px;margin:40px auto;padding:0 24px}
h1{letter-spacing:-.04em}
small{color:#93a4bd}
section{background:#0d1b2e;border:1px solid #193554;border-radius:12px;padding:20px;margin:18px 0}
table{width:100%;border-collapse:collapse}
td,th{padding:9px;border-bottom:1px solid #193554;text-align:left}
.ALLOW{color:#46d891}.BLOCK{color:#ff7285}.APPROVAL_REQUIRED{color:#ffc766}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
:focus-visible{outline:3px solid #7dd3fc;outline-offset:3px}
@media (prefers-reduced-motion: reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
</style>
<main>
<h1>Invock <small>local reference monitor</small></h1>
<p>Enter the local dashboard token to inspect redacted activity and approvals.</p>
<div id="status" role="status" aria-live="polite">Enter a token to load the dashboard.</div>
<section><h2>Privacy</h2><div id="privacy">Loading content-free privacy state.</div></section>
<section>
<label for="token">Bearer token <input id="token" type="password" autocomplete="off"></label>
<button id="load-button" type="button" onclick="load()">Load</button>
</section>
<section><h2>Activity</h2><table><caption>Recent authorized activity</caption><thead><tr><th>Time</th><th>Tool</th><th>Verdict</th><th>Status</th><th>Receipt</th></tr></thead><tbody id="activity"></tbody></table></section>
<section><h2>Approvals</h2><div id="approvals">Load activity to view.</div></section>
</main>
<script>
const h=()=>({Authorization:'Bearer '+document.querySelector('#token').value});
const esc=v=>String(v).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const status=document.querySelector('#status');
const main=document.querySelector('main');
async function load(){
  status.textContent='Loading activity and approvals.';
  main.setAttribute('aria-busy','true');
  try{
    let p=await fetch('/api/v1/privacy');
    if(p.ok){let z=await p.json();document.querySelector('#privacy').textContent=z.mode+' · '+z.verdict;}
    let a=await fetch('/api/v1/activity',{headers:h()});
    if(!a.ok) throw new Error('Activity request failed');
    let x=await a.json();
    document.querySelector('#activity').innerHTML=(x.items||[]).map(v=>'<tr><td>'+esc(v.createdAt)+'</td><td><code>'+esc(v.toolName)+'</code></td><td class="'+esc(v.verdict)+'">'+esc(v.verdict)+'</td><td>'+esc(v.status)+'</td><td><code>'+esc(v.receiptId||'pending')+'</code></td></tr>').join('');
    let b=await fetch('/api/v1/approvals',{headers:h()});
    if(!b.ok) throw new Error('Approvals request failed');
    let y=await b.json();
    document.querySelector('#approvals').innerHTML=(y.items||[]).map(v=>'<p><code>'+esc(v.approvalId)+'</code> · '+esc(v.status)+' · binding <code>'+esc(v.bindingDigest)+'</code></p>').join('')||'No approvals.';
    status.textContent='Dashboard data loaded.';
  }catch(error){
    status.textContent=error instanceof Error ? error.message : 'Dashboard data could not be loaded.';
  }finally{main.removeAttribute('aria-busy');}
}
</script>`; }

export interface ApiHandle { server: Server; token: string; url: string; close(): Promise<void>; }
export function startApi(store: InvockStore, options: ApiOptions = {}): Promise<ApiHandle> {
  if (options.resolveRuntime && !options.gate) throw new Error("runtime resolver requires a canonical InvocationGate");
  if (options.sessionId !== undefined && (options.sessionId.trim().length === 0 || options.sessionId.length > 512)) throw new Error("API sessionId must be a bounded non-empty string");
  const host = options.host ?? "127.0.0.1"; const token = options.token ?? randomBytes(32).toString("base64url");
  const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1";
  if (!loopback && options.allowRemote !== true) throw new Error("Remote API binding requires allowRemote: true");
  const attempts = new Map<string, { count: number; resetAt: number }>();
  const server = createServer((request, response) => { void (async () => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? host}`);
    const hostHeader = request.headers.host ?? "";
    if (loopback ? !/^(127\.0\.0\.1|localhost|\[::1\])(\:\d+)?$/i.test(hostHeader) : !hostHeader.startsWith(host)) { json(response, 403, { error: "invalid_host" }); return; }
    const origin = request.headers.origin;
    if (origin && origin !== `http://${hostHeader}` && !(options.allowedOrigins ?? []).includes(origin)) { json(response, 403, { error: "invalid_origin" }); return; }
    if (url.pathname === "/") { response.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'" }).end(dashboard()); return; }
    if (url.pathname === "/api/v1/health") { json(response, 200, { status: "ok" }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/privacy") { json(response, 200, { mode: options.privacyState?.mode ?? "LOCAL_ZDR", verdict: options.privacyState?.verdict ?? "ALLOW", contractDigest: options.privacyState?.contractDigest ?? "unconfigured", chainDigest: options.privacyState?.chainDigest ?? "unconfigured" }); return; }
    if (!safeTokenMatch(request.headers.authorization, token)) { json(response, 401, { error: "unauthorized" }); return; }
    const remote = request.socket.remoteAddress ?? "unknown"; const now = Date.now(); const current = attempts.get(remote); const bounded = !current || current.resetAt < now ? { count: 0, resetAt: now + 60_000 } : current; bounded.count++; attempts.set(remote, bounded);
    if (bounded.count > 120) { json(response, 429, { error: "rate_limited" }); return; }
    if (request.method === "POST" && url.pathname === "/api/v1/authorize") {
      if (!options.gate) { json(response, 503, { error: "authorization_gate_unavailable" }); return; }
      if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) { json(response, 400, { error: "json_required" }); return; }
      const input = authorizeInput(await body(request), options.sessionId);
      const resolution = await options.resolveRuntime?.(input);
      if (resolution?.denial) { json(response, 200, resolution.denial); return; }
      if (options.sessionId !== undefined && resolution?.overrides?.sessionId !== undefined && resolution.overrides.sessionId !== options.sessionId) { json(response, 200, { verdict: "BLOCK", reasonCodes: ["API_SESSION_BINDING_MISMATCH"] }); return; }
      const overrides = { ...(resolution?.overrides ?? {}), ...(options.sessionId !== undefined ? { sessionId: options.sessionId } : {}) };
      const outcome = await options.gate.authorizeInvocation(requestFor(input), Object.keys(overrides).length > 0 ? overrides : undefined);
      // Authorization is intentionally non-executing. Side effects and receipt
      // completion belong to the explicit /execute endpoint below.
      json(response, 200, resultFor(outcome)); return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/execute") {
      if (!options.gate) { json(response, 503, { error: "authorization_gate_unavailable" }); return; }
      if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) { json(response, 400, { error: "json_required" }); return; }
      const input = authorizeInput(await body(request), options.sessionId);
      const resolution = await options.resolveRuntime?.(input);
      if (resolution?.denial) { json(response, 200, resolution.denial); return; }
      if (options.sessionId !== undefined && resolution?.overrides?.sessionId !== undefined && resolution.overrides.sessionId !== options.sessionId) { json(response, 200, { verdict: "BLOCK", reasonCodes: ["API_SESSION_BINDING_MISMATCH"] }); return; }
      const overrides = { ...(resolution?.overrides ?? {}), ...(options.sessionId !== undefined ? { sessionId: options.sessionId } : {}) };
      const outcome = await options.gate.authorizeInvocation(requestFor(input), Object.keys(overrides).length > 0 ? overrides : undefined);
      if (outcome.kind !== "forward") { json(response, 200, resultFor(outcome)); return; }
      const containedForward = options.onContainedForward;
      if (!containedForward) { json(response, 200, resultFor(options.gate.rejectForward(outcome, "CONTAINED_EXECUTION_UNAVAILABLE"))); return; }
      let execution: ApiContainedForwardResult;
      let boundedResult: ApiExecutionResult;
      let attached: Extract<GateOutcome, { kind: "forward" }> = outcome;
      let receiptId: string;
      try {
        execution = await containedForward(outcome);
        boundedResult = boundedExecutionResult(execution.result);
        attached = options.gate.attachContainmentRun(outcome, execution.containment);
        receiptId = options.gate.finish(attached, boundedToolResult(boundedResult));
      } catch {
        json(response, 200, resultFor(options.gate.rejectForward(attached, "CONTAINED_EXECUTION_FAILED"))); return;
      }
      json(response, 200, { verdict: "ALLOW", reasonCodes: outcome.decision.reasonCodes, receiptId, result: boundedResult } satisfies ApiExecutionResponse); return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/ready") { const ready = store.isReady(); json(response, ready ? 200 : 503, { ready }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/activity") { const records = store.listActivity(Number(url.searchParams.get("limit") ?? 50)) as ActivityRecord[]; json(response, 200, { items: buildReportViewModel(records).items }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/approvals") { json(response, 200, { items: store.listApprovals() }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/tools") { json(response, 200, { items: store.listToolRegistry() }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/expansions") { json(response, 200, { items: store.listExpansionRecords(url.searchParams.get("type") ?? undefined) }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/policies") { json(response, 200, { status: "loaded_at_startup" }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/receipts") { json(response, 200, store.receiptChainStatus()); return; }
    const receipt = /^\/api\/v1\/receipts\/([^/]+)$/u.exec(url.pathname);
    if (request.method === "GET" && receipt?.[1]) { const found = store.getReceipt(receipt[1]); json(response, found ? 200 : 404, found ?? { error: "not_found" }); return; }
    const approve = /^\/api\/v1\/approvals\/([^/]+)\/approve$/u.exec(url.pathname);
    if (request.method === "POST" && approve?.[1]) { if (request.headers["idempotency-key"] === undefined || request.headers["content-type"] !== "application/json") { json(response, 400, { error: "idempotency_key_and_json_required" }); return; } const payload = await body(request); const ok = typeof payload.expectedBindingDigest === "string" && store.approve(approve[1], payload.expectedBindingDigest); json(response, ok ? 200 : 409, { approved: ok }); return; }
    const reject = /^\/api\/v1\/approvals\/([^/]+)\/reject$/u.exec(url.pathname);
    if (request.method === "POST" && reject?.[1]) { if (request.headers["idempotency-key"] === undefined || request.headers["content-type"] !== "application/json") { json(response, 400, { error: "idempotency_key_and_json_required" }); return; } const payload = await body(request); const ok = typeof payload.expectedBindingDigest === "string" && store.reject(reject[1], payload.expectedBindingDigest); json(response, ok ? 200 : 409, { rejected: ok }); return; }
    const pathMod = await import("node:path");
    const fsMod = await import("node:fs");
    const privacyDir = process.env.INVOCK_PRIVACY_DIR ?? pathMod.resolve(".invock");

    if (request.method === "GET" && url.pathname === "/api/privacy/legacy/status") {
      const { loadPrivacyConfig } = await import("../privacy/index.js");
      const config = loadPrivacyConfig(privacyDir);
      const onboarding = config.legacy_onboarding;
      json(response, 200, { status: onboarding?.status ?? "NOT_SCANNED" });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/privacy/legacy/scans") {
      const files = fsMod.existsSync(privacyDir) ? fsMod.readdirSync(privacyDir).filter(f => f.startsWith("legacy-scan-") && f.endsWith(".json")) : [];
      const scans = files.map(file => {
        try {
          const data = JSON.parse(fsMod.readFileSync(pathMod.join(privacyDir, file), "utf8"));
          return {
            scanId: data.summary.scanId,
            startedAt: data.summary.startedAt,
            completedAt: data.summary.completedAt,
            filesExamined: data.summary.filesExamined,
            findingsCount: data.summary.findings
          };
        } catch { return null; }
      }).filter(Boolean);
      json(response, 200, { scans });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/privacy/legacy/findings/summary") {
      const { loadPrivacyConfig } = await import("../privacy/index.js");
      const config = loadPrivacyConfig(privacyDir);
      const lastScanId = config.legacy_onboarding?.last_scan_id;
      if (lastScanId && fsMod.existsSync(pathMod.join(privacyDir, `legacy-scan-${lastScanId}.json`))) {
        try {
          const scanData = JSON.parse(fsMod.readFileSync(pathMod.join(privacyDir, `legacy-scan-${lastScanId}.json`), "utf8"));
          const summary = scanData.findings.map((f: any) => ({
            id: f.id,
            sourceType: f.sourceType,
            format: f.format,
            severity: f.severity,
            matchCount: f.matchCount,
            autoDeleteEligible: f.autoDeleteEligible,
            recommendedActions: f.recommendedActions
          }));
          json(response, 200, { findings: summary });
          return;
        } catch {}
      }
      json(response, 200, { findings: [] });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/privacy/legacy/plans") {
      const files = fsMod.existsSync(privacyDir) ? fsMod.readdirSync(privacyDir).filter(f => f.startsWith("remediation-plan-") && f.endsWith(".json")) : [];
      const plans = files.map(file => {
        try {
          const data = JSON.parse(fsMod.readFileSync(pathMod.join(privacyDir, file), "utf8"));
          return {
            id: data.id,
            scanId: data.scanId,
            createdAt: data.createdAt,
            selectedDeleteCount: data.selectedDeleteCount,
            manualActionCount: data.manualActionCount,
            digest: data.digest
          };
        } catch { return null; }
      }).filter(Boolean);
      json(response, 200, { plans });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/privacy/legacy/provider-actions") {
      const { loadProviderHistoryRecords } = await import("../privacy/legacy/provider-history.js");
      const records = loadProviderHistoryRecords(privacyDir);
      const safeRecords = records.map(r => ({
        providerId: r.providerId,
        productId: r.productId,
        state: r.state,
        evidenceDigest: r.evidenceDigest,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt
      }));
      json(response, 200, { providerActions: safeRecords });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/privacy/boundary") {
      const { loadPrivacyConfig } = await import("../privacy/index.js");
      const config = loadPrivacyConfig(privacyDir);
      const boundaryId = config.legacy_onboarding?.boundary_id;
      if (boundaryId && fsMod.existsSync(pathMod.join(privacyDir, `privacy-boundary-${boundaryId}.json`))) {
        try {
          const boundary = JSON.parse(fsMod.readFileSync(pathMod.join(privacyDir, `privacy-boundary-${boundaryId}.json`), "utf8"));
          json(response, 200, boundary);
          return;
        } catch {}
      }
      json(response, 404, { error: "not_found" });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/privacy/boundary/verification") {
      const { loadPrivacyConfig } = await import("../privacy/index.js");
      const config = loadPrivacyConfig(privacyDir);
      const boundaryId = config.legacy_onboarding?.boundary_id;
      if (boundaryId && fsMod.existsSync(pathMod.join(privacyDir, `privacy-boundary-${boundaryId}.json`))) {
        try {
          const boundary = JSON.parse(fsMod.readFileSync(pathMod.join(privacyDir, `privacy-boundary-${boundaryId}.json`), "utf8"));
          const publicKeyPath = pathMod.join(privacyDir, "receipt-ed25519.public.pem");
          const publicKeyPem = fsMod.existsSync(publicKeyPath) ? fsMod.readFileSync(publicKeyPath, "utf8") : "";
          const { verifyProtectionBoundary } = await import("../privacy/legacy/boundary.js");
          const valid = verifyProtectionBoundary(boundary, publicKeyPem);
          json(response, 200, { boundaryId, valid });
          return;
        } catch {}
      }
      json(response, 200, { valid: false });
      return;
    }

    json(response, 404, { error: "not_found" });
  })().catch(() => json(response, 400, { error: "bad_request" })); });
  return new Promise((resolve, reject) => { server.once("error", reject); server.listen(options.port ?? 0, host, () => { const address = server.address(); if (!address || typeof address === "string") return reject(new Error("Unable to bind API")); resolve({ server, token, url: `http://${host}:${address.port}`, close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())) }); }); });
}
