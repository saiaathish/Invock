import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { InvockStore } from "../storage/store.js";

const MAX_BODY = 256 * 1024;
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" }).end(JSON.stringify(value)); }
async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let length = 0;
  for await (const chunk of request) { const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); length += data.length; if (length > MAX_BODY) throw new Error("Request body exceeds 256 KiB"); chunks.push(data); }
  const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("JSON body must be an object");
  return value as Record<string, unknown>;
}
function safeTokenMatch(actual: string | undefined, expected: string): boolean {
  if (!actual?.startsWith("Bearer ")) return false;
  const a = Buffer.from(actual.slice(7)); const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
function dashboard(): string { return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Invock</title><style>body{margin:0;background:#07111f;color:#e7eefb;font:15px system-ui,sans-serif}main{max-width:1100px;margin:40px auto;padding:0 24px}h1{letter-spacing:-.04em}small{color:#93a4bd}section{background:#0d1b2e;border:1px solid #193554;border-radius:12px;padding:20px;margin:18px 0}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #193554;text-align:left}.ALLOW{color:#46d891}.BLOCK{color:#ff7285}.APPROVAL_REQUIRED{color:#ffc766}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style><main><h1>Invock <small>local reference monitor</small></h1><p>Enter the local dashboard token to inspect redacted activity and approvals.</p><section><label>Bearer token <input id="token" type="password" autocomplete="off"></label> <button onclick="load()">Load</button></section><section><h2>Activity</h2><table><thead><tr><th>Time</th><th>Tool</th><th>Verdict</th><th>Status</th><th>Receipt</th></tr></thead><tbody id="activity"></tbody></table></section><section><h2>Approvals</h2><div id="approvals">Load activity to view.</div></section></main><script>const h=()=>({Authorization:'Bearer '+document.querySelector('#token').value});const esc=v=>String(v).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));async function load(){let a=await fetch('/api/v1/activity',{headers:h()});let x=await a.json();document.querySelector('#activity').innerHTML=(x.items||[]).map(v=>'<tr><td>'+esc(v.createdAt)+'</td><td><code>'+esc(v.toolName)+'</code></td><td class="'+esc(v.verdict)+'">'+esc(v.verdict)+'</td><td>'+esc(v.status)+'</td><td><code>'+esc(v.receiptId||'pending')+'</code></td></tr>').join('');let b=await fetch('/api/v1/approvals',{headers:h()});let y=await b.json();document.querySelector('#approvals').innerHTML=(y.items||[]).map(v=>'<p><code>'+esc(v.approvalId)+'</code> · '+esc(v.status)+' · binding <code>'+esc(v.bindingDigest)+'</code></p>').join('')||'No approvals.'}</script>`; }

export interface ApiHandle { server: Server; token: string; url: string; close(): Promise<void>; }
export function startApi(store: InvockStore, options: { host?: string; port?: number; token?: string; allowRemote?: boolean; allowedOrigins?: string[] } = {}): Promise<ApiHandle> {
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
    if (!safeTokenMatch(request.headers.authorization, token)) { json(response, 401, { error: "unauthorized" }); return; }
    const remote = request.socket.remoteAddress ?? "unknown"; const now = Date.now(); const current = attempts.get(remote); const bounded = !current || current.resetAt < now ? { count: 0, resetAt: now + 60_000 } : current; bounded.count++; attempts.set(remote, bounded);
    if (bounded.count > 120) { json(response, 429, { error: "rate_limited" }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/ready") { const ready = store.isReady(); json(response, ready ? 200 : 503, { ready }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/activity") { json(response, 200, { items: store.listActivity(Number(url.searchParams.get("limit") ?? 50)) }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/approvals") { json(response, 200, { items: store.listApprovals() }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/tools") { json(response, 200, { items: store.listToolRegistry() }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/policies") { json(response, 200, { status: "loaded_at_startup" }); return; }
    if (request.method === "GET" && url.pathname === "/api/v1/receipts") { json(response, 200, store.receiptChainStatus()); return; }
    const receipt = /^\/api\/v1\/receipts\/([^/]+)$/u.exec(url.pathname);
    if (request.method === "GET" && receipt?.[1]) { const found = store.getReceipt(receipt[1]); json(response, found ? 200 : 404, found ?? { error: "not_found" }); return; }
    const approve = /^\/api\/v1\/approvals\/([^/]+)\/approve$/u.exec(url.pathname);
    if (request.method === "POST" && approve?.[1]) { if (request.headers["idempotency-key"] === undefined || request.headers["content-type"] !== "application/json") { json(response, 400, { error: "idempotency_key_and_json_required" }); return; } const payload = await body(request); const ok = typeof payload.expectedBindingDigest === "string" && store.approve(approve[1], payload.expectedBindingDigest); json(response, ok ? 200 : 409, { approved: ok }); return; }
    const reject = /^\/api\/v1\/approvals\/([^/]+)\/reject$/u.exec(url.pathname);
    if (request.method === "POST" && reject?.[1]) { if (request.headers["idempotency-key"] === undefined || request.headers["content-type"] !== "application/json") { json(response, 400, { error: "idempotency_key_and_json_required" }); return; } const payload = await body(request); const ok = typeof payload.expectedBindingDigest === "string" && store.reject(reject[1], payload.expectedBindingDigest); json(response, ok ? 200 : 409, { rejected: ok }); return; }
    json(response, 404, { error: "not_found" });
  })().catch(() => json(response, 400, { error: "bad_request" })); });
  return new Promise((resolve, reject) => { server.once("error", reject); server.listen(options.port ?? 0, host, () => { const address = server.address(); if (!address || typeof address === "string") return reject(new Error("Unable to bind API")); resolve({ server, token, url: `http://${host}:${address.port}`, close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())) }); }); });
}