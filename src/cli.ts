import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parsePolicyYaml, compilePolicy } from "./core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "./gateway/engine.js";
import { runStdioProxy } from "./gateway/stdio.js";
import { InvockStore } from "./storage/store.js";
import { startApi } from "./api/server.js";
import { forgePolicy } from "./forge/index.js";
import { inspectWorkflow } from "./guard/index.js";
import { runContained } from "./containment/index.js";

const root = process.cwd();
function usage(): never { console.error(`Invock — deterministic MCP invocation reference monitor

Usage:
  invock policy validate <file>
  invock doctor [--database <path>] [--key-directory <path>]
  invock receipts verify [--database <path>] [--key-directory <path>]
  invock serve [--database <path>] [--key-directory <path>]
  invock serve --stdio [--database <path>] [--key-directory <path>] <command> [-- <args...>]
  invock demo safe|attack
  invock forge [observation-json]
  invock guard <workflow-file>
  invock contain <fixture-root> <command> [-- <args...>]
`); process.exit(64); }
function policy(file = resolve(root, "policies/default.yaml")) { return compilePolicy(parsePolicyYaml(readFileSync(file, "utf8"))); }
function option(values: string[], name: string): string | undefined { const index = values.indexOf(name); if (index < 0) return undefined; const value = values[index + 1]; if (!value) usage(); values.splice(index, 2); return resolve(root, value); }
function runtime(values: string[]) { const database = option(values, "--database") ?? process.env.INVOCK_DATABASE_PATH ?? resolve(root, ".invock/invock.sqlite"); const keyDirectory = option(values, "--key-directory") ?? process.env.INVOCK_KEY_DIRECTORY; return { database, ...(keyDirectory ? { keyDirectory: resolve(root, keyDirectory) } : {}) }; }
function gate(store: InvockStore) {
  return new InvocationGate(policy(), new StaticDescriptorRegistry({
    read_file: { fields: [{ pointer: "/path", type: "path", access: "read" }] },
    fetch_url: { fields: [{ pointer: "/url", type: "url", methodPointer: "/method" }, { pointer: "/body", type: "data" }] },
    send_email: { fields: [{ pointer: "/to", type: "recipient" }, { pointer: "/body", type: "data" }] },
    run_command: { fields: [{ pointer: "/command", type: "command" }] },
  }), store, { cwd: root, projectRoot: root, organizationDomains: ["example.com"], sessionId: "stdio-local", principal: { principalId: "local-user", clientId: "invock-cli", scopes: ["*"] } });
}
async function demo(attack: boolean): Promise<void> {
  const store = new InvockStore(":memory:"); const monitor = gate(store);
  const request = attack ? { jsonrpc: "2.0" as const, id: 1, method: "tools/call" as const, params: { name: "read_file", arguments: { path: ".env" } } } : { jsonrpc: "2.0" as const, id: 1, method: "tools/call" as const, params: { name: "read_file", arguments: { path: "/workspace/README.md" } } };
  const outcome = await monitor.intercept(request);
  console.log(JSON.stringify(outcome.kind === "respond" ? outcome.response : { decision: outcome.decision.verdict, message: "Would forward to upstream server" }, null, 2));
  store.close();
}

const [command, subcommand, ...rest] = process.argv.slice(2);
if (command === "policy" && subcommand === "validate" && rest[0]) { const compiled = policy(resolve(root, rest[0])); console.log(JSON.stringify({ valid: true, policyVersionId: compiled.policyVersionId, policyDigest: compiled.policyDigest }, null, 2)); }
else if (command === "doctor") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const config = runtime(values); const store = new InvockStore(config.database, config); console.log(JSON.stringify({ ready: store.isReady(), sqlite: "3.51.3+ required", receiptChain: store.verifyChain() ? "valid" : "invalid", instanceId: store.instanceId, database: config.database, keyDirectory: store.keyDirectory }, null, 2)); store.close(); }
else if (command === "receipts" && subcommand === "verify") { const values = [...rest]; const config = runtime(values); const store = new InvockStore(config.database, config); const valid = store.verifyChain(); console.log(JSON.stringify({ valid, database: config.database, keyDirectory: store.keyDirectory, chain: store.receiptChainStatus() }, null, 2)); store.close(); if (!valid) process.exitCode = 1; }
else if (command === "serve" && subcommand === "--stdio") { const values = [...rest]; const config = runtime(values); const separator = values.indexOf("--"); const executable = separator >= 0 ? values.slice(0, separator)[0] : values[0]; if (!executable) usage(); const args = separator >= 0 ? values.slice(separator + 1) : []; const store = new InvockStore(config.database, config); await runStdioProxy({ command: executable, args, cwd: root }, gate(store)); store.close(); }
else if (command === "serve") { const values = [subcommand, ...rest].filter((item): item is string => item !== undefined); const config = runtime(values); const store = new InvockStore(config.database, config); const api = await startApi(store); console.error(`Invock dashboard: ${api.url}\nInvock dashboard token: ${api.token}\nDatabase: ${config.database}\nKey directory: ${store.keyDirectory}\nPress Ctrl+C to stop.`); await new Promise<void>(resolveSignal => { process.once("SIGINT", resolveSignal); process.once("SIGTERM", resolveSignal); }); await api.close(); store.close(); }
else if (command === "demo" && (subcommand === "safe" || subcommand === "attack")) await demo(subcommand === "attack");
else if (command === "forge") { const observations = rest[0] ? JSON.parse(readFileSync(resolve(root, rest[0]), "utf8")) : []; console.log(JSON.stringify(forgePolicy(observations), null, 2)); }
else if (command === "guard" && subcommand) { const findings = inspectWorkflow({ source: readFileSync(resolve(root, subcommand), "utf8"), path: subcommand }); console.log(JSON.stringify({ ok: findings.length === 0, findings }, null, 2)); if (findings.length > 0) process.exitCode = 1; }
else if (command === "contain" && subcommand && rest[0]) { const separator = rest.indexOf("--"); const executable = rest[0]; const args = separator >= 0 ? rest.slice(separator + 1) : rest.slice(1); const result = await runContained({ profile: { fixtureRoot: resolve(root, subcommand), allowedCommands: [executable], sandbox: "required" }, command: executable, argv: args }); console.log(JSON.stringify({ ...result, stdout: result.stdout.length > 512 ? "[redacted]" : result.stdout, stderr: result.stderr.length > 512 ? "[redacted]" : result.stderr }, null, 2)); if (result.status !== "completed") process.exitCode = 1; }
else usage();
