import { runArena } from "../../src/arena/index.js";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicy, parsePolicyYaml } from "../../src/core/policy.js";
import { InvocationGate, StaticDescriptorRegistry } from "../../src/gateway/engine.js";
import { InvockStore } from "../../src/storage/store.js";

const directory = mkdtempSync(join(tmpdir(), "invock-arena-real-"));
const store = new InvockStore(join(directory, "arena.sqlite"));
const gate = new InvocationGate(
  compilePolicy(parsePolicyYaml(`apiVersion: invock.dev/v1
kind: InvocationPolicy
metadata: { name: arena-real }
defaults: { decision: ALLOW, unknownCapability: BLOCK, unknownEffect: BLOCK }
rules:
  - id: protected
    decision: BLOCK
    reasonCodes: [PATH_PROTECTED]
    when: { resources: { paths: { labels: { any: [secret, credential] } } } }
`)),
  new StaticDescriptorRegistry({ read: { fields: [{ pointer: "/path", type: "path", access: "read" }], inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } } }),
  store,
  { cwd: directory, projectRoot: realpathSync(directory), organizationDomains: [], sessionId: "arena", principal: { principalId: "arena", clientId: "arena", scopes: [] } },
);

try {
  const run = await runArena({
    scenarios: [
      { id: "benign-local", attack: false, expectedBlocked: false, invoke: async () => ({ outcome: "completed" as const }) },
      { id: "blocked-local-attack", attack: true, expectedBlocked: true, invoke: async () => ({ outcome: "completed" as const }) },
    ],
    execute: async (scenario, context) => {
      if (!context.protected || scenario.id === "benign-local") return { outcome: "completed" as const };
      const outcome = await gate.authorizeInvocation({ jsonrpc: "2.0", id: "arena-attack", method: "tools/call", params: { name: "read", arguments: { path: ".env" } } });
      return { outcome: outcome.kind === "forward" ? "completed" as const : "blocked" as const };
    },
    metrics: ["scenarioCount", "attackBlocked", "benignCompleted", "falseNegatives", "cleanupCompleted"],
  });
  console.log(JSON.stringify(run));
} finally {
  store.close();
  rmSync(directory, { recursive: true, force: true });
}
