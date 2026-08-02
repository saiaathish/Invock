import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";

export type SupportedAgent = "claude" | "codex" | "cursor";
export interface AgentDetection { installed: boolean; commandPath?: string; version?: string; configPaths: string[]; details: string[] }
export interface AgentResult { changed: boolean; backupPaths: string[]; modifiedPaths: string[]; details: string[] }

const home = () => process.env.HOME ?? process.cwd();
const configPath = (agent: SupportedAgent) => agent === "claude" ? join(home(), ".claude.json") : agent === "codex" ? join(home(), ".codex", "config.toml") : join(home(), ".cursor", "mcp.json");
const command = (agent: SupportedAgent) => agent;
const readVersion = (agent: SupportedAgent, path: string) => { try { return execFileSync(path, ["--version"], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }).trim().split("\n")[0]; } catch { return undefined; } };
const atomicWrite = (path: string, content: string) => { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const tmp = `${path}.invock-${process.pid}.tmp`; writeFileSync(tmp, content, { mode: 0o600 }); renameSync(tmp, path); chmodSync(path, 0o600); };
const backup = (path: string) => { if (!existsSync(path)) return undefined; const target = `${path}.invock-backup-${Date.now()}`; copyFileSync(path, target); chmodSync(target, 0o600); return target; };

export function detectAgent(agent: SupportedAgent): AgentDetection {
  let commandPath: string | undefined;
  try { commandPath = execFileSync("sh", ["-lc", `command -v ${command(agent)}`], { encoding: "utf8", timeout: 3000 }).trim() || undefined; } catch { /* unavailable */ }
  const config = configPath(agent);
  const version = commandPath ? readVersion(agent, commandPath) : undefined;
  return { installed: Boolean(commandPath), ...(commandPath ? { commandPath } : {}), ...(version ? { version } : {}), configPaths: [config], details: [existsSync(config) ? "configuration-readable" : "configuration-not-found"] };
}

export function installAgent(agent: SupportedAgent, executablePath: string, gatewayUrl: string): AgentResult {
  const path = configPath(agent); const backupPath = backup(path); let content = "";
  if (existsSync(path)) content = readFileSync(path, "utf8");
  if (agent === "codex") {
    const marker = "# invock-managed";
    if (!content.includes(marker)) content = `${content.trimEnd()}\n\n${marker}\n[ mcp_servers.invock ]\ncommand = ${JSON.stringify(executablePath)}\nargs = ["serve", "--stdio"]\n# gateway = ${gatewayUrl}\n`;
  } else {
    let parsed: Record<string, unknown> = {};
    try { parsed = content.trim() ? JSON.parse(content) as Record<string, unknown> : {}; } catch { throw new Error(`${path} is not valid JSON`); }
    const servers = (parsed.mcpServers && typeof parsed.mcpServers === "object" ? parsed.mcpServers : {}) as Record<string, unknown>;
    if (!servers.invock) servers.invock = { command: executablePath, args: ["serve", "--stdio"], env: { INVOCK_GATEWAY_URL: gatewayUrl } };
    parsed.mcpServers = servers; content = `${JSON.stringify(parsed, null, 2)}\n`;
  }
  atomicWrite(path, content); return { changed: true, backupPaths: backupPath ? [backupPath] : [], modifiedPaths: [path], details: [`configured ${agent}`, `gateway ${gatewayUrl}`] };
}

export function verifyAgent(agent: SupportedAgent, executablePath: string): { verified: boolean; detection: AgentDetection; reasons: string[] } {
  const detection = detectAgent(agent); const path = configPath(agent); const reasons: string[] = [];
  if (!existsSync(path)) reasons.push("configuration-not-found");
  else if (agent !== "codex") { try { const parsed = JSON.parse(readFileSync(path, "utf8")) as { mcpServers?: Record<string, { command?: string }> }; if (parsed.mcpServers?.invock?.command !== executablePath) reasons.push("invock-entry-missing-or-mismatched"); } catch { reasons.push("configuration-invalid"); } }
  else if (!readFileSync(path, "utf8").includes("# invock-managed")) reasons.push("invock-entry-missing");
  return { verified: reasons.length === 0, detection, reasons };
}

export function uninstallAgent(agent: SupportedAgent): AgentResult {
  const path = configPath(agent); if (!existsSync(path)) return { changed: false, backupPaths: [], modifiedPaths: [], details: ["configuration-not-found"] };
  const prior = readdirSync(dirname(path)).filter(item => item.startsWith(`${path.split("/").pop()}.invock-backup-`)).sort().at(-1);
  if (prior) { const priorPath = join(dirname(path), prior); copyFileSync(priorPath, path); chmodSync(path, 0o600); return { changed: true, backupPaths: [priorPath], modifiedPaths: [path], details: [`restored exact pre-install ${agent} configuration`] }; }
  const original = readFileSync(path, "utf8"); const backupPath = backup(path); let content = original;
  if (agent === "codex") content = original.replace(/\n?# invock-managed[\s\S]*$/m, "\n").trimEnd() + "\n";
  else { const parsed = JSON.parse(original) as Record<string, unknown>; const servers = parsed.mcpServers as Record<string, unknown> | undefined; if (servers) { delete servers.invock; if (Object.keys(servers).length === 0) delete parsed.mcpServers; } content = `${JSON.stringify(parsed, null, 2)}\n`; }
  atomicWrite(path, content); return { changed: content !== original, backupPaths: backupPath ? [backupPath] : [], modifiedPaths: [path], details: [`removed ${agent} integration`] };
}
