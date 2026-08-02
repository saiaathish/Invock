import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { sign, verify } from "node:crypto";
import { basename, dirname, resolve } from "node:path";
import { canonicalize } from "../core/canonical.js";
import { generateSigningMaterial, type SigningMaterial } from "../storage/receipts.js";

export type AlertSeverity = "info" | "warning" | "critical";
export type ControlPlaneListKind = "organizations" | "projects" | "agents" | "alerts";
export type AgentTrustState = "UNVERIFIED" | "ENROLLED" | "ATTESTED" | "SUSPENDED" | "REVOKED";

export interface Organization { id: string; displayName: string; }
export interface Project { id: string; organizationId: string; displayName: string; }
export interface Agent { id: string; projectId: string; displayName: string; trustState: AgentTrustState; }
export interface Alert { projectId: string; severity: AlertSeverity; message: string; }

export interface ControlPlaneSnapshot {
  version: 1;
  organizations: Organization[];
  projects: Project[];
  agents: Agent[];
  alerts: Alert[];
}

interface PersistedControlPlaneIntegrity { algorithm: "Ed25519"; keyId: string; signature: string; }

const agentStates: readonly AgentTrustState[] = ["UNVERIFIED", "ENROLLED", "ATTESTED", "SUSPENDED", "REVOKED"];
const alertSeverities: readonly AlertSeverity[] = ["info", "warning", "critical"];
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
let temporarySequence = 0;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`${field} must be a bounded printable string`);
  return value;
}

function idValue(value: unknown, field: string): string {
  const id = stringValue(value, field, 128);
  if (!idPattern.test(id)) throw new Error(`${field} must match ${idPattern.source}`);
  return id;
}

function safeMessage(value: unknown): string {
  let message = stringValue(value, "message", 2000);
  message = message
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gu, "[REDACTED_PRIVATE_KEY]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/giu, "Bearer [REDACTED_TOKEN]")
    .replace(/\b(?:api[_-]?key|access[_-]?token|secret|password|private[_-]?key)\s*[:=]\s*[^\s,;]+/giu, "$1=[REDACTED]");
  return message;
}

function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }

function validateSnapshot(value: unknown): ControlPlaneSnapshot {
  if (!isRecord(value) || value.version !== 1) throw new Error("control-plane state version is unsupported");
  const expectedKeys = ["version", "organizations", "projects", "agents", "alerts", "integrity"];
  if (Object.keys(value).some(key => !expectedKeys.includes(key))) throw new Error("control-plane state contains an unknown field");
  for (const key of ["organizations", "projects", "agents", "alerts"] as const) if (!Array.isArray(value[key])) throw new Error(`control-plane ${key} must be an array`);
  const organizationItems = value.organizations as unknown[];
  const projectItems = value.projects as unknown[];
  const agentItems = value.agents as unknown[];
  const alertItems = value.alerts as unknown[];

  const organizations = organizationItems.map(item => {
    if (!isRecord(item)) throw new Error("organization must be an object");
    return { id: idValue(item.id, "organization.id"), displayName: stringValue(item.displayName, "organization.displayName", 200) };
  });
  const organizationIds = new Set<string>();
  for (const organization of organizations) if (!organizationIds.add(organization.id)) throw new Error(`duplicate organization ${organization.id}`);

  const projects = projectItems.map(item => {
    if (!isRecord(item)) throw new Error("project must be an object");
    return { id: idValue(item.id, "project.id"), organizationId: idValue(item.organizationId, "project.organizationId"), displayName: stringValue(item.displayName, "project.displayName", 200) };
  });
  const projectIds = new Set<string>();
  for (const project of projects) {
    if (!projectIds.add(project.id)) throw new Error(`duplicate project ${project.id}`);
    if (!organizationIds.has(project.organizationId)) throw new Error(`project ${project.id} references an unknown organization`);
  }

  const agents = agentItems.map(item => {
    if (!isRecord(item)) throw new Error("agent must be an object");
    const trustState = item.trustState;
    if (typeof trustState !== "string" || !agentStates.includes(trustState as AgentTrustState)) throw new Error("agent.trustState is unsupported");
    return { id: idValue(item.id, "agent.id"), projectId: idValue(item.projectId, "agent.projectId"), displayName: stringValue(item.displayName, "agent.displayName", 200), trustState: trustState as AgentTrustState };
  });
  const agentIds = new Set<string>();
  for (const agent of agents) {
    if (!agentIds.add(agent.id)) throw new Error(`duplicate agent ${agent.id}`);
    if (!projectIds.has(agent.projectId)) throw new Error(`agent ${agent.id} references an unknown project`);
  }

  const alerts = alertItems.map(item => {
    if (!isRecord(item)) throw new Error("alert must be an object");
    const severity = item.severity;
    if (typeof severity !== "string" || !alertSeverities.includes(severity as AlertSeverity)) throw new Error("alert.severity is unsupported");
    return { projectId: idValue(item.projectId, "alert.projectId"), severity: severity as AlertSeverity, message: safeMessage(item.message) };
  });
  for (const alert of alerts) if (!projectIds.has(alert.projectId)) throw new Error(`alert references an unknown project`);

  return { version: 1, organizations, projects, agents, alerts };
}

function snapshotPayload(snapshot: ControlPlaneSnapshot): string {
  return `invock-control-plane-v1\0${canonicalize(snapshot)}`;
}

function sortedSnapshot(snapshot: ControlPlaneSnapshot): ControlPlaneSnapshot {
  return {
    version: 1,
    organizations: [...snapshot.organizations].sort((a, b) => a.id.localeCompare(b.id)),
    projects: [...snapshot.projects].sort((a, b) => a.id.localeCompare(b.id)),
    agents: [...snapshot.agents].sort((a, b) => a.id.localeCompare(b.id)),
    alerts: [...snapshot.alerts].sort((a, b) => a.projectId.localeCompare(b.projectId) || a.severity.localeCompare(b.severity) || a.message.localeCompare(b.message)),
  };
}

export class LocalControlPlane {
  readonly statePath: string;
  private state: ControlPlaneSnapshot;
  private readonly signing: SigningMaterial;

  constructor(jsonPath: string) {
    if (typeof jsonPath !== "string" || jsonPath.length === 0) throw new Error("control-plane JSON path is required");
    this.statePath = resolve(jsonPath);
    this.signing = this.loadSigningMaterial(existsSync(this.statePath));
    if (existsSync(this.statePath)) {
      if (!statSync(this.statePath).isFile()) throw new Error("control-plane path must be a file");
      const persisted = JSON.parse(readFileSync(this.statePath, "utf8")) as Record<string, unknown>;
      this.state = sortedSnapshot(validateSnapshot(persisted));
      const integrity = persisted.integrity as Partial<PersistedControlPlaneIntegrity> | undefined;
      if (!integrity || integrity.algorithm !== "Ed25519" || integrity.keyId !== this.signing.signingKeyId || typeof integrity.signature !== "string" || !verify(null, Buffer.from(snapshotPayload(this.state), "utf8"), this.signing.publicKeyPem, Buffer.from(integrity.signature, "base64url"))) throw new Error("control-plane state integrity verification failed");
    } else {
      this.state = { version: 1, organizations: [], projects: [], agents: [], alerts: [] };
      this.persist();
    }
  }

  private keyPath(suffix: string): string { return `${this.statePath}.ed25519.${suffix}`; }
  private writeSecret(path: string, content: string): void { writeFileSync(path, content, { encoding: "utf8", mode: 0o600, flag: "wx" }); try { chmodSync(path, 0o600); } catch { /* best effort */ } }
  private loadSigningMaterial(stateExists: boolean): SigningMaterial {
    const privatePath = this.keyPath("private.pem"); const publicPath = this.keyPath("public.pem"); const keyIdPath = this.keyPath("key-id");
    const present = [privatePath, publicPath, keyIdPath].map(path => existsSync(path));
    if (present.some(Boolean) && !present.every(Boolean)) throw new Error("control-plane signing key set is incomplete");
    if (present.every(Boolean)) return { privateKeyPem: readFileSync(privatePath, "utf8"), publicKeyPem: readFileSync(publicPath, "utf8"), signingKeyId: readFileSync(keyIdPath, "utf8").trim() };
    if (stateExists) throw new Error("control-plane signing key is missing; refusing unsigned state");
    const material = generateSigningMaterial();
    mkdirSync(dirname(this.statePath), { recursive: true, mode: 0o700 });
    this.writeSecret(privatePath, material.privateKeyPem); this.writeSecret(publicPath, material.publicKeyPem); this.writeSecret(keyIdPath, material.signingKeyId);
    return material;
  }

  private persist(): void {
    mkdirSync(dirname(this.statePath), { recursive: true, mode: 0o700 });
    const temporaryPath = `${dirname(this.statePath)}/.${basename(this.statePath)}.${process.pid}.${temporarySequence++}.tmp`;
    try {
      const snapshot = sortedSnapshot(this.state);
      const integrity: PersistedControlPlaneIntegrity = { algorithm: "Ed25519", keyId: this.signing.signingKeyId, signature: sign(null, Buffer.from(snapshotPayload(snapshot), "utf8"), this.signing.privateKeyPem).toString("base64url") };
      writeFileSync(temporaryPath, `${JSON.stringify({ ...snapshot, integrity })}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      try { chmodSync(temporaryPath, 0o600); } catch { /* best effort on non-POSIX filesystems */ }
      renameSync(temporaryPath, this.statePath);
    } catch (error) {
      try { if (existsSync(temporaryPath)) unlinkSync(temporaryPath); } catch { /* preserve the original error */ }
      throw error;
    }
  }

  upsertOrganization(input: { id: string; displayName: string }): Organization {
    const organization = { id: idValue(input.id, "organization.id"), displayName: stringValue(input.displayName, "organization.displayName", 200) };
    const index = this.state.organizations.findIndex(item => item.id === organization.id);
    if (index < 0) this.state.organizations.push(organization); else this.state.organizations[index] = organization;
    this.state = sortedSnapshot(this.state); this.persist(); return clone(organization);
  }

  upsertProject(input: { id: string; organizationId: string; displayName: string }): Project {
    const project = { id: idValue(input.id, "project.id"), organizationId: idValue(input.organizationId, "project.organizationId"), displayName: stringValue(input.displayName, "project.displayName", 200) };
    if (!this.state.organizations.some(item => item.id === project.organizationId)) throw new Error(`project ${project.id} references an unknown organization`);
    const existing = this.state.projects.find(item => item.id === project.id);
    if (existing && existing.organizationId !== project.organizationId) throw new Error(`project ${project.id} cannot move organizations`);
    const index = this.state.projects.findIndex(item => item.id === project.id);
    if (index < 0) this.state.projects.push(project); else this.state.projects[index] = project;
    this.state = sortedSnapshot(this.state); this.persist(); return clone(project);
  }

  registerAgent(input: { id: string; projectId: string; displayName: string; trustState: AgentTrustState }): Agent {
    const agent = { id: idValue(input.id, "agent.id"), projectId: idValue(input.projectId, "agent.projectId"), displayName: stringValue(input.displayName, "agent.displayName", 200), trustState: input.trustState };
    if (!agentStates.includes(agent.trustState)) throw new Error("agent.trustState is unsupported");
    if (!this.state.projects.some(item => item.id === agent.projectId)) throw new Error(`agent ${agent.id} references an unknown project`);
    const existing = this.state.agents.find(item => item.id === agent.id);
    if (existing && existing.projectId !== agent.projectId) throw new Error(`agent ${agent.id} cannot move projects`);
    const index = this.state.agents.findIndex(item => item.id === agent.id);
    if (index < 0) this.state.agents.push(agent); else this.state.agents[index] = agent;
    this.state = sortedSnapshot(this.state); this.persist(); return clone(agent);
  }

  recordAlert(input: { projectId: string; severity: AlertSeverity; message: string }): Alert {
    const alert = { projectId: idValue(input.projectId, "alert.projectId"), severity: input.severity, message: safeMessage(input.message) };
    if (!alertSeverities.includes(alert.severity)) throw new Error("alert.severity is unsupported");
    if (!this.state.projects.some(item => item.id === alert.projectId)) throw new Error("alert references an unknown project");
    if (!this.state.alerts.some(item => item.projectId === alert.projectId && item.severity === alert.severity && item.message === alert.message)) this.state.alerts.push(alert);
    this.state = sortedSnapshot(this.state); this.persist(); return clone(alert);
  }

  list(kind: ControlPlaneListKind): Organization[] | Project[] | Agent[] | Alert[] {
    if (kind === "organizations") return clone(this.state.organizations);
    if (kind === "projects") return clone(this.state.projects);
    if (kind === "agents") return clone(this.state.agents);
    if (kind === "alerts") return clone(this.state.alerts);
    throw new Error(`unsupported control-plane list kind: ${String(kind)}`);
  }

  exportSnapshot(): ControlPlaneSnapshot { return clone(sortedSnapshot(this.state)); }
}
