export type Verdict = "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED";

export type Capability =
  | "fs.read" | "fs.write" | "fs.delete" | "net.read" | "net.send"
  | "process.execute" | "process.shell" | "message.send" | "secret.read"
  | "unknown";

export type Effect =
  | "data.observe" | "data.modify" | "data.delete" | "external.read"
  | "external.disclosure" | "external.communication" | "process.spawn"
  | "command.interpretation" | "persistent.change" | "irreversible.action"
  | "unknown";

export type DataLabel = "public" | "internal" | "secret" | "credential" | "private_key" | "untrusted_content";

export interface Principal {
  principalId: string;
  clientId: string;
  agentId?: string;
  scopes: string[];
}

export interface PathResource {
  kind: "path";
  argumentPointer: string;
  rawDigest: string;
  absolutePath: string;
  realPath?: string;
  nearestRealAncestor?: string;
  exists: boolean;
  isSymlink: boolean;
  access: Array<"read" | "write" | "delete">;
  labels: DataLabel[];
  uncertainty: string[];
}

export interface UrlResource {
  kind: "url";
  argumentPointer: string;
  rawDigest: string;
  canonicalUrl: string;
  scheme: string;
  hostname: string;
  port: number;
  method?: string;
  addressClass: "public" | "private" | "loopback" | "link_local" | "reserved" | "unknown";
  labels: DataLabel[];
  uncertainty: string[];
}

export interface CommandResource {
  kind: "command";
  argumentPointer: string;
  rawDigest: string;
  representation: "argv" | "shell-string";
  executable?: string;
  argv: string[];
  opaqueShell: boolean;
  metacharacters: string[];
  labels: DataLabel[];
  uncertainty: string[];
}

export interface RecipientResource {
  kind: "recipient";
  argumentPointer: string;
  rawDigest: string;
  normalized: string;
  domain?: string;
  external: boolean;
  labels: DataLabel[];
  uncertainty: string[];
}

export interface DataResource {
  kind: "data";
  argumentPointer: string;
  rawDigest: string;
  byteLength: number;
  labels: DataLabel[];
  uncertainty: string[];
}

export type Resource = PathResource | UrlResource | CommandResource | RecipientResource | DataResource;

export interface LineageReference {
  sourceInvocationId: string;
  labels: DataLabel[];
  matchedFingerprintIds: string[];
  matchKinds: Array<"exact" | "base64" | "base64url" | "urlencoded">;
}

export interface ActionEnvelope {
  envelopeVersion: "1.0";
  invocationId: string;
  requestId: string;
  sessionId: string;
  timestamp: string;
  subject: Principal;
  target: {
    serverId: string;
    toolName: string;
    toolSchemaDigest: string;
    toolDescriptorDigest: string;
    registryVersion: string;
    protocolEra: string;
  };
  raw: { protocolMethod: "tools/call"; argumentBytes: number; argumentKeys: string[] };
  capabilities: Capability[];
  effects: Effect[];
  resources: Resource[];
  labels: DataLabel[];
  lineage: LineageReference[];
  riskSignals: string[];
  uncertainty: string[];
  integrity: {
    argumentsDigest: string;
    requestDigest: string;
    policyVersionId: string;
    normalizerVersion: string;
  };
}

export interface PolicyDecision {
  contractVersion: "1.0";
  decisionId: string;
  invocationId: string;
  verdict: Verdict;
  policyVersionId: string;
  policyDigest: string;
  matchedRuleIds: string[];
  reasonCodes: string[];
  traces: Array<{ predicate: string; matched: boolean; observed: unknown; expected: unknown }>;
  obligations: Array<{ type: "approval"; ttlSeconds: number }>;
  retryable: boolean;
  evaluatedAt: string;
}

export interface ToolCallRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: "tools/call";
  params: { name: string; arguments?: unknown; _meta?: Record<string, unknown> };
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}