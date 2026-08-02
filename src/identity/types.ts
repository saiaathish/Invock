export type TrustState = "UNVERIFIED" | "ENROLLED" | "ATTESTED" | "SUSPENDED" | "REVOKED";
export type AgentSessionStatus = "ACTIVE" | "EXPIRED" | "REVOKED";

export interface AgentIdentity {
  id: string;
  organizationId: string;
  projectId: string;
  displayName: string;
  runtimeType: string;
  publicKey?: string;
  trustState: TrustState;
  createdAt: string;
  updatedAt: string;
}

export interface AgentSession {
  id: string;
  agentId: string;
  projectId: string;
  startedAt: string;
  expiresAt: string;
  status: AgentSessionStatus;
}

export interface EnrollmentToken {
  tokenId: string;
  agentId: string;
  organizationId: string;
  projectId: string;
  keyId: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export interface EnrollmentInput {
  organizationId: string;
  projectId: string;
  displayName: string;
  runtimeType: string;
  agentId?: string;
}

export interface EnrollmentResult {
  identity: AgentIdentity;
  token: EnrollmentToken;
}

/** Signed software-workload evidence; this is not hardware attestation. */
export interface SoftwareWorkloadAttestation {
  attestationId: string;
  agentId: string;
  keyId: string;
  manifestDigest: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

/** Canonical, non-secret binding carried by signed execution evidence. */
export interface IdentityEvidenceBinding {
  identityDigest: string;
  sessionDigest: string;
  projectDigest: string;
  agentDigest: string;
  bindingDigest: string;
}

/** Authoritative runtime context used to verify an evidence binding at the gate. */
export interface IdentityRuntimeContext {
  readonly identity: AgentIdentity;
  readonly session: AgentSession;
}
