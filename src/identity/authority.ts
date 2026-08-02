import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync, unlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { digestJson, newId } from "../core/canonical.js";
import type { AgentIdentity, AgentSession, EnrollmentInput, EnrollmentResult, EnrollmentToken, IdentityEvidenceBinding, IdentityRuntimeContext, SoftwareWorkloadAttestation } from "./types.js";

const ENROLLMENT_TTL_SECONDS = 900;
const MAX_SESSION_TTL_SECONDS = 86_400;
const ATTESTATION_TTL_SECONDS = 3_600;
const TOKEN_DOMAIN = "invock-enrollment-v1\0";

interface KeyMaterial { keyId: string; privateKey: string | KeyObject; publicKey: string; }
interface IdentityRecord { identity: AgentIdentity; key: KeyMaterial; }
interface PersistedState {
  version: 1;
  identities: Array<{ identity: AgentIdentity; keyId: string; publicKey: string }>;
  sessions: Array<{ session: AgentSession; digest: string }>;
  consumedTokenIds: string[];
  attestations: SoftwareWorkloadAttestation[];
}
interface StateEnvelope { version: 1; signerPublicKey: string; state: PersistedState; signature: string; }

const MAX_STATE_BYTES = 2 * 1024 * 1024;
const DIGEST = /^[A-Za-z0-9_-]{43}$/u;

function exactKeys(value: Record<string, unknown>, keys: readonly string[], name: string): void {
  const actual = Object.keys(value).sort().join(",");
  const expected = [...keys].sort().join(",");
  if (actual !== expected) throw new Error(`Invalid persisted identity state: ${name} fields`);
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid persisted identity state: ${name}`);
  return value as Record<string, unknown>;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`Invalid persisted identity state: ${name}`);
  return value;
}

function sidecarPath(statePath: string, suffix: string): string { return `${statePath}.${suffix}.key`; }

function privatePublicPem(privatePem: string): string {
  return createPublicKey(createPrivateKey(privatePem)).export({ type: "spki", format: "pem" }).toString();
}

function writeAtomic(path: string, contents: string): void {
  const temporary = `${path}.tmp-${process.pid}-${newId("write")}`;
  try {
    writeFileSync(temporary, contents, { encoding: "utf8", mode: 0o600, flag: "wx" });
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
    chmodSync(path, 0o600);
  } catch (error) {
    try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* preserve original error */ }
    throw new Error(`Unable to persist identity state: ${error instanceof Error ? error.message : "write failed"}`);
  }
}

function assertPrivateSidecar(path: string): void {
  if ((statSync(path).mode & 0o077) !== 0) throw new Error("Insecure persisted identity key permissions");
}

function nonEmpty(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${name} must be a non-empty string`);
  return value;
}

function iso(value: Date, name: string): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${name} must be a valid date`);
  return value.toISOString();
}

function future(timestamp: string, now: Date, name: string): void {
  if (Date.parse(timestamp) <= now.getTime()) throw new Error(`${name} is expired`);
}

function immutable<T extends object>(value: T): T {
  return Object.freeze({ ...value });
}

function copyIdentity(identity: AgentIdentity): AgentIdentity {
  return immutable(identity);
}

function copySession(session: AgentSession): AgentSession {
  return immutable(session);
}

function tokenBody(token: Omit<EnrollmentToken, "signature">): string {
  return `${TOKEN_DOMAIN}${digestJson(token)}`;
}

function attestationBody(attestation: Omit<SoftwareWorkloadAttestation, "signature">): string {
  return `invock-software-workload-attestation-v1\0${digestJson(attestation)}`;
}

function generateKey(keyId = newId("key")): KeyMaterial {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { keyId, privateKey: pair.privateKey, publicKey: pair.publicKey };
}

function signedToken(record: IdentityRecord, issuedAt: Date): EnrollmentToken {
  const body: Omit<EnrollmentToken, "signature"> = {
    tokenId: newId("enroll"), agentId: record.identity.id, organizationId: record.identity.organizationId,
    projectId: record.identity.projectId, keyId: record.key.keyId, issuedAt: iso(issuedAt, "issuedAt"),
    expiresAt: new Date(issuedAt.getTime() + ENROLLMENT_TTL_SECONDS * 1000).toISOString(),
  };
  const signature = sign(null, Buffer.from(tokenBody(body), "utf8"), record.key.privateKey).toString("base64url");
  return { ...body, signature };
}

export class IdentityAuthority {
  private readonly identities = new Map<string, IdentityRecord>();
  private readonly sessions = new Map<string, { session: AgentSession; digest: string }>();
  private readonly consumedTokens = new Set<string>();
  private readonly attestations = new Map<string, SoftwareWorkloadAttestation>();
  private readonly statePath?: string;
  private readonly stateSigningKey?: KeyMaterial;

  constructor(statePath?: string) {
    if (statePath === undefined) return;
    if (typeof statePath !== "string" || statePath.trim().length === 0) throw new Error("statePath must be a non-empty string");
    this.statePath = resolve(statePath);
    mkdirSync(dirname(this.statePath), { recursive: true, mode: 0o700 });
    const signerPath = sidecarPath(this.statePath, "authority");
    if (existsSync(this.statePath) !== existsSync(signerPath)) throw new Error("Incomplete persisted identity key set");
    if (existsSync(this.statePath)) {
      assertPrivateSidecar(this.statePath);
      assertPrivateSidecar(signerPath);
      const privateKey = readFileSync(signerPath, "utf8");
      const envelope = this.readEnvelope(readFileSync(this.statePath));
      if (privatePublicPem(privateKey) !== envelope.signerPublicKey) throw new Error("Persisted state signing key mismatch");
      this.stateSigningKey = { keyId: "authority", privateKey, publicKey: envelope.signerPublicKey };
      this.load(envelope.state);
    } else {
      const generated = generateKey("authority");
      writeAtomic(signerPath, String(generated.privateKey));
      this.stateSigningKey = generated;
      this.persist();
    }
  }

  enroll(input: EnrollmentInput, now: Date): EnrollmentResult {
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("now must be a valid date");
    const id = input.agentId === undefined ? newId("agent") : nonEmpty(input.agentId, "agentId");
    if (this.identities.has(id)) throw new Error("Agent identity already exists");
    const identity: AgentIdentity = {
      id, organizationId: nonEmpty(input.organizationId, "organizationId"), projectId: nonEmpty(input.projectId, "projectId"),
      displayName: nonEmpty(input.displayName, "displayName"), runtimeType: nonEmpty(input.runtimeType, "runtimeType"),
      trustState: "ENROLLED", createdAt: now.toISOString(), updatedAt: now.toISOString(),
    };
    const key = generateKey();
    identity.publicKey = key.publicKey;
    const record: IdentityRecord = { identity, key };
    this.identities.set(id, record);
    this.writeIdentityKey(id, key);
    this.persist();
    return { identity: copyIdentity(identity), token: signedToken(record, now) };
  }

  verifyEnrollment(token: EnrollmentToken, now: Date): boolean {
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("now must be a valid date");
    const record = this.identities.get(token.agentId);
    if (!record || this.consumedTokens.has(token.tokenId)) throw new Error("Unknown or replayed enrollment token");
    if (token.organizationId !== record.identity.organizationId || token.projectId !== record.identity.projectId) throw new Error("Enrollment token project or organization mismatch");
    if (token.keyId !== record.key.keyId) throw new Error("Enrollment token key mismatch");
    future(token.expiresAt, now, "Enrollment token");
    const { signature, ...body } = token;
    let valid = false;
    try { valid = Boolean(record.identity.publicKey && verify(null, Buffer.from(tokenBody(body), "utf8"), record.identity.publicKey, Buffer.from(signature, "base64url"))); } catch { valid = false; }
    if (!valid) throw new Error("Invalid enrollment token signature");
    if (record.identity.trustState === "SUSPENDED" || record.identity.trustState === "REVOKED") throw new Error("Identity is not eligible for enrollment");
    this.consumedTokens.add(token.tokenId);
    this.persist();
    return true;
  }

  rotate(agentId: string, now: Date): AgentIdentity {
    const record = this.record(agentId);
    if (record.identity.trustState === "SUSPENDED" || record.identity.trustState === "REVOKED") throw new Error("Suspended or revoked identity cannot rotate");
    record.key = generateKey();
    record.identity = { ...record.identity, publicKey: record.key.publicKey, trustState: "ENROLLED", updatedAt: iso(now, "now") };
    this.writeIdentityKey(agentId, record.key);
    this.persist();
    return copyIdentity(record.identity);
  }

  /** Attests a signed software manifest and moves the identity to ATTESTED. */
  attest(agentId: string, manifest: unknown, now: Date): { identity: AgentIdentity; attestation: SoftwareWorkloadAttestation } {
    const record = this.record(agentId);
    if (record.identity.trustState === "SUSPENDED" || record.identity.trustState === "REVOKED") throw new Error("Suspended or revoked identity cannot attest");
    const issuedAt = iso(now, "now");
    const body: Omit<SoftwareWorkloadAttestation, "signature"> = { attestationId: newId("attest"), agentId, keyId: record.key.keyId, manifestDigest: digestJson(manifest), issuedAt, expiresAt: new Date(now.getTime() + ATTESTATION_TTL_SECONDS * 1000).toISOString() };
    const signature = sign(null, Buffer.from(attestationBody(body), "utf8"), record.key.privateKey).toString("base64url");
    record.identity = { ...record.identity, trustState: "ATTESTED", updatedAt: issuedAt };
    const attestation = { ...body, signature };
    this.attestations.set(agentId, attestation);
    this.persist();
    return { identity: copyIdentity(record.identity), attestation };
  }

  verifyAttestation(attestation: SoftwareWorkloadAttestation, manifest: unknown, now: Date): boolean {
    const record = this.identities.get(attestation.agentId);
    if (!record || record.key.keyId !== attestation.keyId || record.identity.trustState !== "ATTESTED") throw new Error("Software workload attestation is not trusted");
    if (attestation.manifestDigest !== digestJson(manifest)) throw new Error("Software workload manifest mismatch");
    future(attestation.expiresAt, now, "Software workload attestation");
    const { signature, ...body } = attestation;
    let valid = false;
    try { valid = verify(null, Buffer.from(attestationBody(body), "utf8"), record.identity.publicKey!, Buffer.from(signature, "base64url")); } catch { valid = false; }
    if (!valid) throw new Error("Invalid software workload attestation signature");
    const stored = this.attestations.get(attestation.agentId);
    if (!stored || digestJson(stored) !== digestJson(attestation)) throw new Error("Unknown or tampered software workload attestation");
    return true;
  }

  /** Verifies the authority-owned current workload attestation without accepting caller-owned evidence. */
  verifyExecutionTrust(agentId: string, now: Date): SoftwareWorkloadAttestation {
    const record = this.record(agentId);
    if (record.identity.trustState !== "ATTESTED") throw new Error("IDENTITY_ATTESTATION_REQUIRED");
    const attestation = this.attestations.get(agentId);
    if (!attestation) throw new Error("IDENTITY_ATTESTATION_MISSING");
    if (attestation.keyId !== record.key.keyId || attestation.agentId !== agentId) throw new Error("IDENTITY_ATTESTATION_KEY_MISMATCH");
    future(attestation.expiresAt, now, "Software workload attestation");
    const { signature, ...body } = attestation;
    let valid = false;
    try { valid = verify(null, Buffer.from(attestationBody(body), "utf8"), record.identity.publicKey!, Buffer.from(signature, "base64url")); } catch { valid = false; }
    if (!valid || digestJson(this.attestations.get(agentId)) !== digestJson(attestation)) throw new Error("IDENTITY_ATTESTATION_INVALID");
    return { ...attestation };
  }

  suspend(agentId: string, now: Date): AgentIdentity {
    return this.changeState(agentId, "SUSPENDED", now);
  }

  revoke(agentId: string, now: Date): AgentIdentity {
    const identity = this.changeState(agentId, "REVOKED", now);
    for (const entry of this.sessions.values()) if (entry.session.agentId === agentId) entry.session = { ...entry.session, status: "REVOKED" };
    this.persist();
    return identity;
  }

  openSession(agentId: string, projectId: string, ttlSeconds: number, now: Date): AgentSession {
    const record = this.record(agentId);
    nonEmpty(projectId, "projectId");
    if (projectId !== record.identity.projectId) throw new Error("Session project does not match identity");
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_SESSION_TTL_SECONDS) throw new Error("Invalid session TTL");
    if (record.identity.trustState === "SUSPENDED" || record.identity.trustState === "REVOKED" || record.identity.trustState === "UNVERIFIED") throw new Error("Identity is not eligible for a session");
    const session: AgentSession = { id: newId("session"), agentId, projectId, startedAt: iso(now, "now"), expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(), status: "ACTIVE" };
    this.sessions.set(session.id, { session: copySession(session), digest: digestJson(session) });
    this.persist();
    return copySession(session);
  }

  verifySession(session: AgentSession, now: Date): boolean {
    const stored = this.sessions.get(session.id);
    if (!stored || stored.digest !== digestJson(stored.session) || stored.digest !== digestJson(session)) throw new Error("Unknown or tampered session");
    const record = this.identities.get(session.agentId);
    if (!record || session.projectId !== record.identity.projectId) throw new Error("Session project or identity mismatch");
    if (session.status !== "ACTIVE" || record.identity.trustState === "SUSPENDED" || record.identity.trustState === "REVOKED") throw new Error("Session is not active");
    if (Date.parse(session.expiresAt) <= now.getTime()) { stored.session = { ...stored.session, status: "EXPIRED" }; this.persist(); throw new Error("Session is expired"); }
    return true;
  }

  /** Returns an authority-owned, verified execution context for a live session. */
  executionContext(agentId: string, sessionId: string, now = new Date()): IdentityRuntimeContext {
    const record = this.record(agentId);
    const entry = this.sessions.get(nonEmpty(sessionId, "sessionId"));
    if (!entry || entry.session.agentId !== agentId) throw new Error("IDENTITY_SESSION_NOT_FOUND");
    const session = copySession(entry.session);
    this.verifySession(session, now);
    this.verifyExecutionTrust(record.identity.id, now);
    return { identity: copyIdentity(record.identity), session };
  }

  identityDigest(identity: AgentIdentity): string {
    return digestJson(identity);
  }

  /**
   * Creates the only identity context shape intended for receipt metadata.
   * The session is verified against this authority before it is bound.
   */
  evidenceBinding(identity: AgentIdentity, session: AgentSession, now = new Date()): IdentityEvidenceBinding {
    this.verifySession(session, now);
    const record = this.record(identity.id);
    if (digestJson(identity) !== digestJson(record.identity)) throw new Error("Identity is unknown or tampered");
    if (identity.id !== session.agentId || identity.projectId !== session.projectId) throw new Error("Identity and session binding mismatch");
    return createIdentityEvidenceBinding(identity, session);
  }

  private record(agentId: string): IdentityRecord {
    const record = this.identities.get(nonEmpty(agentId, "agentId"));
    if (!record) throw new Error("Unknown agent identity");
    return record;
  }

  private changeState(agentId: string, trustState: "SUSPENDED" | "REVOKED", now: Date): AgentIdentity {
    const record = this.record(agentId);
    record.identity = { ...record.identity, trustState, updatedAt: iso(now, "now") };
    this.persist();
    return copyIdentity(record.identity);
  }

  private writeIdentityKey(agentId: string, key: KeyMaterial): void {
    if (!this.statePath) return;
    writeAtomic(sidecarPath(this.statePath, agentId), String(key.privateKey));
  }

  private readEnvelope(bytes: Buffer): StateEnvelope {
    if (bytes.length > MAX_STATE_BYTES) throw new Error("Persisted identity state exceeds bounded size");
    let parsed: unknown;
    try { parsed = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("Malformed persisted identity state"); }
    const envelope = object(parsed, "envelope");
    exactKeys(envelope, ["version", "signerPublicKey", "state", "signature"], "envelope");
    if (envelope.version !== 1) throw new Error("Unsupported persisted identity state version");
    const signerPublicKey = text(envelope.signerPublicKey, "signerPublicKey");
    const signature = text(envelope.signature, "signature");
    const state = envelope.state as PersistedState;
    try {
      if (!verify(null, Buffer.from(digestJson(state), "utf8"), signerPublicKey, Buffer.from(signature, "base64url"))) throw new Error("Invalid persisted identity state signature");
    } catch (error) { if (error instanceof Error && error.message.startsWith("Invalid persisted")) throw error; throw new Error("Invalid persisted identity state signature"); }
    return { version: 1, signerPublicKey, state, signature };
  }

  private load(state: PersistedState): void {
    const raw = object(state, "state");
    exactKeys(raw, ["version", "identities", "sessions", "consumedTokenIds", "attestations"], "state");
    if (raw.version !== 1 || !Array.isArray(raw.identities) || !Array.isArray(raw.sessions) || !Array.isArray(raw.consumedTokenIds) || !Array.isArray(raw.attestations)) throw new Error("Invalid persisted identity state shape");
    for (const entryUnknown of raw.identities) {
      const entry = object(entryUnknown, "identity record"); exactKeys(entry, ["identity", "keyId", "publicKey"], "identity record");
      const identity = object(entry.identity, "identity"); exactKeys(identity, ["id", "organizationId", "projectId", "displayName", "runtimeType", "publicKey", "trustState", "createdAt", "updatedAt"], "identity");
      const id = text(identity.id, "identity.id"); const publicKey = text(entry.publicKey, "identity.publicKey"); const keyId = text(entry.keyId, "identity.keyId");
      if (identity.publicKey !== publicKey || this.identities.has(id)) throw new Error("Persisted identity key mismatch");
      const keyFile = sidecarPath(this.statePath!, id);
      if (!existsSync(keyFile)) throw new Error("Incomplete persisted identity key set");
      assertPrivateSidecar(keyFile);
      const privateKey = readFileSync(keyFile, "utf8");
      let matches = false;
      try { matches = privatePublicPem(privateKey) === publicKey; } catch { matches = false; }
      if (!matches) throw new Error("Persisted identity key mismatch");
      this.identities.set(id, { identity: copyIdentity(identity as unknown as AgentIdentity), key: { keyId, privateKey, publicKey } });
    }
    for (const sessionUnknown of raw.sessions) {
      const entry = object(sessionUnknown, "session record"); exactKeys(entry, ["session", "digest"], "session record");
      const session = entry.session as AgentSession; const digest = text(entry.digest, "session.digest");
      if (!DIGEST.test(digest) || digestJson(session) !== digest || this.sessions.has(session.id)) throw new Error("Tampered persisted session state");
      if (!this.identities.has(session.agentId)) throw new Error("Persisted session identity is missing");
      this.sessions.set(session.id, { session: copySession(session), digest });
    }
    for (const tokenId of raw.consumedTokenIds) this.consumedTokens.add(text(tokenId, "consumed token id"));
    for (const attestationUnknown of raw.attestations) {
      const attestation = attestationUnknown as SoftwareWorkloadAttestation;
      const value = object(attestationUnknown, "attestation"); exactKeys(value, ["attestationId", "agentId", "keyId", "manifestDigest", "issuedAt", "expiresAt", "signature"], "attestation");
      const record = this.identities.get(attestation.agentId);
      if (!record || this.attestations.has(attestation.agentId) || attestation.keyId !== record.key.keyId || !DIGEST.test(attestation.manifestDigest)) throw new Error("Invalid persisted attestation state");
      let valid = false;
      try {
        const { signature, ...body } = attestation;
        valid = verify(null, Buffer.from(attestationBody(body), "utf8"), record.identity.publicKey!, Buffer.from(signature, "base64url"));
      } catch { valid = false; }
      if (!valid) throw new Error("Invalid persisted attestation signature");
      this.attestations.set(attestation.agentId, attestation);
    }
  }

  private persist(): void {
    if (!this.statePath || !this.stateSigningKey) return;
    const state: PersistedState = { version: 1, identities: [...this.identities.values()].map(({ identity, key }) => ({ identity, keyId: key.keyId, publicKey: key.publicKey })), sessions: [...this.sessions.values()].map(({ session, digest }) => ({ session, digest })), consumedTokenIds: [...this.consumedTokens], attestations: [...this.attestations.values()] };
    const signature = sign(null, Buffer.from(digestJson(state), "utf8"), this.stateSigningKey.privateKey).toString("base64url");
    writeAtomic(this.statePath, JSON.stringify({ version: 1, signerPublicKey: this.stateSigningKey.publicKey, state, signature } satisfies StateEnvelope));
  }
}

export function createIdentityEvidenceBinding(identity: AgentIdentity, session: AgentSession): IdentityEvidenceBinding {
  if (identity.id !== session.agentId || identity.projectId !== session.projectId) throw new Error("Identity and session binding mismatch");
  const identityDigest = digestJson(identity);
  const sessionDigest = digestJson(session);
  const projectDigest = digestJson({ projectId: identity.projectId });
  const agentDigest = digestJson({ agentId: identity.id, identityDigest });
  const bindingDigest = digestJson({ agentDigest, identityDigest, projectDigest, sessionDigest });
  return Object.freeze({ identityDigest, sessionDigest, projectDigest, agentDigest, bindingDigest });
}

export function assertIdentityEvidenceBinding(binding: IdentityEvidenceBinding): void {
  if (binding === null || typeof binding !== "object") throw new Error("Identity evidence binding must be an object");
  const identityDigest = binding.identityDigest;
  const sessionDigest = binding.sessionDigest;
  const projectDigest = binding.projectDigest;
  const agentDigest = binding.agentDigest;
  const bindingDigest = binding.bindingDigest;
  for (const [name, value] of Object.entries({ identityDigest, sessionDigest, projectDigest, agentDigest, bindingDigest })) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error(`${name} must be a canonical SHA-256 digest`);
  }
  if (bindingDigest !== digestJson({ agentDigest, identityDigest, projectDigest, sessionDigest })) {
    throw new Error("Identity evidence binding digest mismatch");
  }
}
