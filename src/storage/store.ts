import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { digestJson, newId, sameDigest, sha256 } from "../core/canonical.js";
import type { StoredFingerprint } from "../core/lineage.js";
import type { ActionEnvelope, DataLabel, PolicyDecision, Verdict } from "../core/types.js";
import { generateSigningMaterial, makeReceiptPayload, signChainHead, signReceipt, verifyChainHead, verifyReceipt, type SignedChainHead, type SignedReceipt, type SigningMaterial } from "./receipts.js";

interface InvocationRow { invocation_id: string; envelope_json: string; decision_json: string; status: string; upstream_forwarded: number; created_at: string; }
interface ApprovalRow { approval_id: string; invocation_id: string; binding_digest: string; status: string; expires_at: string; }

export interface ActivityItem { invocationId: string; toolName: string; verdict: Verdict; status: string; createdAt: string; receiptId?: string; }
export interface PendingApproval { approvalId: string; invocationId: string; bindingDigest: string; expiresAt: string; status: string; }
export interface ToolRegistryRecord {
  serverId: string;
  toolName: string;
  descriptorDigest: string;
  inputSchemaDigest: string;
  normalizedSchemaVersion: string;
  capabilities: string[];
  effects: string[];
  trustState: "trusted" | "reviewed" | "unknown" | "quarantined";
  quarantineReason?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  registryVersion: string;
  descriptorJson: string;
  normalizerJson: string;
}
export interface StoreOptions { keyDirectory?: string; chainHeadPath?: string; taintKey?: Buffer; signing?: SigningMaterial; }

export class InvockStore {
  readonly db: DatabaseSync;
  readonly instanceId: string;
  readonly taintKey: Buffer;
  readonly signing: SigningMaterial;
  readonly keyDirectory: string;
  private readonly chainHeadPath: string;
  private readonly ephemeralKeyDirectory: boolean;
  private healthy = true;

  constructor(databasePath = ":memory:", options: StoreOptions = {}) {
    if (databasePath !== ":memory:") { mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 }); }
    this.db = new DatabaseSync(databasePath);
    if (databasePath !== ":memory:") { try { chmodSync(databasePath, 0o600); } catch { /* owner permission is best effort on non-POSIX filesystems */ } }
    this.db.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;");
    const version = this.db.prepare("SELECT sqlite_version() AS version").get() as { version: string };
    if (version.version.localeCompare("3.51.3", undefined, { numeric: true }) < 0) throw new Error(`SQLite ${version.version} is below the required 3.51.3`);
    this.migrate();
    this.ephemeralKeyDirectory = databasePath === ":memory:" && !options.keyDirectory;
    this.keyDirectory = options.keyDirectory ?? (this.ephemeralKeyDirectory ? mkdtempSync(join(tmpdir(), "invock-keys-")) : `${databasePath}.keys`);
    this.chainHeadPath = options.chainHeadPath ?? join(this.keyDirectory, "chain-head.json");
    mkdirSync(this.keyDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.keyDirectory, 0o700); } catch { /* best effort */ }
    const instance = this.getMeta("instance_id");
    this.instanceId = instance ?? newId("instance");
    const legacyTaintKey = this.getMeta("taint_key");
    const legacySigning = this.getMeta("signing");
    this.taintKey = options.taintKey ?? this.loadOrCreateTaintKey(legacyTaintKey);
    this.signing = options.signing ?? this.loadOrCreateSigning(legacySigning);
    if (!instance) this.setMeta("instance_id", this.instanceId);
    this.setMeta("signing_key_id", this.signing.signingKeyId);
    this.setMeta("signing_public_key", this.signing.publicKeyPem);
    if (legacyTaintKey !== null || legacySigning !== null) {
      this.db.prepare("UPDATE meta SET value = 'migrated-outside-sqlite' WHERE key IN ('taint_key', 'signing')").run();
      this.db.prepare("DELETE FROM meta WHERE key IN ('taint_key', 'signing')").run();
      this.db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);");
    }
    this.ensureChainHead();
    if (!this.verifyChain()) { this.healthy = false; throw new Error("Receipt chain verification failed; refusing to start"); }
  }

  private migrate(): void {
    const metaExists = (this.db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'meta'").get() as { present: number } | undefined) !== undefined;
    if (metaExists) {
      const version = (this.db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value: string } | undefined)?.value;
      if (version !== undefined && version !== "2") throw new Error(`Unsupported future or unknown database schema version: ${version}`);
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS invocations (
        invocation_id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL, decision_json TEXT NOT NULL,
        status TEXT NOT NULL, upstream_forwarded INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, completed_at TEXT
      ) STRICT;
      CREATE TABLE IF NOT EXISTS taint_records (
        taint_record_id TEXT PRIMARY KEY, source_invocation_id TEXT NOT NULL, session_id TEXT NOT NULL, labels_json TEXT NOT NULL, expires_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS taint_fingerprints (
        fingerprint_id TEXT PRIMARY KEY, taint_record_id TEXT NOT NULL REFERENCES taint_records(taint_record_id) ON DELETE CASCADE,
        kind TEXT NOT NULL, digest BLOB NOT NULL CHECK(length(digest) = 32), source_length INTEGER NOT NULL,
        UNIQUE(taint_record_id, kind, digest)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS idx_fingerprint_lookup ON taint_fingerprints(kind, digest);
      CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY, invocation_id TEXT NOT NULL UNIQUE REFERENCES invocations(invocation_id),
        binding_digest TEXT NOT NULL, status TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT, consumed_at TEXT
      ) STRICT;
      CREATE TABLE IF NOT EXISTS receipts (
        sequence INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, receipt_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS tool_registry (
        server_id TEXT NOT NULL, tool_name TEXT NOT NULL, descriptor_digest TEXT NOT NULL, input_schema_digest TEXT NOT NULL,
        normalized_schema_version TEXT NOT NULL, capabilities_json TEXT NOT NULL, effects_json TEXT NOT NULL, trust_state TEXT NOT NULL,
        quarantine_reason TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, registry_version TEXT NOT NULL,
        descriptor_json TEXT NOT NULL, normalizer_json TEXT NOT NULL, PRIMARY KEY(server_id, tool_name)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS expansion_records (
        record_id TEXT PRIMARY KEY, record_type TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      ) STRICT;
    `);
    const taintColumns = this.db.prepare("PRAGMA table_info(taint_records)").all() as Array<{ name: string }>;
    if (!taintColumns.some(column => column.name === "session_id")) this.db.exec("ALTER TABLE taint_records ADD COLUMN session_id TEXT NOT NULL DEFAULT 'legacy'");
    this.setMeta("schema_version", "2");
  }
  private setMeta(key: string, value: string): void { this.db.prepare("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)").run(key, value); }
  private getMeta(key: string): string | null { return (this.db.prepare("SELECT value FROM meta WHERE key = ?").get(key) as { value: string } | undefined)?.value ?? null; }
  private writeSecret(path: string, content: string | Buffer): void { const temporary = `${path}.${process.pid}.${Date.now()}.tmp`; writeFileSync(temporary, content, { mode: 0o600 }); try { chmodSync(temporary, 0o600); } catch { /* best effort */ } renameSync(temporary, path); }
  private loadOrCreateTaintKey(legacy: string | null): Buffer { const path = join(this.keyDirectory, "taint-hmac.key"); if (existsSync(path)) return Buffer.from(readFileSync(path, "utf8").trim(), "base64url"); const key = legacy ? Buffer.from(legacy, "base64url") : randomBytes(32); this.writeSecret(path, key.toString("base64url")); return key; }
  private loadOrCreateSigning(legacy: string | null): SigningMaterial {
    const privatePath = join(this.keyDirectory, "receipt-ed25519.private.pem"); const publicPath = join(this.keyDirectory, "receipt-ed25519.public.pem"); const keyIdPath = join(this.keyDirectory, "receipt-ed25519.key-id");
    if (existsSync(privatePath) && existsSync(publicPath) && existsSync(keyIdPath)) return { privateKeyPem: readFileSync(privatePath, "utf8"), publicKeyPem: readFileSync(publicPath, "utf8"), signingKeyId: readFileSync(keyIdPath, "utf8").trim() };
    const material = legacy ? JSON.parse(legacy) as SigningMaterial : generateSigningMaterial(); this.writeSecret(privatePath, material.privateKeyPem); this.writeSecret(publicPath, material.publicKeyPem); this.writeSecret(keyIdPath, material.signingKeyId); return material;
  }
  private chainHead(): SignedChainHead | null { try { return JSON.parse(readFileSync(this.chainHeadPath, "utf8")) as SignedChainHead; } catch { return null; } }
  private writeChainHead(head: SignedChainHead): void { this.writeSecret(this.chainHeadPath, `${JSON.stringify(head)}\n`); }
  private ensureChainHead(): void {
    if (this.chainHead()) return;
    const row = this.db.prepare("SELECT sequence, receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1").get() as { sequence: number; receipt_hash: string } | undefined;
    const count = (this.db.prepare("SELECT COUNT(*) AS count FROM receipts").get() as { count: number }).count;
    if (count > 0) throw new Error("Receipt chain head is missing; refusing to accept possible terminal truncation");
    this.writeChainHead(signChainHead({ chainId: this.getMeta("chain_id") ?? this.instanceId, receiptCount: count, lastSequence: row?.sequence ?? 0, lastReceiptHash: row?.receipt_hash ?? null, keyId: this.signing.signingKeyId, updatedAt: new Date().toISOString() }, this.signing));
    if (this.getMeta("chain_id") === null) this.setMeta("chain_id", this.instanceId);
  }
  close(): void { this.db.close(); if (this.ephemeralKeyDirectory) rmSync(this.keyDirectory, { recursive: true, force: true }); }
  isReady(): boolean { return this.healthy && this.verifyChain(); }

  private approvalBinding(envelope: ActionEnvelope, decision: PolicyDecision): string {
    return digestJson({ principalId: envelope.subject.principalId, clientId: envelope.subject.clientId, sessionId: envelope.sessionId, serverId: envelope.target.serverId, toolName: envelope.target.toolName, argumentsDigest: envelope.integrity.argumentsDigest, toolSchemaDigest: envelope.target.toolSchemaDigest, descriptorDigest: envelope.target.toolDescriptorDigest, registryVersion: envelope.target.registryVersion, protocolEra: envelope.target.protocolEra, policyVersionId: decision.policyVersionId, decisionReasonCodes: decision.reasonCodes, requestedCapabilities: envelope.capabilities, requestedEffects: envelope.effects });
  }

  recordInterception(envelope: ActionEnvelope, decision: PolicyDecision, now = new Date()): PendingApproval | undefined {
    this.db.prepare("INSERT INTO invocations(invocation_id, envelope_json, decision_json, status, created_at) VALUES (?, ?, ?, ?, ?)").run(envelope.invocationId, JSON.stringify(envelope), JSON.stringify(decision), decision.verdict === "BLOCK" ? "blocked" : decision.verdict === "APPROVAL_REQUIRED" ? "pending_approval" : "intercepted", now.toISOString());
    if (decision.verdict !== "APPROVAL_REQUIRED") return undefined;
    const approvalId = newId("apr"); const bindingDigest = this.approvalBinding(envelope, decision); const ttl = decision.obligations.find(item => item.type === "approval")?.ttlSeconds ?? 300; const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();
    this.db.prepare("INSERT INTO approvals(approval_id, invocation_id, binding_digest, status, expires_at) VALUES (?, ?, ?, 'pending', ?)").run(approvalId, envelope.invocationId, bindingDigest, expiresAt);
    return { approvalId, invocationId: envelope.invocationId, bindingDigest, expiresAt, status: "pending" };
  }

  approve(approvalId: string, expectedBindingDigest: string, now = new Date()): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db.prepare("SELECT approval_id, invocation_id, binding_digest, status, expires_at FROM approvals WHERE approval_id = ?").get(approvalId) as ApprovalRow | undefined;
      const valid = row && row.status === "pending" && row.expires_at > now.toISOString() && sameDigest(row.binding_digest, expectedBindingDigest);
      if (!valid) { this.db.exec("ROLLBACK"); return false; }
      this.db.prepare("UPDATE approvals SET status = 'approved', decided_at = ? WHERE approval_id = ?").run(now.toISOString(), approvalId);
      this.db.exec("COMMIT"); return true;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  reject(approvalId: string, expectedBindingDigest: string, now = new Date()): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try { const row = this.db.prepare("SELECT approval_id, binding_digest, status, expires_at FROM approvals WHERE approval_id = ?").get(approvalId) as ApprovalRow | undefined; if (!row || row.status !== "pending" || row.expires_at <= now.toISOString() || !sameDigest(row.binding_digest, expectedBindingDigest)) { this.db.exec("ROLLBACK"); return false; } this.db.prepare("UPDATE approvals SET status = 'rejected', decided_at = ? WHERE approval_id = ?").run(now.toISOString(), approvalId); this.db.exec("COMMIT"); return true; } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  /** Atomically consumes an exact approval. Any mutation or replay returns false. */
  consumeApproval(approvalId: string, envelope: ActionEnvelope, bindingDecision: PolicyDecision, forwardingDecision: PolicyDecision, now = new Date()): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db.prepare("SELECT approval_id, invocation_id, binding_digest, status, expires_at FROM approvals WHERE approval_id = ?").get(approvalId) as ApprovalRow | undefined;
      const valid = row && row.status === "approved" && row.expires_at > now.toISOString() && sameDigest(row.binding_digest, this.approvalBinding(envelope, bindingDecision));
      if (!valid) { this.db.exec("ROLLBACK"); return false; }
      this.db.prepare("UPDATE approvals SET status = 'consumed', consumed_at = ? WHERE approval_id = ?").run(now.toISOString(), approvalId);
      this.db.prepare("UPDATE invocations SET status = 'pending_approval' WHERE invocation_id = ?").run(row.invocation_id);
      this.db.prepare("INSERT INTO invocations(invocation_id, envelope_json, decision_json, status, upstream_forwarded, created_at) VALUES (?, ?, ?, 'forwarding', 1, ?)").run(envelope.invocationId, JSON.stringify(envelope), JSON.stringify(forwardingDecision), now.toISOString());
      this.db.exec("COMMIT"); return true;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  activeFingerprints(sessionId: string, now = new Date()): StoredFingerprint[] {
    const rows = this.db.prepare(`SELECT fp.fingerprint_id, fp.kind, fp.digest, fp.source_length, tr.taint_record_id, tr.source_invocation_id, tr.labels_json FROM taint_fingerprints fp JOIN taint_records tr ON tr.taint_record_id = fp.taint_record_id WHERE tr.expires_at > ? AND tr.session_id = ?`).all(now.toISOString(), sessionId) as Array<{ fingerprint_id: string; kind: StoredFingerprint["kind"]; digest: Uint8Array; source_length: number; taint_record_id: string; source_invocation_id: string; labels_json: string }>;
    return rows.map(row => ({ fingerprintId: row.fingerprint_id, kind: row.kind, digest: Buffer.from(row.digest), sourceLength: row.source_length, taintRecordId: row.taint_record_id, sourceInvocationId: row.source_invocation_id, labels: JSON.parse(row.labels_json) as DataLabel[] }));
  }

  recordTaint(sourceInvocationId: string, sessionId: string, labels: DataLabel[], fingerprints: Array<{ fingerprintId: string; kind: string; digest: Buffer; sourceLength: number }>, now = new Date(), ttlSeconds = 1800): void {
    if (fingerprints.length === 0 || labels.length === 0) return;
    const recordId = newId("taint"); const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO taint_records(taint_record_id, source_invocation_id, session_id, labels_json, expires_at) VALUES (?, ?, ?, ?, ?)").run(recordId, sourceInvocationId, sessionId, JSON.stringify(labels), expiresAt);
      const insert = this.db.prepare("INSERT INTO taint_fingerprints(fingerprint_id, taint_record_id, kind, digest, source_length) VALUES (?, ?, ?, ?, ?)");
      for (const item of fingerprints) insert.run(item.fingerprintId, recordId, item.kind, item.digest, item.sourceLength);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  complete(envelope: ActionEnvelope, decision: PolicyDecision, forwarded: boolean, result: unknown, approvalId?: string, now = new Date(), metadata: { intentCapsuleDigest?: string; capabilityLeaseChainDigest?: string; effectiveAuthorityDigest?: string; containmentRunId?: string; arenaRunId?: string; policyDraftDigest?: string; protocolProfileId?: string } = {}): SignedReceipt {
    this.db.exec("BEGIN IMMEDIATE");
    let committed = false;
    try {
      const previous = this.db.prepare("SELECT receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1").get() as { receipt_hash: string } | undefined;
      const sequence = (this.db.prepare("SELECT COALESCE(MAX(sequence), 0) AS maximum FROM receipts").get() as { maximum: number }).maximum + 1;
      const receipt = signReceipt(makeReceiptPayload({ instanceId: this.instanceId, sequence, envelope, decision, upstreamForwarded: forwarded, previousReceiptHash: previous?.receipt_hash ?? null, ...(forwarded ? { upstreamResultDigest: sha256(JSON.stringify(result)) } : {}), ...(approvalId ? { approvalId } : {}), ...metadata, now }), this.signing);
      this.db.prepare("INSERT INTO receipts(sequence, receipt_id, receipt_json, receipt_hash, created_at) VALUES (?, ?, ?, ?, ?)").run(sequence, receipt.payload.receiptId, JSON.stringify(receipt), receipt.receiptHash, now.toISOString());
      this.db.prepare("UPDATE invocations SET status = ?, upstream_forwarded = ?, completed_at = ? WHERE invocation_id = ?").run(forwarded ? "completed" : decision.verdict === "BLOCK" ? "blocked" : "pending_approval", forwarded ? 1 : 0, now.toISOString(), envelope.invocationId);
      this.db.exec("COMMIT"); committed = true;
      this.writeChainHead(signChainHead({ chainId: this.getMeta("chain_id") ?? this.instanceId, receiptCount: sequence, lastSequence: sequence, lastReceiptHash: receipt.receiptHash, keyId: this.signing.signingKeyId, updatedAt: now.toISOString() }, this.signing));
      return receipt;
    } catch (error) { if (!committed) this.db.exec("ROLLBACK"); throw error; }
  }

  verifyChain(): boolean {
    try {
      let previous: string | null = null; let expectedSequence = 1;
      const receipts = this.db.prepare("SELECT sequence, receipt_json, receipt_hash FROM receipts ORDER BY sequence ASC").all() as Array<{ sequence: number; receipt_json: string; receipt_hash: string }>;
      for (const row of receipts) { const receipt = JSON.parse(row.receipt_json) as SignedReceipt; if (row.sequence !== expectedSequence++ || row.receipt_hash !== receipt.receiptHash || receipt.signingKeyId !== this.signing.signingKeyId || !verifyReceipt(receipt, this.signing.publicKeyPem, previous)) { this.healthy = false; return false; } previous = receipt.receiptHash; }
      const head = this.chainHead(); const chainId = this.getMeta("chain_id") ?? this.instanceId;
      const valid = Boolean(head && verifyChainHead(head, this.signing.publicKeyPem) && head.chainId === chainId && head.keyId === this.signing.signingKeyId && head.receiptCount === receipts.length && head.lastSequence === receipts.length && head.lastReceiptHash === previous);
      this.healthy = valid; return valid;
    } catch { this.healthy = false; return false; }
  }
  listActivity(limit = 50): ActivityItem[] {
    const rows = this.db.prepare("SELECT invocation_id, envelope_json, decision_json, status, upstream_forwarded, created_at FROM invocations ORDER BY created_at DESC LIMIT ?").all(Math.min(Math.max(limit, 1), 200)) as unknown as InvocationRow[];
    return rows.map(row => { const envelope = JSON.parse(row.envelope_json) as ActionEnvelope; const decision = JSON.parse(row.decision_json) as PolicyDecision; const receipt = this.db.prepare("SELECT receipt_id FROM receipts WHERE json_extract(receipt_json, '$.payload.invocationId') = ?").get(row.invocation_id) as { receipt_id: string } | undefined; return { invocationId: row.invocation_id, toolName: envelope.target.toolName, verdict: decision.verdict, status: row.status, createdAt: row.created_at, ...(receipt ? { receiptId: receipt.receipt_id } : {}) }; });
  }
  listApprovals(): PendingApproval[] { return (this.db.prepare("SELECT approval_id, invocation_id, binding_digest, status, expires_at FROM approvals ORDER BY expires_at ASC").all() as unknown as ApprovalRow[]).map(row => ({ approvalId: row.approval_id, invocationId: row.invocation_id, bindingDigest: row.binding_digest, expiresAt: row.expires_at, status: row.status })); }
  getReceipt(id: string): SignedReceipt | undefined { const row = this.db.prepare("SELECT receipt_json FROM receipts WHERE receipt_id = ?").get(id) as { receipt_json: string } | undefined; return row ? JSON.parse(row.receipt_json) as SignedReceipt : undefined; }
  receiptChainStatus(): { ready: boolean; chainHead: SignedChainHead | null } { return { ready: this.isReady(), chainHead: this.chainHead() }; }
  saveToolRegistry(record: ToolRegistryRecord): void { this.db.prepare(`INSERT INTO tool_registry(server_id, tool_name, descriptor_digest, input_schema_digest, normalized_schema_version, capabilities_json, effects_json, trust_state, quarantine_reason, first_seen_at, last_seen_at, registry_version, descriptor_json, normalizer_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(server_id, tool_name) DO UPDATE SET descriptor_digest=excluded.descriptor_digest, input_schema_digest=excluded.input_schema_digest, normalized_schema_version=excluded.normalized_schema_version, capabilities_json=excluded.capabilities_json, effects_json=excluded.effects_json, trust_state=excluded.trust_state, quarantine_reason=excluded.quarantine_reason, last_seen_at=excluded.last_seen_at, registry_version=excluded.registry_version, descriptor_json=excluded.descriptor_json, normalizer_json=excluded.normalizer_json`).run(record.serverId, record.toolName, record.descriptorDigest, record.inputSchemaDigest, record.normalizedSchemaVersion, JSON.stringify(record.capabilities), JSON.stringify(record.effects), record.trustState, record.quarantineReason ?? null, record.firstSeenAt, record.lastSeenAt, record.registryVersion, record.descriptorJson, record.normalizerJson); }
  getToolRegistry(serverId: string, toolName: string): ToolRegistryRecord | undefined { const row = this.db.prepare("SELECT * FROM tool_registry WHERE server_id = ? AND tool_name = ?").get(serverId, toolName) as Record<string, unknown> | undefined; return row ? { serverId: String(row.server_id), toolName: String(row.tool_name), descriptorDigest: String(row.descriptor_digest), inputSchemaDigest: String(row.input_schema_digest), normalizedSchemaVersion: String(row.normalized_schema_version), capabilities: JSON.parse(String(row.capabilities_json)) as string[], effects: JSON.parse(String(row.effects_json)) as string[], trustState: String(row.trust_state) as ToolRegistryRecord["trustState"], ...(row.quarantine_reason ? { quarantineReason: String(row.quarantine_reason) } : {}), firstSeenAt: String(row.first_seen_at), lastSeenAt: String(row.last_seen_at), registryVersion: String(row.registry_version), descriptorJson: String(row.descriptor_json), normalizerJson: String(row.normalizer_json) } : undefined; }
  listToolRegistry(): ToolRegistryRecord[] { return (this.db.prepare("SELECT server_id, tool_name FROM tool_registry ORDER BY server_id, tool_name").all() as Array<{ server_id: string; tool_name: string }>).flatMap(row => { const record = this.getToolRegistry(row.server_id, row.tool_name); return record ? [record] : []; }); }
  saveExpansionRecord(input: { recordId: string; recordType: "intent_capsule" | "capability_lease" | "policy_draft" | "containment_run" | "arena_run" | "protocol_negotiation"; digest: string; payload: unknown; status: string; now?: Date }): void { const now = (input.now ?? new Date()).toISOString(); this.db.prepare("INSERT INTO expansion_records(record_id, record_type, digest, payload_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(record_id) DO UPDATE SET digest=excluded.digest, payload_json=excluded.payload_json, status=excluded.status, updated_at=excluded.updated_at").run(input.recordId, input.recordType, input.digest, JSON.stringify(input.payload), input.status, now, now); }
  getExpansionRecord(recordId: string): { recordId: string; recordType: string; digest: string; payload: unknown; status: string; createdAt: string; updatedAt: string } | undefined { const row = this.db.prepare("SELECT record_id, record_type, digest, payload_json, status, created_at, updated_at FROM expansion_records WHERE record_id = ?").get(recordId) as Record<string, unknown> | undefined; return row ? { recordId: String(row.record_id), recordType: String(row.record_type), digest: String(row.digest), payload: JSON.parse(String(row.payload_json)) as unknown, status: String(row.status), createdAt: String(row.created_at), updatedAt: String(row.updated_at) } : undefined; }
  listExpansionRecords(recordType?: string): Array<{ recordId: string; recordType: string; digest: string; status: string; createdAt: string; updatedAt: string }> { const rows = (recordType ? this.db.prepare("SELECT record_id, record_type, digest, status, created_at, updated_at FROM expansion_records WHERE record_type = ? ORDER BY created_at").all(recordType) : this.db.prepare("SELECT record_id, record_type, digest, status, created_at, updated_at FROM expansion_records ORDER BY created_at").all()) as Array<Record<string, unknown>>; return rows.map(row => ({ recordId: String(row.record_id), recordType: String(row.record_type), digest: String(row.digest), status: String(row.status), createdAt: String(row.created_at), updatedAt: String(row.updated_at) })); }
  invalidateToolApprovals(serverId: string, toolName: string): void { this.db.prepare(`UPDATE approvals SET status = 'invalidated', decided_at = ? WHERE approval_id IN (SELECT a.approval_id FROM approvals a JOIN invocations i ON i.invocation_id = a.invocation_id WHERE json_extract(i.envelope_json, '$.target.serverId') = ? AND json_extract(i.envelope_json, '$.target.toolName') = ? AND a.status IN ('pending','approved'))`).run(new Date().toISOString(), serverId, toolName); }
}
