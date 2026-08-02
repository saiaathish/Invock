# Invock ZDR Implementation Baseline

## Repository

- Root: `/Users/saiaathishkarthik/Desktop/Invock`
- Branch: `main`
- Commit: `07c8b800c263fd82bf2297551a96773319e11db3`
- Initial Git status: existing CLI/package changes and `.freebuff/`; preserved.

## Runtime

- Node: `v22.23.1`
- pnpm: `11.15.1`
- Platform: `Darwin`
- Architecture: `arm64`

## Existing Validation

- Frozen install: PASS
- Typecheck: PASS
- Tests: PASS
- Passed: 291 before ZDR; 295 after ZDR tests
- Failed: 0
- Skipped: 0
- Build: PASS
- Existing certification: PASS
- CLI certification: PASS
- git diff --check: PASS

## Existing Privacy-Relevant Paths

### SQLite writes

- Receipts, metadata, containment evidence, lineage digests, and bounded result metadata. Existing receipt path receives request/result-derived fields and requires ZDR integration review.

### Filesystem writes

- Runtime database sidecars, signing material, control-plane state, containment records, agent backups, and privacy metadata.

### Logs

- CLI status and diagnostics; raw content logging is not intentionally enabled.

### Traces

- No dedicated tracing backend found.

### Receipts

- Signed content-free digests plus existing bounded metadata; existing engine persistence remains a Stage 2 integration boundary.

### Reports

- Evidence/report renderers expose redacted metadata and digests.

### API responses

- Authenticated authorization/execution responses can carry tool results by design; API persistence is not used.

### Dashboard storage

- Served runtime state; no browser persistence identified.

### Browser storage

- No localStorage/sessionStorage use identified.

### Temporary files

- Containment fixtures and agent atomic-write temporary files; privacy scans must cover them.

## Existing Agent Visibility

### Claude

- Model request visible to Invock: UNKNOWN outside MCP/tool path.
- Tool call visible to Invock: MCP calls only.
- Local client history controlled by Invock: NO.
- Provider retention verifiable: UNKNOWN.

### Codex

- Model request visible to Invock: UNKNOWN outside MCP/tool path.
- Tool call visible to Invock: MCP calls only.
- Local client history controlled by Invock: NO.
- Provider retention verifiable: UNKNOWN.

## Baseline Blockers

- End-to-End ZDR for third-party model/client paths remains blocked without declared, evidenced processor profiles.
