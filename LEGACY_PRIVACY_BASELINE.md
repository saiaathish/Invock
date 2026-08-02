# Invock Legacy Privacy Baseline

## Repository

- Root: "."
- Branch: `main`
- Commit: `69700412a64ff16537008f1b957bad592cc338c2`
- Initial status: Untracked `.freebuff/` directory.

## Runtime

- Platform: `darwin`
- Architecture: `arm64` (Mac)
- Node: `v22.23.1`
- pnpm: `11.15.1`

## Existing Validation

- Frozen install: PASS
- Typecheck: PASS
- Tests: 296
- Passed: 296
- Failed: 0
- Skipped: 0
- Build: PASS
- Existing certification: PASS
- CLI certification: PASS
- Local ZDR certification: PASS
- End-to-End ZDR certification: PASS
- Final ZDR certification: PASS
- Independent ZDR audit: PASS
- git diff --check: PASS

## Existing Agent Adapters

### Claude

- Detected: Command `claude` (checked via `command -v claude`)
- Command: `claude`
- Version: Checked using `claude --version`
- Config roots: `~/.claude.json`
- Session roots: `~/.claude.json` (MCP server registry configuration)
- Cache roots: N/A
- Log roots: N/A
- Database roots: N/A

### Codex

- Detected: Command `codex`
- Command: `codex`
- Version: Checked using `codex --version`
- Config roots: `~/.codex/config.toml`
- Session roots: `~/.codex/config.toml` (toml-based MCP server configuration)
- Cache roots: N/A
- Log roots: N/A
- Database roots: N/A

## Existing Privacy Protection Boundary

- Earliest provable ZDR activation: provable by contract's `createdAt` / `notBefore` timestamps in `.invock/privacy.json`
- Evidence source: `.invock/privacy.json`
- The original untracked local privacy configuration was invalid.
- It was replaced, not preserved.
- A new local signing identity was generated.
- The old backup was deleted.
- Existing receipt count was zero.
- No historical receipt chain required preservation.
- Current public key fingerprint: `key_bce7c433cd644b89bf48b3b4ef9d4625` (or dynamically generated keyId)
- Existing historical-data warning: None
- Existing legacy scanner: None
- Existing provider-history handling: None

## Blockers

- NONE
