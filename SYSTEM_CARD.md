# Invock system card

## Purpose

Invock is a local-first deterministic reference monitor for agent tool calls. It is designed to reduce unauthorized side effects at the mediation boundary and produce signed, redacted evidence.

## Supported boundary

- MCP newline-delimited stdio and authenticated Streamable HTTP POST.
- Local TypeScript/Python authorization clients.
- Local Ed25519 software workload identity primitives.
- Policy, Intent Capsule, Capability Lease, lineage, approval, receipt, and containment primitives.

## Security properties targeted

- Fail-closed normalization and unknown-value handling.
- Monotonic delegated authority.
- Exact one-time approval binding.
- Session-partitioned lineage.
- Signed receipt chaining and terminal-head verification.
- Required containment never silently falls back to an unenforced process.

## Out of scope or not proven

Invock does not prove hardware attestation, upstream honesty after an allowed request, arbitrary semantic secret transformation detection, DNS-rebinding resistance, hosted enterprise controls, production deployment safety, or framework-wide interception for the request adapters.

## Evaluation status

The current local run (2026-08-02) reports 291 passing tests, zero failures, and zero skips. `pnpm certify` passes its executed phases with 207 files scanned and zero high-confidence findings; mutation review kills 3/3 configured mutations. The local Arena covers 18 scenarios × 3 repetitions with 51/51 protected attacks blocked, 3/3 benign workflows completed, and a measured 0/3 protected false-positive rate for the bounded benign fixture. The scoped Chromium dashboard runner and three sequential digest-pinned product containment runs pass; `pnpm supply-chain -- --sign` verifies an Ed25519 signature over the local SBOM/evidence payload. Strict-authority CLI coverage, stdio schema-quarantine persistence, receipt-key history, detached lineage proofs, and gate-bound containment evidence are tested; ordinary adapter forwarding is not gateway-wide containment. Judge mode is `degraded` because its browser/Compose evidence path is unavailable, and final certification remains `NOT READY`. Clean release rehearsals are now locally complete; broad accessibility, independent-audit reconciliation, external provenance/advisory evidence, and production deployment remain NOT PROVEN.

## Responsible use

Use fake secrets and loopback sinks for demonstrations. Treat `ALLOW` as a decision at the configured mediation boundary, not as a guarantee that a remote service is benign. Review every generated policy and activate it only with attributable human approval.
