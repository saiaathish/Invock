# Implementation status

## Hackathon-supported boundary

Invock is implemented as a local MCP invocation reference monitor for newline-delimited stdio and authenticated Streamable HTTP POST mediation.

Delivered and covered by the mandatory suite:

- Shared non-bypassable authorization for requests and notifications.
- Complete argument-schema validation and canonical authorized forwarding.
- Duplicate-ID protection, response-ID validation, control-plane correlation, and bounded timeout cleanup.
- Persistent registry and live schema-drift quarantine with approval invalidation.
- Exact atomic one-time approvals including rejection, expiry validation, replay defense, protocol/session/schema/registry binding, and 20-contender concurrency proof.
- Session-partitioned encoded-flow lineage and live zero-sink exfiltration tests.
- External Ed25519/HMAC keys, signed receipts, signed chain head, terminal-deletion detection, and fail-closed corruption readiness.
- Configurable isolated databases and key directories with schema-version checks and legacy key migration.
- Hardened authenticated loopback API/dashboard.
- Deterministic `pnpm demo`, `pnpm demo:certify`, and authoritative `pnpm certify`.
- GitHub-ready license, ignore rules, exact package-manager metadata, Node version, and CI workflow.

Current mandatory suite: **122 tests, 122 passing, 0 failed, 0 skipped**. Expanded INV-41..INV-85 evidence and release certification pass in `EXPANDED_INVARIANTS_MATRIX.md` and `scripts/expanded-certify.ts`.

## Explicit P3 roadmap only

- Complete Streamable HTTP GET/SSE upstream lifecycle.
- DNS pinning and redirect-by-redirect enforcement.
- OS/container containment.
- Rich SQL/command semantic analysis.
- Semantic secret paraphrase/arbitrary cryptographic transformation detection.
- External transparency anchoring, SBOM/provenance, richer UI workflows, and broad performance/fuzz matrices.

Invock controls tool invocations visible at its supported mediation boundary. It does not prove that an upstream tool server behaves honestly after receiving an allowed request.
