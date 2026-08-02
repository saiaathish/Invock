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
- Signed software-workload enrollment/attestation, identity rotation/revocation, authority bindings, signed human capsule activation, and binding-aware receipts.
- Bounded hex and gzip/deflate/brotli lineage transforms with session-scoped fingerprints.
- Executable 18-scenario Arena (three repetitions and three execution paths), deterministic judge mode, property/fuzz/chaos suites, and a signed local supply-chain evidence inventory.
- GitHub-ready license, ignore rules, exact package-manager metadata, Node version, and CI workflow.

Latest verified mandatory suite: **322 tests, 322 passing, 0 failed, 0 skipped**. The local certification command reports only the phases it actually executes; digest-pinned local containment, signed local supply-chain evidence, receipt-key history, detached lineage proofs, and gate-bound containment evidence are implemented locally, while gateway-wide adapter enforcement, independent audits, external provenance/advisories, browser breadth, and broader production gates remain separately scoped.

The authenticated local `/api/v1/authorize` route is wired to the canonical `InvocationGate`. SDK requests carrying an Intent Capsule must also carry a session ID and a validated Capability Lease chain; malformed or incomplete authority fails closed.

## Explicit remaining gaps

- DNS pinning and redirect-by-redirect enforcement.
- External deployment and fleet-wide Docker/macOS containment proof beyond the local digest-pinned certification.
- Browser accessibility evidence and a hosted/enterprise control plane.
- External advisory/signature verification and build provenance beyond the locally verified evidence signature.
- Arbitrary semantic secret transformation detection and upstream honesty after an allowed request.

Invock controls tool invocations visible at its supported mediation boundary. It does not prove that an upstream tool server behaves honestly after receiving an allowed request.
