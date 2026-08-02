# Invock security boundary

Invock controls MCP `tools/call` invocations and the explicitly allowlisted inert control-plane methods visible at its supported mediation boundary.

Supported transports:

- Newline-delimited JSON-RPC/MCP stdio mediation.
- Authenticated, loopback-by-default Streamable HTTP POST mediation for explicit supported protocol versions.

Not supported in this hackathon boundary:

- Complete Streamable HTTP GET/SSE upstream session lifecycle.
- Fleet-wide DNS policy: remote Streamable HTTP targets are required to use HTTPS and a caller-supplied DNS pinner, but Invock does not provide a hosted DNS policy or resolver service.
- Production-wide containment certification. The local runner supports Docker and macOS sandbox profiles when the runtime is available, and returns `unsupported` or `network: "unknown"` when enforcement cannot be proven.
- Semantic paraphrase or arbitrary cryptographic secret-transformation detection.
- Proof that an upstream server behaves honestly after receiving an allowed request.

The local authenticated API exposes `POST /api/v1/authorize` through the same deterministic gate as the MCP adapters. Intent Capsules are only accepted with an agent, session, and validated Capability Lease chain; the server does not synthesize authority. Software workload identity is local Ed25519 identity, not hardware attestation. `rootIssuer` and lease `issuer` values are immutable, digest-bound labels; they are not claims of independently authenticated issuer provenance unless an embedding supplies and verifies that control-plane record.

Invock controls tool invocations visible at its supported mediation boundary. It does not prove that an upstream tool server behaves honestly after receiving an allowed request.

Use fake data and loopback sinks for demonstrations. Never test with real secrets or public exfiltration targets.
