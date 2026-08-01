# Invock security boundary

Invock controls MCP `tools/call` invocations and the explicitly allowlisted inert control-plane methods visible at its supported mediation boundary.

Supported transports:

- Newline-delimited JSON-RPC/MCP stdio mediation.
- Authenticated, loopback-by-default Streamable HTTP POST mediation for explicit supported protocol versions.

Not supported in this hackathon boundary:

- Complete Streamable HTTP GET/SSE upstream session lifecycle.
- DNS pinning and redirect-by-redirect destination enforcement.
- OS or container sandboxing.
- Semantic paraphrase or arbitrary cryptographic secret-transformation detection.
- Proof that an upstream server behaves honestly after receiving an allowed request.

Invock controls tool invocations visible at its supported mediation boundary. It does not prove that an upstream tool server behaves honestly after receiving an allowed request.

Use fake data and loopback sinks for demonstrations. Never test with real secrets or public exfiltration targets.