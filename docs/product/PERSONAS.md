# Invock personas

## Evidence legend

- **Validated fact** — directly established by an executed repository command or an explicit repository document.
- **Repository evidence** — a cited implementation or documentation observation; not customer validation.
- **Market research** — NOT PROVEN in this repository; no external research was used for these documents.
- **Product hypothesis** — a proposition to test.
- **Unvalidated assumption** — an unverified condition that could invalidate the proposition.

## Primary persona: MCP/platform developer

- **Repository evidence:** Invock mediates MCP `tools/call`; the CLI exposes `serve --stdio`, `policy validate`, `doctor`, `receipts verify`, `forge`, `guard`, and `contain` (`SECURITY.md`; `src/cli.ts:14-24`).
- **Job:** insert a deterministic authorization boundary before an MCP tool call, understand a block or approval, and keep the upstream protocol usable.
- **Product hypothesis:** the first adopter is a developer who owns an MCP client/server integration and can run a local process or loopback service.
- **Unvalidated assumption:** this developer has authority to change the integration and can tolerate policy configuration work.
- **Adoption signal:** a real integration can pass safe traffic through `serve --stdio` and explain a blocked or approval-required call using its receipt.

## Secondary persona: security engineer / application security reviewer

- **Repository evidence:** the implementation records signed receipts and a chain head, supports one-time approvals, registry drift quarantine, and fail-closed corruption readiness (`IMPLEMENTATION_STATUS.md:10-17`; `src/storage/receipts.ts:35-67`).
- **Job:** review which tool calls were allowed, blocked, or awaiting approval and assess whether the mediation boundary is explicit.
- **Product hypothesis:** this persona can become the internal champion when evidence quality matters more than broad policy automation.
- **Unvalidated assumption:** a local dashboard and signed receipt artifacts are acceptable evidence for the pilot’s review process.
- **Adoption signal:** the reviewer can reproduce a decision, verify the receipt chain, and identify the exact supported boundary.

## Economic / executive buyer hypothesis

- **Repository evidence:** NOT PROVEN. The repository identifies a local reference monitor, not a buyer, budget, organization size, or procurement path (`README.md`; `IMPLEMENTATION_STATUS.md`).
- **Product hypothesis:** the economic buyer may be a platform-security or developer-infrastructure leader responsible for safe AI/tool integrations.
- **Unvalidated assumption:** the cost of unsafe or unaudited tool calls is material enough to fund a product around this boundary.
- **Required validation:** interview evidence, a quantified avoided-incident or review-time outcome, and a deployment/security review.

## Explicit non-personas for the current boundary

Invock should not be positioned as a complete network security gateway, OS/container sandbox, honest-upstream proof, or full Streamable HTTP GET/SSE lifecycle. Those claims are contradicted by `SECURITY.md:10-17` and the P3 roadmap in `IMPLEMENTATION_STATUS.md:23-31`; treating them as current capability is **FALSE**.
