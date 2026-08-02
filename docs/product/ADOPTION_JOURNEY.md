# Adoption journey

This is a **Product hypothesis**, not a validated funnel. No customer or conversion evidence exists in the repository.

| Stage | User action | Current repository evidence | Gate to advance | Likely blocker |
|---|---|---|---|---|
| Discover | Read the boundary and run a safe demo | `README.md`; `src/cli.ts:21-22`; `package.json` demo scripts | User can state what is and is not mediated | Confusing roadmap vs current support |
| Instrument | Run `serve --stdio` around a local MCP command | `src/cli.ts:20,49`; `src/gateway/stdio.ts:30-37` | Safe fixture request reaches the gate | Process ownership, policy location, local SQLite/key directory |
| Prove | Exercise allow, block, and approval paths | `src/gateway/engine.ts:108-138`; `IMPLEMENTATION_STATUS.md:7-16` | Receipt IDs and decisions are reviewable | Tool descriptors and schemas may be incomplete |
| Review | Verify receipts and inspect activity/approvals | `src/cli.ts:18-20,47-50`; `src/api/server.ts` | Reviewer reproduces result without secret data | Dashboard is local and token-based; no enterprise console is evidenced |
| Expand | Add registry drift and policy-forge workflow | `src/registry/registry.ts`; `src/forge/index.ts`; `src/guard/index.ts` | Change causes explicit review/quarantine | Workflow ownership and human approval process |
| Renew | Quantify reduced review effort or prevented unsafe calls | NOT PROVEN | Pilot metric improves against a pre-agreed baseline | No customer baseline, pricing, SLA, or procurement evidence |

## Onboarding blockers to test

1. **Integration:** whether the target MCP client can be wrapped by a local stdio proxy.
2. **Policy:** whether the team can author descriptors and policy conditions for its real tools.
3. **Operations:** who owns the SQLite database and key directory, and how backups/rotation are handled.
4. **Boundary:** whether Streamable HTTP POST is sufficient; GET/SSE lifecycle is explicitly unsupported (`SECURITY.md:10-13`).
5. **Trust:** whether local signed receipts satisfy the reviewer; enterprise anchoring and SBOM/provenance are roadmap items (`IMPLEMENTATION_STATUS.md:29-31`).

## Adoption hypothesis

The wedge is a single high-risk MCP integration with a small set of representative tools, a local operator, and a security reviewer. This is a **Product hypothesis**; design-partner validation is required before claiming repeatability.
