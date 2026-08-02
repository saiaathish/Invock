# Commercialization hypotheses

## Target buyer and value

- **Developer buyer/champion:** MCP/platform developer integrating the local reference monitor (`README.md`; `src/cli.ts`).
- **Security buyer:** reviewer accountable for explicit policy decisions, approvals, registry drift, and receipt evidence (`IMPLEMENTATION_STATUS.md:10-16`).
- **Economic buyer:** NOT PROVEN; hypothesize platform-security or developer-infrastructure leadership, then validate budget ownership.
- **Value hypothesis:** reduce unreviewed tool-call risk and review effort by making authorization decisions deterministic, explicit, and auditable. No financial value or customer outcome is proven.

## Value metric hypothesis

Primary candidate: **in-scope MCP tool calls mediated with reviewable outcomes**, segmented by forwarded, blocked, approval-required, and quarantined calls. Secondary candidates are reviewer minutes per decision, time to integrate one workflow, and receipt-chain verification rate. These are measurement proposals, not results.

## Packaging hypothesis

1. **Open core:** local mediation engine, protocol boundary, policy evaluation, demos, receipt verification, and CLI workflows evidenced in this repository.
2. **Commercial layer hypothesis:** operational support, managed fleet visibility, enterprise identity/retention/integration controls, and governance workflows.
3. **Boundary:** do not imply that roadmap items are commercial today. GET/SSE lifecycle, DNS/redirect enforcement, OS/container sandboxing, external transparency anchoring, SBOM/provenance, and broad performance/fuzz matrices are explicitly unsupported or roadmap (`SECURITY.md:10-17`; `IMPLEMENTATION_STATUS.md:23-31`).

No pricing, customer, conversion, SLA, or willingness-to-pay claim is proven; inventing one would be **FALSE**.

## Validation required

Run design-partner pilots with synthetic data and supported transports. Validate: buyer role and budget path; repeatable setup; measurable review-time or risk outcome; acceptable local key/database operations; transport fit; willingness to continue; and which commercial controls are actually required. Capture evidence in partner feedback, not in assumptions.

## 12-month roadmap hypothesis

| Period | Focus | Exit evidence |
|---|---|---|
| Months 0–3 | Supported-boundary pilots, onboarding, baseline metrics | Executed pilot records and reproducible receipts |
| Months 4–6 | Package the stable local wedge; improve policy/registry review workflows | Repeatable setup and documented retention/operations model |
| Months 7–9 | Validate commercial operational requirements; assess supported HTTP deployment gaps | Buyer and security review evidence; explicit gap decisions |
| Months 10–12 | Decide whether to productize managed governance and roadmap controls | Paid-design or equivalent willingness-to-pay evidence; no fabricated forecast |

This roadmap is a hypothesis, not a committed delivery schedule.
