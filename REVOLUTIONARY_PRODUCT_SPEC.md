# Invock product specification: authority before action

## Thesis

Invock is a local reference monitor for visible MCP tool invocations. Its product promise is narrow and testable: before a visible action reaches an upstream tool, Invock normalizes the request, applies policy and effective authority, records a redacted decision, and either allows, requires an exact one-time approval, or blocks. The judge should understand the decision and its evidence without seeing a secret or trusting a marketing claim.

Claim labels used in this document:

- `IMPLEMENTED`: observed in the repository and backed by executed evidence in the handoff.
- `PLANNED`: product design only; not a current capability.
- `NOT PROVEN`: a claim that needs a specific future test or live inspection.
- `FALSE`: contradicted by repository evidence and must not be presented as true.

## Authority pipeline

The intended five-minute mental model is:

```text
visible MCP request
  -> canonical normalization and argument/resource classification
  -> static policy decision
  -> active intent capsule + monotonic lease evaluation
  -> taint / protected-resource / approval checks
  -> redacted receipt and activity record
  -> ALLOW, APPROVAL_REQUIRED, or BLOCK
  -> forward only when the gate returns a forward outcome
```

`IMPLEMENTED`: the gateway exposes `InvocationGate.authorizeInvocation`, policy evaluation, authority evaluation, approval binding, receipt metadata, and forward/respond outcomes. Capsules start `PROPOSED`, activate explicitly, and leases narrow authority; malformed, expired, revoked, out-of-budget, or out-of-scope authority fails closed. The authority tests and gateway tests cover these behaviors.

`IMPLEMENTED`: the local API is loopback by default, bearer-authenticates protected routes, validates Host and Origin, rate-limits authenticated requests, and exposes activity, approvals, tools, expansions, policies, receipts, and receipt lookup routes in `src/api/server.ts`. The dashboard currently renders token entry, activity, and approvals from real API data.

`IMPLEMENTED` bounded browser evidence: the served dashboard is exercised through Chromium for focus, contrast, keyboard interaction, responsive rendering, live status, reduced-motion handling, and authenticated state changes. `NOT PROVEN`: full WCAG conformance, screen-reader behavior, and assistive-technology coverage.

## Product pillars

1. **Visible-action authority**. A request is judged at the mediation boundary, with tool, capabilities, effects, resources, labels, budgets, session, and protocol context. Hidden behavior after an allowed request is outside this product boundary.
2. **Monotonic delegation**. A child lease can only narrow its parent. The capsule/lease digests and effective digest make the authority decision inspectable.
3. **Human approval as a bound operation**. Approval is bound to the exact invocation context and consumed once. Mutation and replay must remain denied.
4. **Evidence without exposure**. Report views project only invocation ID, tool, verdict, status, time, and receipt ID. Raw arguments, payloads, and secret-like values do not belong in the judge view.
5. **Fail-closed limits**. Unsupported transport lifecycle, unavailable containment, malformed policy/authority, and unverified claims are visible as limits, not silently converted into success.

## Supported boundary

`IMPLEMENTED`: newline-delimited JSON-RPC/MCP stdio mediation and authenticated loopback-by-default Streamable HTTP mediation for the implemented profiles exist in code and tests. The CLI currently provides `init`, `scan`, `supply-chain scan`, policy learn/diff/simulate/activate/rollback, `doctor`, receipt verification/export, `serve`, `serve --stdio`, `judge`, `demo safe|attack`, `forge`, `guard`, and `contain`.

`IMPLEMENTED`: the repository documents fake data and loopback sinks for demonstrations and forbids real secrets or public exfiltration targets.

`NOT PROVEN` or explicitly out of boundary: a production-grade upstream honesty guarantee, external receipt anchoring, production key management, broad performance claims, and full WCAG/assistive-technology accessibility certification. The current repository also contains older reports whose claims conflict with current evidence; those reports are not authority for this product spec.

## Integration order

The judge-facing product should be integrated in this order:

1. **Existing local proof** (`IMPLEMENTED`): run `pnpm build`, `pnpm test`, `pnpm demo:safe`, and `pnpm demo:attack`.
2. **Current dashboard proof** (`IMPLEMENTED` surface and scoped browser evidence, `NOT PROVEN` full UX conformance): start `pnpm invock serve` with a disposable local database, open the printed loopback URL, and use the printed token. Inspect only redacted activity, approvals, and receipts.
3. **Authority story** (`IMPLEMENTED` library/test capability): show proposal -> activation -> lease narrowing -> evaluation -> receipt metadata using existing tests or a future documented fixture. Do not imply the dashboard already has capsule editing or lease visualization.
4. **Local attack fixture** (`IMPLEMENTED`): `pnpm judge:certify` uses fake-only local fixtures and a loopback sink; the blocked protected-path attack records zero sink deliveries and signed evidence. This remains a mediation-boundary demonstration, not a production exfiltration guarantee.
5. **Accessibility and evidence gate** (`PARTIAL`): the scoped Chromium runner executes keyboard, focus, contrast, reduced-motion, responsive, and dashboard interaction checks; full WCAG and screen-reader checks still require separate evidence.

## UX states and data contracts

| UX state | User-visible content | Real data source now | Status |
|---|---|---|---|
| Start / orientation | “Visible action -> policy -> authority -> evidence” and boundary note | README and CLI usage text | `PLANNED` presentation |
| CLI safe proof | ALLOW and “Would forward to upstream server” | `src/cli.ts demo safe` | `IMPLEMENTED` |
| CLI blocked proof | BLOCK, `PATH_PROTECTED`, receipt ID | `src/cli.ts demo attack` | `IMPLEMENTED` |
| Dashboard token gate | Local URL, password input, Load action | `startApi` token and inline dashboard | `IMPLEMENTED` surface; scoped browser accessibility PASS, broad WCAG `NOT PROVEN` |
| Activity | time, tool, verdict, status, receipt | `GET /api/v1/activity` -> `buildReportViewModel` | `IMPLEMENTED` |
| Approvals | approval ID, status, binding digest | `GET /api/v1/approvals` | `IMPLEMENTED` read surface |
| Tools / expansions / policies | registry, expansion records, startup policy status | authenticated API routes | `IMPLEMENTED` API; no current dashboard rendering |
| Receipt detail / chain | receipt or chain status | authenticated receipt routes and `receipts verify` | `IMPLEMENTED` API/CLI; dashboard rendering `PLANNED` |
| Attack blocked before sink | sink count remains zero and reason is shown | `pnpm judge:certify` fake-only flow plus Arena protected path | `IMPLEMENTED` locally; production guarantee `NOT PROVEN` |
| Approval required -> approve -> replay denied | exact binding, one-time consumption, replay result | engine/store tests | `IMPLEMENTED` engine/test; single end-to-end judge presentation `NOT PROVEN` |
| Unsupported capability | explicit unsupported/NOT PROVEN banner | README and containment result type | `PLANNED` presentation |

The UI must never invent users, invocations, latency, sink counts, screenshots, or performance numbers. If a field is absent from the API or test output, render “not available” or omit it.

## Accessibility and interaction acceptance gates

The current inline dashboard is not accepted as judge-ready until the following are executed on the runnable page:

- Keyboard-only: token input, Load button, activity table, and approval content are reachable in logical order; no keyboard trap.
- Focus: every interactive control has a visible focus indicator and focus remains understandable after Load.
- Semantics: one page title, real labels for the token field, table headers associated with cells, status/verdict text not conveyed by color alone, and useful empty/error states.
- Contrast: normal text, small text, borders, focus indicators, and all verdict states meet the selected WCAG AA threshold; record the tool and result.
- Motion: no required animation; `prefers-reduced-motion` is honored if motion is later added.
- Responsive: 320px-wide keyboard and touch review; tables remain readable without hidden critical data.
- Security UX: token is password-type, never written into report content, and all demo data is fake/local.

These are acceptance gates, not claims that the current page passes them.

## Acceptance gates

The product spec is complete only when each gate has an artifact:

1. `IMPLEMENTED`: build and full tests pass on the exact revision.
2. `IMPLEMENTED`: safe and protected-path attack CLI outputs are captured without secrets.
3. `IMPLEMENTED`: API auth/Host behavior and redacted report tests pass.
4. `PARTIAL`: judge mode demonstrates safe/blocked fake actions, zero sink delivery, signed evidence, and cleanup; approval mutation/replay is covered by engine/store tests rather than one end-to-end presentation artifact.
5. `PARTIAL`: scoped browser accessibility and responsive checks pass on the actual dashboard; broad WCAG and assistive-technology certification remains open.
6. `PLANNED`: any benchmark reports measured runs, hardware/runtime, sample size, baseline, and variance. No target number is promised here.
7. `PLANNED`: every judge slide/statement links to code, test, command output, or is labeled roadmap/NOT PROVEN.

## Roadmap

- **Now**: local CLI proof, fail-closed authority primitives, authenticated redacted API/dashboard, receipt and approval evidence.
- **Next**: broaden accessibility evidence to WCAG/assistive technology, add receipt-detail presentation, and create a single judge narrative that combines approval/replay with the existing fake-data flow.
- **Then**: dashboard views for receipt detail, authority scope, explicit approval action, and unsupported-boundary states, each with accessibility tests.
- **Later**: external receipt anchoring, production key storage, broader transport/session coverage, verified containment across supported hosts, and measured performance/fuzz/property matrices.

The roadmap does not promote any later item to current capability.
