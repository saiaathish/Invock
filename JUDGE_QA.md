# Invock judge Q&A

Answers below use `IMPLEMENTED`, `PLANNED`, `NOT PROVEN`, and `FALSE` labels so a presenter can answer hostile questions without inflating the evidence.

## Architecture

**Q: What is Invock?**<br>
**A:** `IMPLEMENTED`: a local reference monitor for visible MCP tool invocations. It normalizes a request, evaluates policy and optional effective authority, persists a redacted decision/receipt, and returns allow, approval-required, or block. The central gateway is `InvocationGate` in `src/gateway/engine.ts`.

**Q: Where does it sit?**<br>
**A:** `IMPLEMENTED`: at the supported stdio and Streamable HTTP mediation boundaries. It is not an agent runtime and does not inspect arbitrary hidden code inside an upstream server.

**Q: What is the authority model?**<br>
**A:** `IMPLEMENTED`: an intent capsule is proposed then explicitly activated; capability leases can delegate only a monotonic subset; evaluation checks tool, capability, effect, resource, data-label, expiry, revocation, delegation depth, and budgets. The result includes reason codes and an effective digest.

**Q: What data reaches the report?**<br>
**A:** `IMPLEMENTED`: `buildReportViewModel` projects invocation ID, tool name, verdict, status, timestamp, and receipt ID. The UI tests prove arbitrary arguments and secret-like payloads are absent from the report view.

## Novelty

**Q: What is novel here?**<br>
**A:** The product thesis is the combination of visible-action mediation, monotonic authority, exact one-time approvals, and redacted cryptographic evidence in one local gate. The novelty claim is a product position, not a published comparative benchmark; no claim of industry-wide uniqueness is proven.

**Q: Is this just an allowlist?**<br>
**A:** No. `IMPLEMENTED`: policy produces ALLOW, BLOCK, or APPROVAL_REQUIRED; normalization classifies arguments and resources; authority can narrow policy; approvals bind to the exact invocation; receipts and activity preserve evidence. The scope remains visible MCP actions.

## Threat model

**Q: Does it stop a malicious upstream tool server?**<br>
**A:** No. `IMPLEMENTED boundary`: it governs the request visible before forwarding. `FALSE` claim: “Invock proves the upstream server is honest.” The README explicitly disclaims that guarantee.

**Q: Can I show a real secret or public exfiltration target?**<br>
**A:** No. `IMPLEMENTED safety rule`: use fake values such as `FAKE_SECRET_123` and loopback sinks only. Public exfiltration and real credentials are outside the demo and prohibited by `SECURITY.md`.

**Q: Does approval make an action safe?**<br>
**A:** No. `IMPLEMENTED`: approval authorizes one exact bound action and is consumed once; it is not a semantic safety guarantee. Mutation, replay, expiry, session, and protocol changes must remain denied.

**Q: What happens on malformed or expired authority?**<br>
**A:** `IMPLEMENTED`: evaluation returns `allowed: false` with reason codes such as `MALFORMED_CAPSULE`, `CAPSULE_EXPIRED`, `NO_LEASE`, or `DELEGATION_DEPTH_EXCEEDED`. The intended posture is fail closed.

## Limits

**Q: Is it production-ready?**<br>
**A:** `NOT PROVEN` as a production claim. Current evidence is local build/test/demo/API evidence. Production key custody, external receipt anchoring, broad deployment coverage, and independent performance evidence are not established by this handoff.

**Q: Does the dashboard prove accessibility?**<br>
**A:** Only within a narrow scope. `IMPLEMENTED` evidence: the real Chromium runner passes keyboard focus, contrast, responsive rendering, live status, reduced motion, and authenticated interaction. `NOT PROVEN`: full WCAG conformance, screen-reader behavior, and assistive-technology coverage.

**Q: Does `pnpm demo:safe` prove a real upstream call?**<br>
**A:** No. `FALSE`: it is an in-memory gate call and prints “Would forward to upstream server.” It proves an ALLOW decision only. The stronger real-fixture story is roadmap unless a local fixture is added and executed.

**Q: Does `pnpm demo:attack` prove zero exfiltration?**<br>
**A:** No. `FALSE` as a general claim. The current command proves a protected-path BLOCK with `PATH_PROTECTED` and a receipt ID. The separate `pnpm judge:certify` fake-only flow reports zero sink deliveries for its blocked attack; that remains local boundary evidence, not a production exfiltration guarantee.

## Benchmarks

**Q: What is the latency or throughput?**<br>
**A:** `IMPLEMENTED` as a local measurement only: `pnpm arena` runs 18 scenarios × 3 repetitions across protected, unprotected, and static-allowlist paths and reports p95/p99, throughput, and dispersion. These are host measurements, not production throughput or SLO evidence.

**Q: What is the baseline?**<br>
**A:** `IMPLEMENTED` in Arena: the same scenarios run through unprotected and static-allowlist adapters, with raw outcomes, sink counts, and measured timing. It is a local comparison, not an independent production study.

## Integrations

**Q: Which interfaces exist now?**<br>
**A:** `IMPLEMENTED`: CLI commands include init, scan, supply-chain scan, policy learn/diff/simulate/activate/rollback, doctor, receipt verification/export, serve, judge, safe/attack demos, forge, guard, and contain. The API includes authenticated activity, approvals, tools, expansions, policies, receipts, receipt lookup, approve, and reject routes in source. The current dashboard renders only token entry, activity, and approvals.

**Q: Can I integrate with an arbitrary MCP server?**<br>
**A:** Only within the supported mediation profiles and with the actual transport/session behavior verified. `NOT PROVEN`: arbitrary production compatibility. Unsupported lifecycle or transport claims must be called out rather than inferred from a type or route.

**Q: What do Forge, Guard, and Contain mean?**<br>
**A:** `IMPLEMENTED` as local contracts/tests: Forge creates a deterministic policy draft from supplied observations and requires explicit human approval to activate; Guard statically inspects workflow text; Contain reports `unsupported` when a required OS sandbox is unavailable. None is a claim of GitHub integration, production isolation, or network access.

## Commercialization

**Q: Who would buy this?**<br>
**A:** A plausible buyer is a team deploying tool-using agents that needs a reviewable control point for high-impact visible actions. That is a market hypothesis, not customer evidence. Pricing, adoption, retention, and willingness-to-pay are `NOT PROVEN` in this repository.

**Q: What is the product wedge?**<br>
**A:** Start with local, auditable MCP invocation control: exact approvals, authority narrowing, and redacted evidence. Then earn broader deployment claims only through transport, key custody, accessibility, performance, and operational evidence. This is a roadmap strategy, not a revenue claim.

## Hostile questions

**Q: Your documents say “accessible.” Did you test it?**<br>
**A:** Not yet. `NOT PROVEN`. The requirement is defined as an acceptance gate, and the current page must pass actual keyboard, focus, contrast, semantics, responsive, and reduced-motion checks before that word is used as a result.

**Q: Your old certification says PASS. Why should I trust it?**<br>
**A:** Trust the command and scope, not the banner. The current verification run independently executed `pnpm build` and `pnpm test` with 283 passing tests, plus bounded CLI/API probes and local judge/Arena checks. Older reports contain claims that conflict with current source or have narrower test scope; those contradictions are `FALSE` for broad claims and are not repeated here.

**Q: Can a compromised client bypass Invock?**<br>
**A:** The product only controls requests that actually traverse its supported mediation boundary. A client that routes around the monitor is outside this proof. Deployment must therefore make the monitor the enforced path; that deployment property is `NOT PROVEN` by this local repository alone.

**Q: Can an attacker tamper with the database and receipts?**<br>
**A:** `IMPLEMENTED` tests cover receipt signatures and persisted chain checks in the current suite. `NOT PROVEN` as an external tamper-evidence or production key-custody claim: external anchoring and production key management remain roadmap items.

**Q: Why not hide the limitations during a five-minute pitch?**<br>
**A:** Because the product is an authority-and-evidence system. A truthful boundary is part of the demonstration: current, planned, not proven, and contradicted claims are deliberately separated so a judge can reproduce the result.

## Evidence index

Current executable evidence for this handoff:

- `pnpm build`: exit 0.
- `pnpm test`: 283 passed, 0 failed, 0 skipped.
- `pnpm invock --help`: printed the current lifecycle, policy, judge, supply-chain, and containment commands and exited 0.
- `pnpm arena`: 18 scenarios × 3 repetitions; protected attack block rate 100% (51/51), benign completion 100% (3/3), cleanup completed.
- `pnpm demo:safe`: ALLOW / “Would forward to upstream server”.
- `pnpm demo:attack`: BLOCK / `PATH_PROTECTED` / run-specific receipt ID.
- `git status --short`: clean before adding these three new files.

No screenshot, fake user, public sink, real secret, production benchmark, or browser accessibility PASS is claimed here.
