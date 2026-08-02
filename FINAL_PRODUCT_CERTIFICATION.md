# Final product certification

## Scope

This artifact defines the executable, honest certification boundary for the local-first Invock slice. It does not certify the broader transformation mandate, hosted enterprise features, or integrations that are absent from this repository.

Run:

```bash
node --import tsx scripts/final-certify.ts
```

The script executes toolchain and frozen-install checks, typecheck, lint, the full suite plus focused partitions, build, accessibility, containment, Arena, guard, supply-chain/SBOM/advisory, mutation, demo, base certification, release rehearsal, CLI/evidence lifecycle, documentation/claim consistency, audit, process, container, and artifact cleanup phases. It reports phase results from child-process exit codes and output assertions. Any failed phase produces a nonzero exit code. It does not use a hardcoded PASS, swallow errors, or turn unsupported integrations into passing claims.

## Latest verification snapshot

On 2026-08-02, the current local verification wave recorded 291/291 tests with zero failures or skips; typecheck, lint, build, focused partitions, browser accessibility checks, mutation review, demo certification, double release rehearsal, CLI lifecycle, evidence export, and the local production-dependency advisory scan passed. The scoped browser runner exercised Chromium, keyboard focus, contrast, responsive rendering, live status, reduced motion, and authenticated dashboard interaction; broader WCAG and assistive-technology coverage remains `NOT_PROVEN`. The digest-pinned Docker certification passed three sequential local runs through both its direct probe and the product `runContained` path; `pnpm supply-chain -- --sign` verified the local Ed25519 evidence signature. Receipt-key history, SQLite startup integrity, detached lineage linkage, and explicit gate-bound containment evidence now have focused local coverage, but ordinary adapter forwarding is still not gateway-wide containment and detached transform recomputation remains unproven. The five current post-fix audit reports were completed and reconciled, but their findings do not all pass. A subsequent `node --import tsx scripts/final-certify.ts` run returned exit 1 with `External release provenance: NOT_PROVEN`, `Independent audits: FAIL`, and `VERDICT: NOT READY`; all other executed local phases passed. Production deployment remains unproven.

`pnpm expanded-certify` has a bounded local pass for its full-suite, build, double-certification, Docker attack-probe, Arena, and mutation phases. The latest final certification reports both local and digest-pinned Docker containment as `PASS`; this remains local runtime evidence and does not prove external deployment or fleet-wide enforcement.

**Current product-transformation verdict: NOT READY.**

## Current independent-audit reconciliation

The five current read-only reports under `.artifacts/independent-audits/` cover authorization, protocols/SDKs, containment/lineage, persistence/cryptography/supply chain, and product/UX/benchmark/documentation. They are evidence for the dirty worktree at HEAD `58ce434a569f64444512aa98a217c66b2258d8b6`, not proof of a clean release.

| Audit | Current disposition | Open boundary |
|---|---|---|
| Authorization | `PASS` for the supported local boundary | Production or universal authorization, external identity/attestation, concurrent fleet enforcement, and remote receipt verification remain `NOT_PROVEN`. |
| Protocols and SDKs | `PASS` for supported local paths; `DONE_WITH_CONCERNS` overall | Automatic framework hooks, focused Python runtime integration, hosted deployment, and production-scale isolation remain `NOT_PROVEN`. |
| Containment and lineage | `PARTIAL` / `DONE_WITH_CONCERNS` | Explicit containment-to-receipt/evidence attachment and detached linkage checks are locally implemented and tested; mandatory gateway-wide adapter containment, independent transform recomputation, resource telemetry, and production/fleet enforcement remain `NOT_PROVEN`; the gateway-wide P1 remains open. |
| Persistence, cryptography, and supply chain | `NOT PROVEN READY` / `DONE_WITH_CONCERNS` | Receipt-key history, SQLite startup integrity, and resolved lockfile package inventory are locally evidenced; crash-safe rotation, full dependency-edge/advisory semantics, trusted external provenance, and clean release attribution remain `NOT_PROVEN`. |
| Product, UX, benchmark, and documentation | `NOT READY` | No P0 or confirmed P1 was found, but stale historical artifacts and evidence-promotion risk remain P2 claim-hygiene concerns. |

The reports close the prior missing-artifact question but do not close the readiness gate. `final-certify` correctly treats the non-PASS audit dispositions as `Independent audits: FAIL`; this is why the overall result remains `NOT READY` even though the executable local phases pass.

## Certified local surfaces

- Validated, project-owned control-plane state persisted through atomic JSON replacement.
- Redacted JSON, NDJSON, and Markdown evidence projections.
- Public receipt verification material without private signing keys or raw arguments.
- CLI help, initialization, local scan, policy draft/simulation/approval flow, lifecycle aliases, and evidence export.
- Existing Invock authorization, receipt, API, protocol, guard, forge, and containment tests remain in the full suite.

## Explicitly not certified

The following remain unsupported or unproven and are not represented as PASS: enterprise/cloud control-plane deployment, SSO/SCIM, remote anchoring, framework-wide interception beyond the local OpenAI-shaped and secondary adapters, production containment beyond the existing fail-closed boundary, clean-install certification, an all-PASS independent audit wave, full Arena research results, and broad WCAG/assistive-technology accessibility certification beyond the scoped browser runner.

## Verdict rule

The command may report a passing local slice only when every executed phase passes. A passing local slice is not a `READY` claim for the full product-transformation mandate. Any broader readiness statement requires separate implementation and direct evidence for each mandatory gate.
