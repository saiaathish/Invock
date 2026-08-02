# Invock: an execution trust layer for autonomous AI systems

## Abstract

Invock explores a deterministic reference monitor that intersects policy, human-activated intent, delegated capabilities, schema-derived effects, data lineage, and containment before forwarding agent tool calls. It emits signed receipts for observed decisions. The current repository demonstrates a local MCP slice; it does not claim a completed research evaluation or production security proof.

## 1. Motivation

Tool-use agents can turn untrusted content into filesystem, network, process, or communication side effects. Static allowlists alone do not express session taint, one-time approvals, or delegated authority budgets.

## 2. Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md). The monitor treats agent requests, tool descriptors, upstream servers, and workflow configuration as potentially untrusted inputs.

## 3. Related work

Prior-art positioning and non-novel claims are recorded in [PRIOR_ART_REVIEW.md](PRIOR_ART_REVIEW.md). Invock's contribution is a product-level composition and evidence model, not a claim of formal academic novelty.

## 4. System model

The intended authority relation is `Policy ∩ Intent ∩ Lease ∩ Identity ∩ Schema ∩ Lineage ∩ Containment`. Each additional layer may only narrow authority.

## 5. Authority calculus

The executable subset and unresolved properties are documented in [AUTHORITY_CALCULUS.md](AUTHORITY_CALCULUS.md). Explicit unknown capability/effect values fail closed in the current implementation.

## 6. Architecture

See [EXPANDED_ARCHITECTURE.md](EXPANDED_ARCHITECTURE.md). The canonical gate is shared by stdio, Streamable HTTP, and the local SDK API handler.

## 7. Implementation

The implementation uses TypeScript, SQLite, Ed25519 receipts, keyed lineage fingerprints, local JSON control-plane state, and bounded containment runners.

## 8. Evaluation methodology

The current Arena runner uses a fixed seed and three repetitions for 18 local scenarios across protected, unprotected, and static-allowlist paths. This is a reproducible local benchmark, not production throughput or an independently reviewed research claim.

## 9. Benchmark scenarios

Current measured scenarios cover prompt injection, exfiltration and encoding, path/command/SQL/SSRF abuse, approvals, protocol and tool poisoning, schema drift, delegation, cross-session leakage, malicious local servers, receipt tampering, identity misuse, policy regression, and a benign workflow. The full raw research bundle and independent external comparison remain unproven.

## 10. Baselines

The current baseline callback is intentionally local and simple. No production baseline or external framework comparison has been run.

## 11. Security results

The latest repository suite reports 322 passing tests. Focused tests cover normalization, approvals, lineage encodings and detached lineage evidence, authority lifecycle and binding, identity evidence, API authentication, property/fuzz/chaos behavior, signed supply-chain evidence, and containment fail-closed behavior including gate-bound run linkage.

## 12. Benign utility

The local Arena run measured 3/3 protected benign completions and a 0/3 protected false-positive rate for its bounded `benign-workflow` fixture. This is a local scenario result, not a broad false-positive estimate across real workloads.

## 13. Performance

`pnpm arena` reports local protected/baseline latency statistics. They are host measurements and must not be interpreted as production throughput or SLO evidence.

## 14. Ablation study

Required ablations—removing intent, leases, lineage, containment, schema quarantine, and approval binding—are specified but not all executed. Results are NOT PROVEN.

## 15. Failure analysis

Known limits include upstream honesty, DNS rebinding, arbitrary semantic secret transformations, incomplete browser accessibility testing, and unavailable containment runtimes.

## 16. Limitations

No hardware attestation, hosted enterprise control plane, customer validation, or formal verification claim is made.

## 17. Ethics and responsible disclosure

Use fake credentials and local sinks. Report security findings privately to the repository owner before public disclosure. Do not test public exfiltration targets.

## 18. Reproducibility

Use `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm test`, `pnpm build`, `pnpm demo:certify`, and `pnpm arena`. Record the exact revision, environment, seed, and runtime availability.

## 19. Conclusion

Invock is a production-shaped local reference monitor and evidence substrate. Its broader product thesis remains a research and engineering program rather than a fully proven production system.

## 20. Status

This document is a transparent system paper draft. It is not peer-reviewed and contains no fabricated confidence intervals, customer evidence, or significance claims.
