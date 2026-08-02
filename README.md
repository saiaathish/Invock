# Invock

Invock is a deterministic execution-trust layer for AI agents: it evaluates tool calls against policy, intent, delegated capabilities, data lineage, and containment before any supported side effect is forwarded.

## Thirty-second architecture

```text
Agent / SDK / MCP transport
        -> canonical ActionEnvelope
        -> InvocationGate
           policy ∩ intent capsule ∩ lease chain ∩ session/identity context
           ∩ schema/lineage/containment constraints
        -> ALLOW | BLOCK | APPROVAL_REQUIRED
        -> signed receipt chain and redacted evidence bundle
```

The deterministic gate—not an LLM—returns the authorization verdict. LLMs may propose intent or policy, but they cannot authorize an action.

## Try it locally

Requirements: Node `>=22.5.0` and pnpm `11.15.1`.

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm demo:certify
pnpm invock serve --database .invock/judge.sqlite --key-directory .invock/judge-keys
```

The server binds to loopback, prints a short-lived bearer token, exposes a redacted dashboard, and provides non-executing `POST /api/v1/authorize`. Server-owned contained execution is a separate `POST /api/v1/execute` contract and requires trusted containment signer/profile configuration. Use only fake secrets and local fixtures.

## Verified local evidence

The latest local run on 2026-08-01 produced:

- `pnpm test`: 322 passed, 0 failed, 0 skipped on the current worktree.
- `pnpm arena`: 18 deterministic scenarios × 3 repetitions × protected/unprotected/static paths.
- `pnpm judge:certify`: local fake-data judge flow passed with containment/browser evidence explicitly reported as unavailable.
- `pnpm typecheck` and `pnpm build`: passed.
- `pnpm certify`: passed its explicitly executed local phases, including a bounded high-confidence scan of 173 files with zero findings.
- `node --import tsx scripts/final-certify.ts`: runs the bounded release phases and reports `NOT READY` while independent-audit, external provenance, advisory, and broad accessibility gates remain open; local digest-pinned containment and signed local supply-chain evidence are checked directly.
- A bounded live CLI/API probe returned `ALLOW` for a project read and accepted a fully supplied active Intent Capsule plus Capability Lease chain.

These are local-slice results, not a production-readiness or full mandate certification. Product Docker runtime execution, broad assistive-technology accessibility, clean-install rehearsals, and independent release gates remain separately evidenced or unproven.

## Integrations

- MCP newline-delimited stdio and authenticated Streamable HTTP POST mediation.
- TypeScript and dependency-free Python clients for the local authorization API.
- OpenAI-shaped and secondary-framework adapters that authorize before invoking a caller-supplied executor and pass only the gate's canonical arguments after `ALLOW`. Official framework package hooks remain caller-owned.
- Local Policy Forge, Policy Diff, Invock Guard, Arena, signed receipts, and redacted evidence exports.

## Security boundary

Invock mediates tool calls visible at its supported boundary and fails closed on malformed arguments, unknown normalizer metadata, protected paths, approval replay, schema drift, explicit unknown authority values, mismatched intent bindings, and unavailable required containment. Software workload identity uses local Ed25519 keys; it is not hardware attestation. Local supply-chain reports can include a verifiable Ed25519 signature over the evidence inventory with `pnpm supply-chain -- --sign`; this is local evidence, not external CI/registry provenance or a malicious-package verdict.

The supported boundary does not claim DNS-rebinding resistance, arbitrary semantic secret-transformation detection, upstream honesty after an allowed request, hosted enterprise control plane, SSO/SCIM, or production deployment proof. See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [FINAL_PRODUCT_CERTIFICATION.md](FINAL_PRODUCT_CERTIFICATION.md).
