# Jobs to be done

All customer language below is a **Product hypothesis** unless marked otherwise. No customer interviews or external market research are present; such validation is **NOT PROVEN**.

## Job 1 — put a reviewable gate in front of a tool call

- **When:** an MCP client is about to invoke a tool.
- **I want:** the call normalized and evaluated against policy before forwarding.
- **So I can:** block unsafe calls, request a one-time approval, or forward canonical arguments.
- **Repository evidence:** `src/gateway/engine.ts:62-138` describes the non-bypassable `tools/call` gate; `src/core/normalize.ts:241-242` records canonical envelope data.
- **Outcome to test:** safe fixture traffic forwards; denied traffic does not; approval is exact, expires, and cannot replay (`IMPLEMENTATION_STATUS.md:12-13`).

## Job 2 — explain a decision after the fact

- **When:** a reviewer asks what happened.
- **I want:** a receipt, decision, status, and chain-verification result.
- **So I can:** investigate without reading sensitive payloads or guessing.
- **Repository evidence:** `src/storage/store.ts:199-230`; `src/ui/report.ts`; CLI `receipts verify` in `src/cli.ts:18-20,48`.
- **Outcome to test:** a pilot can locate the receipt ID and verify a valid chain; tampering causes verification failure.

## Job 3 — handle change without silently widening authority

- **When:** an upstream tool schema changes.
- **I want:** the registry to detect drift and quarantine the tool until reviewed.
- **So I can:** avoid carrying forward stale approvals.
- **Repository evidence:** `IMPLEMENTATION_STATUS.md:12`; `src/registry/registry.ts:55-95`; `src/storage/store.ts:237`.
- **Outcome to test:** changed schema yields quarantine and approval invalidation.

## Job 4 — start with evidence, then propose policy

- **When:** an integration has observed calls but no trusted policy draft.
- **I want:** a draft from observations and an explicit human activation step.
- **So I can:** review proposed authority before activation.
- **Repository evidence:** `src/cli.ts:22,52`; `src/forge/index.ts:69-106` requires attributable human approval for activation.
- **Outcome to test:** generated draft remains a draft until an approval record is supplied.

## Jobs explicitly outside the current supported boundary

Complete GET/SSE lifecycle, DNS/redirect enforcement, OS/container sandboxing, arbitrary semantic secret-transformation detection, and proof of honest upstream behavior are **NOT PROVEN** and are explicitly not supported (`SECURITY.md:10-17`).
