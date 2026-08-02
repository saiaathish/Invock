# Threat model

## Scope

This is a source-grounded threat model for the current Invock tree at audit time. The protected operation is an MCP `tools/call` crossing Invock to an upstream tool server. The analysis covers `src/**`, `test/**`, `scripts/**`, `SECURITY.md`, `policies/default.yaml`, the checked-in workflow, and the current executable evidence from `pnpm test`, `pnpm build`, the focused security suite, targeted source inspections, and two read-only in-memory probes.

Invock is a reference monitor, not a proof that an upstream server is honest after an allowed request. `SECURITY.md:10-18` explicitly excludes complete upstream GET/SSE lifecycle mediation, DNS pinning and redirect-by-redirect destination enforcement, OS/container sandboxing, semantic paraphrase or arbitrary cryptographic secret-transformation detection, and upstream honesty. Those exclusions are modeled as trust-boundary limits, not silently treated as controls.

Architecture summary:

* Stdio input is framed and parsed by `src/gateway/stdio.ts:55-81`. Allowlisted control-plane messages are forwarded directly at `:62-69`; `tools/call` enters `InvocationGate.authorizeInvocation` at `:71-80`.
* HTTP `/mcp` authenticates host, origin, and bearer token at `src/mcp/http.ts:36-42`, then forwards control-plane messages at `:70-82` or routes `tools/call` through the same gate at `:84-105`. Optional GET/SSE creates a local session endpoint at `:43-50`; this is not a complete upstream GET/SSE session.
* The gate normalizes, evaluates policy and optional authority, records an interception, and returns `forward` only after those decisions at `src/gateway/engine.ts:63-140`. `finish`, `finishNotification`, and `fail` persist the result at `:145-154`.
* The upstream client performs configured HTTP/HTTPS requests, optional DNS pinning, redirect handling, size limits, and response correlation at `src/mcp/upstream.ts:197-239` and `:341-443`.
* The API server exposes unauthenticated health and dashboard HTML, bearer-protected activity, approvals, registry, expansion, and receipt routes, and approval state transitions at `src/api/server.ts:34-52`.
* Persistence writes SQLite invocation, approval, registry, taint, and receipt state, external key files, and a signed JSON chain head at `src/storage/store.ts:44-72`, `:81-137`, and `:199-222`.
* Containment is a local child-process runner. It denies selected commands and bounds argv/output/time, but it returns `unsupported` instead of claiming a required sandbox at `src/containment/runner.ts:30-45`; the actual spawn at `:57-84` has no OS network isolation.

## Assets

| Asset | Confidentiality / integrity / availability impact | Location or owner |
|---|---|---|
| Secrets, credentials, private keys, and tainted result data | C / I / A: disclosure or replay is high impact | Upstream results, in-memory envelopes, external key files, taint fingerprints |
| Authorized action boundary | I / A: an unauthorized side effect defeats the product | `InvocationGate`, policy, authority, normalizer, registry |
| Policy, intent capsule, lease chain, schema, and normalizer digests | I: changes can amplify privilege | `src/core/policy.ts`, `src/authority/**`, `src/registry/**` |
| Approval state and binding | I / A: replay or mutation can authorize a side effect | SQLite `approvals` and `invocations` tables |
| Receipt chain and chain head | I / A: audit evidence must not be forged or silently truncated | SQLite receipts plus external signed `chain-head.json` |
| Principal, session, protocol era, and request identity | I: cross-session or cross-client authority reuse | Normalization context and approval binding |
| Upstream transport destination and response correlation | C / I / A: SSRF, redirect leakage, confused responses | HTTP client and gateway |
| CI workflow and package supply chain | I / A: build-time code execution or artifact tampering | `.github/workflows/ci.yml`, `package.json`, `pnpm-lock.yaml` |

## Actors

| Actor | Capability and assumption |
|---|---|
| A1. Untrusted MCP caller | Can submit malformed JSON-RPC, tool arguments, notifications, duplicate IDs, approval IDs, and tainted values through a supported transport. Cannot directly edit local files. |
| A2. Malicious or compromised upstream server | Controls `tools/list` annotations, upstream responses, redirect responses, and child-process stdout. This is the highest-risk untrusted trust boundary because control-plane metadata can influence normalization. |
| A3. Local same-user process | May reach loopback ports or read process-visible state. It does not automatically possess the dashboard bearer token, but localhost is not a remote-user boundary. |
| A4. Policy or configuration operator | Can choose policies, upstream URL, redirect policy, normalizer descriptors, containment profile, key paths, and whether to enable remote API binding. Configuration is trusted input only after review. |
| A5. Filesystem or database tamperer | Can alter SQLite, key files, chain head, workflow, or package inputs if it has owner/root/repository write access. Receipt verification assumes keys and runtime are not already compromised. |
| A6. CI or dependency attacker | Can exploit mutable workflow action references, package lifecycle scripts, or a compromised dependency to execute in CI. |
| A7. Honest upstream tool | Returns well-formed protocol data and respects the request. Invock does not prove this behavior after forwarding. |

## Trust boundaries

1. **Caller -> transport parser.** JSON-RPC framing, size limits, method allowlists, request IDs, bearer token, host, and origin are checked. The HTTP token is a shared bearer secret, not per-principal authentication.
2. **Transport -> reference monitor.** Every recognized `tools/call` should pass through `authorizeInvocation`; control-plane methods are a separate direct-forwarding path. A notification has no response ID, so approval-required notifications are blocked by `NOTIFICATION_APPROVAL_UNSUPPORTED` in `src/gateway/engine.ts:105-109`.
3. **Upstream `tools/list` -> registry/normalizer.** The response supplies the `io.invock/normalizer` annotation consumed by `src/registry/registry.ts:97-108`, persisted by `:77-85`, and later used by the gate. This boundary is not authenticated or semantically validated.
4. **Raw arguments -> normalized action envelope.** `src/core/normalize.ts:220-245` validates schemas and modeled trees, resolves paths, classifies URLs, and infers capabilities/effects. An unrecognized field type is not rejected by the loop at `:227-234`; it produces no resource.
5. **Policy/authority -> forwarding port.** `src/gateway/engine.ts:85-117` is the reference-monitor decision point. The only returned `forward` path is the gate, but its inputs include the upstream-controlled registry descriptor.
6. **Gate -> upstream side effect.** Stdio writes to `child.stdin` at `src/gateway/stdio.ts:80`; HTTP calls `forward` at `src/mcp/http.ts:97`; configured upstream transport writes network requests at `src/mcp/upstream.ts:382-405`. Downstream upstream honesty is outside the monitor.
7. **Result -> lineage and persistence.** `src/gateway/engine.ts:145-151` stores keyed fingerprints for selected labels. Raw result text is not supposed to enter receipt payloads, but upstream output and report fields remain trust-boundary inputs.
8. **API caller -> control-plane state.** Bearer authentication gates state reads and approval transitions at `src/api/server.ts:36-51`; `/` and `/api/v1/health` are intentionally unauthenticated at `:34-35`.
9. **Process -> containment runner.** `runContained` spawns a fixture-resolved Node process at `src/containment/runner.ts`. Required sandbox requests fail closed; unenforced `sandbox: "none"` reports network `unknown` rather than claiming isolation.
10. **Repository -> CI.** `.github/workflows/ci.yml` pins its third-party actions by full commit SHA. The lockfile and workflow remain build-time trust boundaries, and dependency/SBOM evidence is still scoped separately.

## STRIDE table

| STRIDE | Attack surface | Current control and evidence | Residual risk / calibrated status |
|---|---|---|---|
| Spoofing | Shared HTTP/API bearer token; principal context; session IDs | Constant-time token comparisons and host checks at `src/mcp/http.ts:10,36-42` and `src/api/server.ts:15-18,31-38`; focused API test passed. | No per-caller identity or token rotation protocol is proven. A stolen token is bearer access. P1 conditional on token exposure, NOT PROVEN as an exploit here. |
| Tampering | Arguments, schemas, normalizers, policies, SQLite, keys, chain head | Canonical request forwarding and closed normalizer validation at `src/core/normalize.ts`; signed receipt verification at `src/storage/store.ts`; 290-test suite passed. | The earlier hostile-normalizer bypass is remediated for the tested metadata forms. Dynamic registry provenance and broader production evidence remain NOT PROVEN; bounded property/fuzz coverage is now present locally. |
| Repudiation | Invocation, approval, receipt, and chain state | Signed receipts and head checkpoint are implemented at `src/storage/receipts.ts:52-84` and `src/storage/store.ts:199-222`; focused receipt tests passed. | `src/core/canonical.ts:3-17` is a custom canonicalizer while receipts label it RFC8785-JCS at `src/storage/receipts.ts:35`. Full interoperability is NOT PROVEN. |
| Information disclosure | Secret paths, tainted output, URL/body forwarding, API receipt routes, child output | Protected path labels at `src/core/normalize.ts:131-149`; lineage HMACs at `src/core/lineage.ts:37-49`; documented exact/base64/urlencoded tests passed; report rendering is redacted by `src/ui/report.ts`. | Paraphrase/arbitrary crypto detection is not wired into the gate; DNS pinning is optional; upstream honesty is outside scope. P1/P2 conditional gaps. |
| Denial of service | Oversized frames/bodies, duplicate IDs, slow upstream, SSE sessions, child processes | 2 MiB frame/body bounds, timers, correlation cleanup, SSE idle/heartbeat, and process-group termination are present at `src/gateway/stdio.ts:6-12,79-101`, `src/mcp/http.ts:9-12,94-105`, and containment `:69-92`; tests passed. | Unauthenticated health/dashboard and shared bearer endpoints remain local availability surfaces. No sustained load test was run. P2/P3, NOT PROVEN under load. |
| Elevation of privilege | Upstream normalizer, authority `unknown`, policy defaults, approval replay, schema drift | Exact approval binding/consumption, registry quarantine, closed normalizer validation, and authority unknown-value tests passed. | The earlier normalizer and explicit-unknown findings are remediated in this tree. Identity/project trust, full property coverage, and upstream provenance remain bounded gaps. |

## Attack paths

### AP-1: Control-plane normalizer poisoning -> direct egress (resolved)

1. A compromised upstream returns a valid-looking `tools/list` with a tool schema for a URL argument and `annotations["io.invock/normalizer"].fields[0].type = "untrusted-runtime-type"`.
2. `PersistentToolRegistry.observeToolsList` accepts it because it requires only a record and a `fields` array (`src/registry/registry.ts:97-108`), then persists the record (`:77-85`).
3. The current normalizer performs closed-field-kind, pointer, access, method-pointer, declared-capability/effect, and no-argument-authority validation before normalization (`src/core/normalize.ts:14-35`).
4. `test/security-hardening.test.ts` exercises the poisoned-type path and asserts no forward outcome.

The earlier probe reproduced a forward outcome on the pre-hardening tree. It is retained here as historical evidence and is RESOLVED for the covered forms. Dynamic signed registry provenance, fuzz coverage, and all possible annotation shapes remain NOT PROVEN.

### AP-2: Explicit unknown authority -> allowed decision (resolved)

`src/authority/validation.ts` no longer admits `unknown` in the allow-list sets, and `evaluateMonotonicAuthority` explicitly rejects unknown capsule, lease, request capability, and effect values. `test/security-hardening.test.ts` exercises the authority path. The earlier allowed outcome is historical evidence from the pre-hardening tree and is RESOLVED for those values; broader unknown resource/protocol/property vectors remain NOT PROVEN.

### AP-3: Upstream destination confusion -> SSRF or redirected disclosure (P1)

`StreamableHttpUpstreamClient` accepts `http:` and `https:` URLs (`src/mcp/upstream.ts:70-78`), makes DNS pinning optional (`:375-380`), and follows same-host redirects without calling the standalone `guardRedirect` implementation (`:419-435`). Cross-host and redirect-count checks are present and tested, but same-host DNS rebinding and HTTPS policy are not guaranteed. `SECURITY.md:12-14` records this as unsupported. P1 when an attacker can influence upstream configuration or redirect behavior; no live public target was contacted.

### AP-4: Secret transformation outside lineage coverage -> disclosure after approval (P1)

The gate uses `matchSensitiveValue` from `src/core/lineage.ts` (`src/gateway/engine.ts:2,75`) and the stored variants are exact, Base64, Base64URL, and URL-encoded (`src/core/lineage.ts:23-34`). The separate `src/analysis/crypto.ts` detector is not imported by the gate. `SECURITY.md:15` explicitly excludes arbitrary cryptographic transformations and paraphrase. A tool that hashes or semantically rewrites secret output can therefore avoid this lineage signal. This is a boundary gap, not a claim that the documented encodings failed; those tests passed. P1 if operators expect universal secret transformation containment, otherwise an explicit P2 limitation.

### AP-5: Local child process reported as network-denied without enforcement (resolved for unsupported mode)

`runContained` reports `capabilities.network: "unknown"` when enforcement is not active and returns `unsupported` for required sandbox requests without an enforceable runtime. Docker secure-default invariants and timeout/cleanup behavior are tested; direct Docker image execution and macOS runtime proof remain NOT PROVEN. `sandbox: "none"` is deliberately not an isolation claim.

### AP-6: Build-time supply-chain drift (partially remediated)

The CI workflow now uses full commit SHAs for its third-party actions. The generic Guard still detects only obviously mutable `main`, `master`, and `latest` references, so it is not a complete SHA-policy validator. Dependency audit, SBOM/provenance, and remote action review remain NOT PROVEN.

## Existing controls with source evidence

| Control | Source evidence | Executed evidence | Status |
|---|---|---|---|
| JSON-RPC/frame/body bounds and supported method boundary | `src/gateway/stdio.ts:6-18,57-69`; `src/mcp/protocol.ts:25-47`; `src/mcp/http.ts:9-12,53-72` | `pnpm test` and focused transport tests | PASS for tested cases only |
| Shared `tools/call` authorization before forwarding | `src/gateway/engine.ts`; stdio; HTTP; API `/api/v1/authorize` | 291/291 full suite; bounded CLI/API probe | PASS for covered routes; dynamic registry provenance, gateway-wide containment, and production deployment remain NOT PROVEN |
| Schema and hidden-property rejection | `src/core/normalize.ts:55-91,93-102,220-245`; `src/gateway/engine.ts:35-46` | `test/security.test.ts`, `test/readiness.test.ts` | PASS for static descriptors and tested schema drift |
| Approval binding, expiry, replay, and atomic state | `src/storage/store.ts:140-179` | `test/security.test.ts`, `test/readiness.test.ts` | PASS for tested approval paths |
| Authority capsule/lease lifecycle and session binding | `src/authority/capsule.ts`, `src/authority/lease.ts`, `src/authority/evaluate.ts`; gate session check `src/gateway/engine.ts` | authority, gateway, API, and identity tests | PASS for tested known values and explicit unknowns; full property coverage NOT PROVEN |
| Taint storage without plaintext values | `src/core/lineage.ts:37-49`; `src/storage/store.ts:187-197` | `test/security.test.ts:56-64,138-160` | PASS for documented encodings and session separation |
| Receipt signatures and terminal chain-head detection | `src/storage/receipts.ts:47-85`; `src/storage/store.ts:199-222` | receipt corruption/deletion tests in `test/readiness.test.ts` | PASS for current implementation; RFC8785 compliance NOT PROVEN |
| API host/origin/token/rate limits and redacted views | `src/api/server.ts:31-45`; `src/ui/report.ts` | `test/api.test.ts`, `test/ui/ui.test.ts` | PASS for tested loopback behavior |
| Containment bounds and required-sandbox fail-closed behavior | `src/containment/runner.ts` | `test/containment/runner.test.ts`; bounded Docker probe | PASS for bounds/unsupported mode; direct Docker/macOS enforcement NOT PROVEN |
| Dependency/workflow review | tracked `pnpm-lock.yaml`; SHA-pinned `.github/workflows/ci.yml` | workflow guard and source inspection | Workflow pinning PASS; dependency audit/SBOM/provenance NOT PROVEN |

## Gaps

* The normalizer now rejects unknown field kinds, pointers, access values, method pointers, declared capabilities/effects, and empty no-argument authority. Dynamic signed registry provenance and full fuzz/property coverage remain NOT PROVEN.
* Authority rejects explicit `unknown` capability/effect values. The remaining authority gap is binding all identity/project/registry/containment components in every deployment path.
* The authority implementation checks request membership in capsule/leaf constraints but does not itself state or enforce the full `P ∩ I ∩ L ∩ S ∩ D ∩ C` contract. The proposed calculus in `AUTHORITY_CALCULUS.md` is the required target, not a claim that current code implements every component.
* The upstream URL client does not require HTTPS, DNS pinning, or redirect-by-redirect destination reclassification.
* Lineage covers documented encodings only. The crypto and paraphrase analyzers are standalone and not on the forwarding path.
* `network: "unknown"` is returned when the local process runner does not enforce a network boundary; Docker execution and macOS runtime proof remain separately scoped.
* Receipt code labels a custom canonicalizer RFC8785-JCS without RFC test-vector evidence.
* CI action references are pinned by full SHA in the checked-in workflow, but the generic workflow guard does not yet require SHA references for every arbitrary workflow.
* The current test tree has no `test/stdio.test.ts`; claims citing that file are stale evidence pointers.

## Severity rubric

* **P0:** Direct, demonstrated unauthorized external side effect, secret disclosure, arbitrary code execution, or reference-monitor bypass with a realistic attacker-controlled input. Requires reproduction or equivalent direct source proof. No current P0 remains after the normalizer hardening; AP-1 is retained as a resolved historical finding.
* **P1:** High-impact privilege, identity, SSRF, lineage, or containment failure that needs a deployment condition or is a boundary limitation. Source proof plus a realistic path is sufficient; live internet interaction is not required. AP-2 and AP-5 are resolved for their tested values; AP-3/AP-4 remain documented boundary limitations.
* **P2:** Integrity, availability, supply-chain, interoperability, or misleading-certification gap without a demonstrated direct side effect. Source evidence is required. AP-6 and canonicalization are P2.
* **P3:** Defense-in-depth, usability, or documentation issue with no material security effect demonstrated. Do not use P3 to downgrade an untested high-impact path.

Confidence is separate from severity: HIGH means the source and/or local reproduction establishes the behavior; MEDIUM means a deployment-dependent path is source-supported but not executed; LOW is a hypothesis and is not reported as a finding.

## Required remediation

1. **RESOLVED for covered forms: block untrusted normalizer input.** The runtime rejects unknown field types, pointers, access values, method pointers, and authority metadata before forwarding. Bind the normalizer digest to an operator-approved registry record and add property/fuzz coverage before claiming universal provenance.
2. **RESOLVED for explicit capability/effect values: make unknown impossible to allow.** Validation and evaluation reject `unknown`; extend the same proof to every resource, protocol, registry, principal, and containment state.
3. **P1, make destination enforcement mandatory.** Require HTTPS unless an explicit local-only policy permits HTTP; pin and revalidate every redirect destination; classify every resolved address and deny loopback, private, link-local, reserved, and unresolved addresses unless explicitly and separately authorized.
4. **IMPLEMENTED at the result-contract level: correct containment semantics.** Return `network: "unknown"` or `unsupported` unless an OS/container policy actually enforces no network. Keep required sandbox mode fail-closed; direct Docker/macOS execution remains a release gate.
5. **P1/P2, define lineage coverage.** Either wire crypto/paraphrase detectors into the gate with fail-closed uncertainty or state that only the four documented encodings are covered and require explicit approval for every other transformed result.
6. **P2, use a real RFC8785 implementation or rename the receipt field.** Add RFC vectors for numbers, Unicode, escaping, and nested objects before claiming JCS interoperability.
7. **PARTIALLY IMPLEMENTED: pin CI actions by full commit SHA.** The checked-in CI workflow uses immutable SHAs; make the generic Guard reject all non-SHA action references and run dependency/SBOM review in controlled CI.
8. **IMPLEMENTED: remove unconditional certification text.** `scripts/certify.ts` performs a bounded high-confidence scan and emits its count; it does not certify dependency or production secret-management controls.

## Findings

| ID | Severity | Confidence | Finding | Evidence |
|---|---|---|---|---|
| TM-001 | RESOLVED | HIGH | Earlier upstream-controlled normalizer type confusion bypassed effect inference; current closed validation rejects the tested form before forwarding. | Historical probe; current `src/core/normalize.ts` and `test/security-hardening.test.ts` |
| TM-002 | RESOLVED | HIGH | Earlier authority kernel allowed explicit `unknown` capability/effect values; current validator/evaluator rejects them. | Historical probe; current `src/authority/validation.ts`, `src/authority/evaluate.ts`, and security-hardening tests |
| TM-003 | P1 | MEDIUM | Upstream HTTP destination protection is optional and does not prove DNS-rebinding or HTTPS/redirect destination safety. | `src/mcp/upstream.ts:70-78,375-435`; `SECURITY.md:12-14`; redirect tests only |
| TM-004 | RESOLVED FOR UNSUPPORTED MODE | HIGH | Earlier containment result claimed network denial for an unenforced local process; current `sandbox: "none"` reports network `unknown` and required sandbox fails closed. | `src/containment/runner.ts`; containment tests and bounded probe |
| TM-005 | P1 | MEDIUM | Secret lineage does not cover arbitrary crypto or paraphrase transformations on the forwarding path. | `src/gateway/engine.ts:2,75`; `src/core/lineage.ts:23-34`; `SECURITY.md:15` |
| TM-006 | P2 | HIGH | Receipt metadata claims RFC8785-JCS while implementation uses a custom JSON canonicalizer without RFC vectors. | `src/storage/receipts.ts:35,52-60`; `src/core/canonical.ts:3-17` |
| TM-007 | PARTIALLY RESOLVED | HIGH | Checked-in CI actions are now pinned by full SHA; generic Guard enforcement and dependency/SBOM evidence remain open. | `.github/workflows/ci.yml`; `src/guard/index.ts` |
