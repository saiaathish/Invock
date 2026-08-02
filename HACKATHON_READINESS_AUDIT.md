# Invock Hackathon Readiness Audit

> SUPERSEDED HISTORICAL ARTIFACT — DO NOT USE AS CURRENT EVIDENCE. This file preserves a dated pre-hardening audit snapshot for traceability only. The statements below describe the filesystem and test inventory observed by that audit; they are not claims about the current checkout, current HEAD, current test count, or current security behavior. Consult `CURRENT_STATE_AUDIT.md` and `FINAL_PRODUCT_CERTIFICATION.md` for the current evidence boundary.

> **Current-tree fact check:** the live checkout and exact commit are intentionally not duplicated in this archived report because they change. Run `git rev-parse HEAD`, `git status --short --branch`, and `pnpm test` from the repository root before using any present-tense product or release claim.

## 1. Final Verdict

**NOT READY**

At the time of this independent, no-repair snapshot, the audit recorded that the supplied seven tests passed and that two authorization bypasses appeared to violate the then-current reference-monitor claim: a JSON-RPC `tools/call` notification was reported as forwarded without authorization in both supported transports, and declared tool descriptors were reported to ignore unlisted arguments while forwarding the original request upstream. The documented full demo was also reported as not runnable from the documented commands. These are historical P0/P1 findings, not a current-tree verdict.

## 2. Executive Summary

Positive evidence: Node 22, TypeScript, the SQLite-backed store, loopback API, direct gate checks, and the supplied certification command execute successfully in the audited environment. The implementation has real HMAC, Ed25519, SQLite, and HTTP server code; it is not merely a documentation-only project.

However, the end-to-end security boundary is incomplete. `src/gateway/stdio.ts` and `src/mcp/http.ts` classify a call as securable only when it has an `id`. A syntactically valid JSON-RPC notification with `method: "tools/call"` is therefore forwarded without reaching `InvocationGate`. In the HTTP implementation this was independently reproduced by the audit subagent with a local mock: `intercepted: 0, forwarded: 1`. This bypass skips policy evaluation, approvals, taint handling, persistence, and receipts.

Separately, `normalizeInvocation` normalizes only descriptor-listed JSON pointers and does not validate the complete argument object against a tool schema. The gate then forwards the original request. Thus a static descriptor can authorize a benign listed field while an upstream-capable unlisted field remains invisible to policy. The claimed “unknown security-relevant input does not silently allow” invariant is not met.

No real credentials or external services were used. This report is the sole audit-created repository artifact.

## 3. Repository and Environment

| Item | Evidence | Result |
|---|---|---|
| Working directory | `/Users/saiaathishkarthik/Desktop/Invock` | Observed |
| Git root / branch / commit | The audit environment reported `fatal: not a git repository` for `git rev-parse`, `git branch`, `git log`, and `git status` | **Unavailable in that historical audit environment** |
| Initial working tree | Cannot be established without `.git`; pre-audit file inventory was recorded by the environment | Not independently provable |
| Node | `v22.23.1` | Meets `>=22.5.0` |
| Corepack | `0.35.0` | Observed |
| pnpm | `11.15.1` | Observed |
| SQLite | Node built-in `node:sqlite`; application checks `sqlite_version() >= 3.51.3` | Observed during tests |
| Lockfile | `pnpm-lock.yaml` present; SHA-256 during audit `58ed8f…302ec` | Present |
| Package pinning | `yaml`, `tsx`, TypeScript, and Node types use exact versions in `package.json` | Positive |
| Protocol SDK pinning | No MCP SDK dependency is present; transport is hand-written | Claim cannot be evaluated as SDK pinning |

The historical audit environment reported that its folder was not a Git checkout. Consequently, that audit could not report commit provenance, history secret scan, tracked/untracked separation, or final `git status --short`. This was a snapshot-environment limitation, not a statement about the current checkout and not a source-code repair performed by that audit.

## 4. Claimed Scope

The user-facing scope was extracted from `README.md`, `IMPLEMENTATION_STATUS.md`, `package.json`, CLI help, source comments, and certification output:

- deterministic ActionEnvelope normalization and deny-overrides YAML policy;
- stdio mediation and guarded Streamable HTTP POST mediation;
- exact/encoded sensitive-flow matching;
- one-time approvals;
- SQLite activity/approval/taint storage and Ed25519 receipt chain;
- loopback authenticated dashboard/API;
- an in-memory schema-drift quarantine boundary;
- CLI demos and `pnpm certify`.

`IMPLEMENTATION_STATUS.md` accurately identifies major roadmap omissions such as SSE/GET, upstream HTTP session handling, durable registry lifecycle, DNS pinning, SQL parsing, process containment, and extensive verification. Those omissions were not treated as failures unless they conflicted with an implemented claim.

## 5. Verified Functionality

| Function | Evidence | Verdict |
|---|---|---|
| TypeScript compilation | `pnpm typecheck` exit 0 | VERIFIED |
| Unit/API test runner | The historical snapshot recorded `pnpm test`: 7 passed, 0 failed, 0 skipped | VERIFIED for that snapshot only |
| Production build | `pnpm build` exit 0 | VERIFIED |
| Certification command execution | `pnpm certify` exited 0 and runs typecheck, test, build, then `dist/scripts/certify.js` | PARTIALLY VERIFIED |
| Direct protected-path gate denial | `test/security.test.ts:42-44` | VERIFIED (engine level) |
| Direct one-time approval mutation/replay denial | `test/security.test.ts:46-54` | VERIFIED (engine level) |
| Direct Base64 flow block | `test/security.test.ts:56-64` | VERIFIED (narrow/manual source-label setup) |
| API bearer/Host behavior | real `startApi` test at `test/api.test.ts` | VERIFIED (covered routes) |
| HTTP request-with-id pre-forward denial | `test/mcp-registry.test.ts:30-38` | VERIFIED (one path) |
| HTTP tool-call notification mediation | subagent local mock reproduced forwarding with zero interception | **FALSE** |
| stdio tool-call notification mediation | source audit: `stdio.ts:17-18, 52-56` forwards no-id call | **FALSE** |
| Registry quarantine in product gateway | registry has no integration with `InvocationGate` or CLI | **FALSE** |
| Documented complete demo | README has only `demo:safe`/`demo:attack`; no documented mock server/sink/approval/receipt-chain workflow | NOT VERIFIED |

## 6. Claim-to-Evidence Matrix

| ID | Claim | Source | Required evidence | Actual implementation | Test coverage | Runtime proof | Verdict |
|---|---|---|---|---|---|---|---|
| C-01 | Every visible MCP tool call is authorized | README opening; `stdio.ts:29-30`; `http.ts:15` | Both transports reject/mediate all call forms | No-id calls bypass `isToolCall` | No notification test | HTTP mock observed `forwarded:1`, `intercepted:0` | **FALSE** |
| C-02 | stdio tool calls only forward after policy | `stdio.ts:30` | Allowed/block/pending E2E fixture | Request-with-id path gates first | No stdio tests | Audit mock rehearsal covered ordinary path only | PARTIALLY VERIFIED |
| C-03 | HTTP POST applies same gate | README; `http.ts:15` | Auth, valid request, block, pending, notification | Ordinary requests gate; notification bypasses | One blocked request test | Bypass reproduced | **FALSE** |
| C-04 | Fail-closed normalization | README; `engine.ts:51-57` | Bad descriptor/input cannot forward | Caught normalizer exceptions become block | Indirect only | Source confirms | PARTIALLY VERIFIED |
| C-05 | Unknown security facts do not allow | README; policy defaults | Unlisted arguments/schema validation | Unlisted arguments are ignored and original request forwards | None | Static proof `normalize.ts:163-171`, `engine.ts:59` | **FALSE** |
| C-06 | Exact/encoded taint | README; `lineage.ts:23-68` | exact + each stated encoding E2E | HMAC variants/decoding implemented | Base64 only, source label manually injected | No Base64URL/URL encoded E2E proof | PARTIALLY VERIFIED |
| C-07 | One-time exact approval | README; `store.ts:69-103` | arg/tool/server/schema/policy/replay/concurrent tests | digest includes listed fields; static target/server | arg mutation/replay only | Engine direct proof | PARTIALLY VERIFIED |
| C-08 | Signed hash-chained receipts | README; `receipts.ts` | persisted chain tamper/deletion/reorder/wrong-key tests | Ed25519 and sequential previous hash real | detached object tamper only | No persisted corruption/deletion proof | PARTIALLY VERIFIED |
| C-09 | Schema drift quarantine | README; `registry.ts` | discovery state feeds invocation decision | in-memory registry only, unused by gateway | isolated registry test | No gateway quarantine proof | **FALSE** |
| C-10 | Dashboard/API exposes real state | README; `api/server.ts` | fresh DB, auth, activity, approval, receipt UI/API | real store reads for implemented endpoints | API auth only | subagent rehearsal verified activity/approval/receipt APIs | PARTIALLY VERIFIED |
| C-11 | CLI demos demonstrate system | README/package scripts; `cli.ts:28-33` | documented full story | two in-memory direct gate calls only | None | `demo:safe` prints “Would forward”; attack blocks | **FALSE as full demo** |
| C-12 | `pnpm certify` proves listed claims | README/package scripts; `scripts/certify.ts` | all named subchecks exercised | only four hand-coded assertions after generic tests | no transport/stdout/drift persistence coverage | command exits 0 | PARTIALLY VERIFIED |

## 7. Certification Audit

### Commands and outcomes

```text
pnpm install --frozen-lockfile --offline  -> exit 0, “Already up to date”
pnpm typecheck                            -> exit 0
pnpm test                                 -> 7 pass / 0 fail / 0 skip
pnpm build                                -> exit 0
pnpm certify                              -> exit 0
```

The offline frozen install demonstrates that the current installed/cache state is lockfile-compatible. The audit attempted a separate temporary-copy install from a zeroed temporary worktree, but it stalled and was terminated; therefore a genuinely fresh-network or empty-cache installation is **not independently proven**. The source lockfile did not need regeneration during the successful offline command.

`package.json:15` invokes typecheck, tests, build, then `dist/scripts/certify.js`. `scripts/certify.ts:27-35` checks only a protected path, an approval-required egress, a mutated approval retry, and a chain verification. Its printed four-line PASS banner does not execute stdio transport, notification handling, dashboard, API approval, schema-drift integration, tampered database, or full demo checks. Failures in its executed assertions are not swallowed, but its scope is materially narrower than its label suggests.

## 8. MCP stdio Audit

### Positive evidence

- `spawn(..., { shell: false, stdio: ["pipe","pipe","pipe"] })` at `src/gateway/stdio.ts:36` avoids shell expansion.
- Ordinary request-with-id calls call `gate.intercept` before `child.stdin.write` (`stdio.ts:54-56`).
- Diagnostics write to stderr (`stdio.ts:43-45`), and protocol output uses stdout (`stdio.ts:40`).
- Oversized/NUL/malformed lines are rejected (`stdio.ts:10-15, 51`); malformed upstream output closes the child (`stdio.ts:58-60`).

### Failures

1. **P0: no-id `tools/call` notification bypass.** `isToolCall` at `stdio.ts:17-18` requires a string/number id. The router at `stdio.ts:52-53` forwards every nonmatching message to upstream. A tool-side-effect notification therefore bypasses policy and audit.
2. **P1: duplicate request ID correlation is unsafe.** `inFlight.set(message.id, outcome)` at line 56 overwrites a prior active request with the same id. The first matching upstream response can be associated with the wrong envelope/receipt and the other is unaccounted.
3. **P2: no stdio integration test exists** for initialize, tools/list, blocked/pending upstream counts, stdout cleanliness, frame limit, concurrent IDs, child shutdown, or malformed upstream behavior. There are no request timeouts or graceful escalation sequence.

## 9. Streamable HTTP Audit

### Positive evidence

- Defaults to `127.0.0.1` (`src/mcp/http.ts:17`).
- Checks Host, optional Origin, bearer token, exact `/mcp`, POST, JSON content type, and 2 MiB accumulated body size (`http.ts:19-30`).
- The supplied test proves one regular protected request returns block and calls the injected forwarder zero times (`test/mcp-registry.test.ts:30-37`).
- GET is explicitly 405, matching the documented POST-only limitation (`http.ts:25`).

### Failures

1. **P0: valid JSON-RPC tool notifications bypass the gate.** `parseJsonRpc` accepts a message with method/no id (`protocol.ts:28-33`). `isToolCall` demands `id` (`protocol.ts:39-42`); `http.ts:31-32` forwards all nonmatches. Independent local mock evidence: a `tools/call` notification produced HTTP 200 with `intercepted: 0, forwarded: 1`.
2. **P1: protocol version negotiation accepts arbitrary unknown strings as stable 2025.** `negotiateEra` only special-cases 2026 and two legacy versions; all other values return stable-2025 (`protocol.ts:15-23`). No response header confirms negotiation.
3. **P1: upstream response correlation and shape are not verified.** `http.ts:38-42` accepts any object containing `result`, ignores upstream id, and casts `result` to `ToolResult`; mismatched upstream replies can be emitted as the client request’s id.
4. **P2: only a server-side forwarding callback exists.** No upstream Streamable HTTP client, session mapping, GET/SSE, redirect controls, or hard timeouts are implemented. These are documented incomplete, but the POST entry point is not exposed by CLI.

## 10. ActionEnvelope and Policy Audit

`src/core/normalize.ts:160-181` creates a canonical envelope from descriptor-designated pointers and `src/core/policy.ts:157-181` evaluates a deny-overrides lattice. `canonical.ts` sorts object keys for digests. Normalizer exceptions enter `failureEnvelope` and a block (`engine.ts:51-57`). YAML uses `uniqueKeys: true`, `maxAliasCount: 0` on conversion, custom root tags rejected, bounded file size, and strict top-level keys (`policy.ts:54-98`).

**P0: descriptor omission is an authorization bypass.** `normalizeInvocation` loops only over `descriptor.fields` (`normalize.ts:163-171`), silently ignores all other arguments, and does not validate against a full upstream tool input schema. `InvocationGate` returns the untouched `request` on allow (`engine.ts:59`). Thus policy can classify a safe `/path` as an allowed read while a hidden/unlisted `command`, URL, content, or other side-effecting field is delivered to an upstream tool. This contradicts the README fail-closed claim and means unknown fields are not uncertainty facts.

Other limits: the actual policy is compiled once in CLI (`cli.ts:19-26`) with no policy activation/reload API; conditions are direct recursive evaluation rather than the claimed VM; no test covers aliases/merge keys, invalid policies, policy evaluator failure, JSON-key reorder, traversal/prefix/symlink corpus, or rule ordering beyond source reasoning.

## 11. Taint and Exfiltration Audit

`lineage.ts:12-68` uses standard HMAC-SHA-256 with domain separation and constant-time equal-length comparisons. It generates exact/Base64/Base64URL/URL-encoded fingerprints; candidate decoding is implemented. `store.ts:111-120` persists fingerprints, lengths, labels, source invocation IDs, and expiry—not raw result text. This is positive evidence for the narrow raw-secret persistence claim.

Findings:

- **P1: session isolation is absent.** `InvockStore.activeFingerprints` joins all unexpired taint records without filtering session (`store.ts:106-109`), while `recordTaint` stores no session id. A secret observed in one logical session can affect another session. This is a false-positive/cross-tenant boundary issue despite the single-user design.
- **P2: only Base64 is actually tested.** The sole encoded test manually mutates a forward envelope’s labels and calls `finish` (`test/security.test.ts:56-62`). Base64URL and URL-encoded claims are code-only; source labels/output extraction are not exercised by a real MCP result.
- **P2: HMAC/signing private material is stored in SQLite metadata** (`store.ts:30-37`). The README labels that developer-reference behavior, but a database writer can obtain the taint key and signing private key. It is not strong tamper evidence against an attacker able to edit that database.

## 12. Approval Audit

Positive evidence: approval binding hashes principal/client/server/tool/argument/schema/descriptor/policy/reasons/capabilities/effects (`store.ts:69-71`). `BEGIN IMMEDIATE` and status checks protect approve/consume (`store.ts:81-103`). The direct test proves one changed body is denied and exact replay is denied (`test/security.test.ts:46-54`). A forwarded approval remains consumed even if later upstream completion fails.

Findings:

- **P1: binding has no live registry/server integration.** The target server is hard-coded as `default` in normalized envelopes (`normalize.ts:176-180`), and static descriptor digests are local code-derived (`engine.ts:87-91`), not discovered schemas. Tool/server/schema drift therefore cannot be the dynamic approval invalidator the product describes.
- **P2: no reject operation, concurrent-consumption test, expiration test, restart test, tool-change test, server-change test, or policy-change test exists.** The API only supports approve (`api/server.ts:35-36`).

## 13. Receipt and Cryptography Audit

`receipts.ts:31-51` generates Ed25519 keys using Node crypto, signs a domain-separated SHA-256 receipt hash, verifies it with Node `verify`, and compares expected predecessor hashes. `store.ts:123-139` serializes receipt creation with `BEGIN IMMEDIATE`; startup calls `verifyChain` (`store.ts:38`).

Findings:

- **P1: the only tamper test is detached-object verification.** `test/security.test.ts:66-72` mutates an object returned from `getReceipt`, then explicitly observes `store.verifyChain() === true` because the stored row was not mutated. It proves `verifyReceipt` on the modified in-memory object fails, but does not prove startup rejects modified/deleted/reordered/corrupt database rows.
- **P1: deleting the terminal receipt is not detectable by the local chain.** `verifyChain` iterates whatever rows remain (`store.ts:135-139`) and has no externally anchored chain head/checkpoint. Middle deletion should fail predecessor linkage, but tail deletion appears valid.
- **P2: the same SQLite meta table stores the private signing key** (`store.ts:30-37`), so an attacker with write access can replace receipts and key material. README acknowledges developer-reference key storage but its tamper-evidence claim must be constrained accordingly.

## 14. SQLite and Persistence Audit

Positive evidence: every store connection executes `foreign_keys=ON`, WAL, FULL synchronous mode, and busy timeout (`store.ts:24-28`); strict tables and relevant uniqueness constraints exist (`store.ts:42-64`); approval and receipt writes use `BEGIN IMMEDIATE`.

Findings:

- **P1: no migration system exists.** `migrate()` only creates current tables; there is no schema version, forward migration, compatibility check, rollback, or durability test.
- **P2: taint expiry is query filtering only.** Expired rows are excluded but never purged (`store.ts:106-120`).
- **P2: encryption/key separation is absent.** This is acknowledged in README but remains unsuitable for a stronger local-database attacker model.

## 15. Schema-Drift Audit

`registry.ts` computes descriptor/schema digests and identifies required/type/structure changes; isolated test `test/mcp-registry.test.ts:40-47` proves an added required `command` field yields a high drift and quarantine status.

**P1: quarantine is not enforced.** `ToolRegistry` is an in-memory standalone class (`registry.ts:42-50`). `InvocationGate` receives `StaticDescriptorRegistry` and never imports/consults `ToolRegistry` (`engine.ts:8, 42, 87-92`). CLI does not perform tools/list discovery. Drift does not persist, cannot invalidate approvals, cannot appear in dashboard state, and cannot block a live upstream call.

## 16. Dashboard and API Audit

### Positive evidence

- Loopback is the default (`api/server.ts:22-23`); hostile Host is rejected (`:25-26`).
- Protected API routes check constant-time bearer comparison (`:14-18, 29`).
- `/health` is intentionally public; `/ready`, `/activity`, `/approvals`, receipt lookup, and approve route exist (`:28-36`).
- Subagent live rehearsal on a fresh temporary database confirmed dashboard start/auth, activity/approvals/receipts routes, API approval, and cleanup.

### Findings

- **P1: README/API scope overstates dashboard capability.** README describes dashboard API but only activity/approvals/receipt are implemented. No `/tools`, `/policy`, policy activation/validation, metrics, pagination cursor, rejection, receipt verification/export, or scopes exist.
- **P2: `/` dashboard and `/health` are intentionally unauthenticated.** The page does not embed the token, which is good; however, Host-only local protection is not a substitute for same-origin/Origin handling on dashboard API.
- **P2: API error text returns internal exception messages** (`api/server.ts:38`), which can reveal body/parser details. No rate limit or CORS policy is implemented.

## 17. End-to-End Demo Rehearsal

The supplied package commands were run:

```text
pnpm demo:safe   -> { "decision": "ALLOW", "message": "Would forward to upstream server" }
pnpm demo:attack -> structured BLOCK/PATH_PROTECTED result
```

These are in-memory `InvocationGate` calls (`cli.ts:28-33`), not a real MCP client/server proxy demonstration. The independent demo subagent did assemble a temporary safe stdio mock and exercised a useful manual story (safe read, protected block, approval API, approved forward, replay denial, receipt/activity endpoints), but that harness and its commands are not documented in README and do not include the taint/exfiltration narrative prescribed by the task.

**P1: the documented full hackathon demo does not exist.** README gives no `demo:up`, mock MCP server, mock sink, taint permit policy, approval CLI/API command sequence, receipt export/verify command, or dashboard walkthrough. It cannot prove the required 16-step story without undocumented custom harness work. `serve --stdio` also hardcodes `.invock/invock.sqlite` (`cli.ts:39`), making a clean repeatable stdio demo database unavailable through documented options.

## 18. Test Quality Audit

The historical seven-test snapshot used real Node SQLite and real local HTTP server instances where applicable, but coverage was shallow and most critical supported-transport properties were untested at that time.

| Mutation / failure | Existing detection | Assessment |
|---|---|---|
| Change protected path block to allow | `security.test.ts:42-44` | Detected at gate level |
| Skip Base64 taint matching | `security.test.ts:56-64` | Detected only with manually injected source label |
| Forward a regular protected HTTP request before gate | `mcp-registry.test.ts:30-37` | Detected for id-bearing HTTP request |
| Forward a stdio protected request before gate | None | Not detected |
| Permit tool-call notification bypass | None | Not detected; confirmed bypass |
| Accept any approval digest | `security.test.ts:46-54` | Partially detected |
| Do not consume approval | replay assertion | Detected |
| Stop receipt signature verification | detached `verifyReceipt` assertion | Partially detected |
| Ignore persisted receipt-chain corruption | None | Not detected |
| Ignore schema drift in actual gateway | None | Not detected |
| Disable dashboard bearer auth | `api.test.ts` | Detected for activity |
| Persist raw result secret | None / no database inspection | Not directly detected |

No tests are skipped, but no stdio E2E test, no concurrency test, no HTTP notification/correlation/limit/abort test, no policy-adversarial corpus, no source-result taint test, no migration recovery test, and no persistence corruption test exists.

## 19. Dependency and Supply-Chain Audit

- Direct dependencies are minimal: `yaml@2.8.1`; development tooling uses exact `tsx@4.20.5`, TypeScript `5.9.2`, and Node types `22.18.0` (`package.json:20-27`).
- `pnpm-lock.yaml` is present and frozen offline installation succeeded in the current environment.
- No MCP SDK is used; the implementation uses Node standard libraries and a hand-written protocol subset.
- Standard Node crypto is used for HMAC and Ed25519; no custom primitive is implemented.
- YAML is parsed as data, not JavaScript.

Findings:

- **P1: reproducibility metadata is incomplete.** `package.json` has no `packageManager` pin, no `.npmrc`, no CI, no SBOM/provenance/license, and README uses mutable `pnpm install` rather than frozen install. A fully fresh temporary-copy test was attempted but stalled; current-cache frozen install passed only.
- **P2: Node’s SQLite API remains experimental** and prints warnings on every test/certification run. The Node engine minimum is clear but no runtime doctor validates all operational expectations before serving.

## 20. Documentation and Submission Audit

Positive: project name is consistently Invock; README states the visible-invocation boundary and does not claim to prevent hidden malicious server actions; incomplete HTTP/SSE, DNS, SQL, containment, and benchmark work are honestly noted. No real credentials, PEM blocks, large binaries, `.env` files, or dependency cache were found by the audit’s redacted pattern scan.

Findings:

- **P1: no LICENSE file and no Git metadata/history are present.** A hackathon judge cannot establish commit identity, inspect history for secrets, or reproduce a normal repository checkout.
- **P1: claimed features conflict with actual wiring** (same HTTP authorization gate; operational drift quarantine; full demo/certification breadth).
- **P2: README quick start and CLI help omit the practical full demo, HTTP gateway launch, approval operation workflow, receipt verification/export, and fallback demo plan.**
- **P2: README’s security-check list identifies seven checks but the documented `pnpm certify` banner reports only four, and the latter does not exercise all seven.**

## 21. Security Invariant Results

| ID     | Invariant                               | Test method | Evidence | Result    |
| ------ | --------------------------------------- | ----------- | -------- | --------- |
| INV-01 | Every supported tool call is mediated   | HTTP/stdio static + HTTP mock | no-id tools/call bypass | FAIL |
| INV-02 | Blocked call never reaches upstream     | regular request test + notification proof | id-bearing pass; protected notification bypasses decision | FAIL |
| INV-03 | Pending approval never reaches upstream | direct engine test + transport review | notification skips pending state | FAIL |
| INV-04 | Approval binds to exact invocation      | direct mutation/replay test | body mutation blocked; full dynamic server/schema not wired | FAIL |
| INV-05 | Approval is one-time                    | direct replay test | `security.test.ts:46-54` | PASS |
| INV-06 | Policy failure is fail-closed           | source review | normalizer failures block; no reload path | PASS |
| INV-07 | Unknown effects do not silently allow   | static review | unlisted descriptor arguments ignored | FAIL |
| INV-08 | Exact secret flow is detected           | code + Base64 test path | keyed exact HMAC variant exists | PASS |
| INV-09 | Claimed encoded flows are detected      | test/code review | Base64 only tested; Base64URL/URL-encoded not E2E | FAIL |
| INV-10 | Raw secrets are not persisted           | storage review | taint rows store keyed digest/metadata, not result text | PASS |
| INV-11 | Critical schema drift quarantines       | isolated registry test + wiring review | quarantine not consulted by gateway | FAIL |
| INV-12 | Receipt tampering is detected           | detached signature test | mutated in-memory receipt fails `verifyReceipt` | PASS |
| INV-13 | Chain corruption is detected            | code/test review | tail deletion undetectable; no DB-corruption test | FAIL |
| INV-14 | Sensitive API routes require auth       | live local API test | activity unauthenticated 401; approve path has auth guard | PASS |
| INV-15 | HTTP binds loopback by default          | source/live dashboard rehearsal | default `127.0.0.1` | PASS |
| INV-16 | MCP stdout remains protocol-clean       | source review, no E2E capture | intended routing only; no transport proof | FAIL |
| INV-17 | Clean certification succeeds            | frozen offline install + certify | succeeds with existing cache; virgin checkout not proven | FAIL |
| INV-18 | Full demo succeeds                      | documented commands | only two in-memory demos exist | FAIL |
| INV-19 | Documentation matches implementation    | claim matrix | transport/drift/demo claims overstate wiring | FAIL |
| INV-20 | Audit cleanup completes                 | process/temp cleanup commands | temp harnesses killed/removed; no active audit server reported | PASS |

## 22. Findings by Severity

### P0 — CRITICAL SUBMISSION BLOCKER

1. **MCP `tools/call` notifications bypass authorization in HTTP and stdio.** `src/mcp/protocol.ts:39-42`, `src/mcp/http.ts:31-32`, `src/gateway/stdio.ts:17-18,52-56`. Confirmed with a local mock for HTTP. Violates INV-01 through INV-03.
2. **Unlisted security-relevant arguments are not normalized or denied, but are forwarded unchanged.** `src/core/normalize.ts:160-171` with `src/gateway/engine.ts:59`. Violates fail-closed unknown-input claim and the authorization-boundary claim.

### P1 — MAJOR SUBMISSION BLOCKER

1. Schema-drift quarantine is isolated and not enforced by the actual invocation path (`src/registry/registry.ts:42-50`; `engine.ts:42,87-92`).
2. No documented end-to-end demo command set exists; demos are in-memory outcomes, not MCP transport/sink/approval/receipt story (`src/cli.ts:28-33`; README).
3. HTTP protocol selection accepts arbitrary versions; upstream response correlation/shape is not verified (`protocol.ts:15-23`; `http.ts:38-42`).
4. stdio duplicate request IDs overwrite correlation state (`stdio.ts:37,56`).
5. Receipt chain testing/persistence cannot detect terminal deletion and stores private signing key with receipts (`store.ts:30-37,135-139`).
6. No Git repository/commit/history and no license; clean submission provenance cannot be audited.
7. Fresh zero-state install was not proven; package-manager toolchain is not pinned in manifest/CI.

### P2 — IMPORTANT BEFORE SUBMISSION

1. Taint is not scoped to a logical session; Base64URL/URL encoding claims lack E2E tests.
2. Approval rejection, expiry, concurrent consumption, restart, tool/server/schema/policy-change coverage is absent.
3. Dashboard/API has only partial documented endpoint surface, no scopes/rate limiting, and exposes raw internal exception text.
4. No stdio E2E protocol lifecycle/frame/concurrency/cleanup tests; no HTTP abort/body-limit/origin/correlation suite.
5. CLI hardcodes `.invock/invock.sqlite` in stdio mode; no documented temp DB option.

### P3 — POST-HACKATHON IMPROVEMENT

The honestly documented roadmap: GET/SSE, upstream HTTP sessions, DNS pinning/redirect validation, richer SQL/command/recipient normalizers, compiled policy VM, property/mutation/fuzz/performance suites, external receipt anchoring, containment, cross-platform CI, SBOM, and production key store.

## 23. Documented Out-of-Scope Roadmap

The following are correctly documented as not completed and were not independent blockers by themselves: Streamable HTTP GET/SSE, upstream session client, durable registry lifecycle, DNS rebinding/pinning, redirect validation, SQL parser, full normalizer set, VM bytecode, property/mutation/fuzz/benchmark suites, process sandboxing, external receipt anchoring, full API/dashboard scopes and OpenAPI, and release CI/SBOM/provenance.

## 24. Exact Pre-Submission Actions

1. **Fix and test the P0 transport bypass:** reject `tools/call` notifications or route every tools/call form through a policy decision before any forwarding in both stdio and HTTP. Add upstream invocation-count E2E tests.
2. **Make normalization schema-complete and fail closed:** validate the entire argument object, represent/deny unlisted fields, and forward only the authorized canonical argument set. Add adversarial undeclared-field tests.
3. **Wire registry drift to live tools/list/invocation/approval state:** persist tool versions, block quarantined tools, and invalidate approvals on descriptor/schema changes.
4. Publish a deterministic, hermetic demo fixture package/commands covering real stdio forwarding, block, taint/exfiltration, approval/replay/mutation, receipt verification, and dashboard state. Run it from a fresh temporary DB.
5. Add persisted receipt tamper/deletion/reorder tests, move signing/taint keys out of the mutable SQLite database for any tamper-evidence claim, and document terminal-deletion limitation until external anchoring exists.
6. Add package-manager pin/CI/`--frozen-lockfile` instructions, a license, and submit from an actual Git repository with a recorded commit.

## 25. Commands Executed

```text
pwd; git rev-parse/branch/HEAD/status/diff/log probes (all Git probes failed in the historical audit environment: no `.git` there)
node --version; corepack --version; pnpm --version
pnpm install --frozen-lockfile --offline
pnpm typecheck
pnpm test
pnpm build
pnpm certify
pnpm demo:safe
pnpm demo:attack
local dashboard/API readiness and authenticated activity rehearsal (temporary DB)
redacted secret/artifact scan and process cleanup probes
```

The temporary-copy clean-install attempt was terminated after stalling. It is reported as incomplete rather than as a pass.

## 26. Temporary Artifact and Process Cleanup

- Audit subagents used `/tmp/invock-*` directories, local mock servers, fake secrets, and fake tokens only.
- Hung temporary audit proof/clean-copy processes were explicitly terminated with `pkill`; matching `/tmp/invock-clean-audit.*` and `/tmp/invock-audit-proofs.*` directories were removed.
- Dashboard rehearsal process received SIGINT and its temporary database/logs were removed.
- No public network destination, real credential, commit, push, PR, dependency update, or product-source modification was used.

## 27. Final Working-Tree State

In the historical audit environment, Git status could not be obtained because that directory was not a Git repository. The audit-created source artifact was **only this report, `HACKATHON_READINESS_AUDIT.md`**. Generated `dist/` and `node_modules/` were treated as pre-existing/ignored by that snapshot; temporary `.invock` and `/tmp` audit artifacts were removed. Final package/document hashes were explicitly left for a later real-checkout verification.
