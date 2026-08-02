# Expanded invariant matrix (INV-41..INV-85)

> HISTORICAL/SCOPED MATRIX. This grouped matrix is not the current product certification and does not authorize a READY claim. Any row that depends on Docker or expanded certification must be re-run in the current environment.

Status is evidence-based: `PASS` requires a focused test or runtime proof; `NOT PROVEN` remains a release blocker.

| ID | Invariant | Evidence | Status |
|---|---|---|---|
| INV-41 | Proposed capsule cannot authorize | `test/authority/authority.test.ts` | PASS |
| INV-42 | Activation binds digest | `test/authority/authority.test.ts` | PASS |
| INV-43 | Expired capsule fails closed | `test/authority/authority.test.ts` | PASS |
| INV-44 | Revoked capsule fails closed | `test/authority/authority.test.ts` | PASS |
| INV-45 | Effective authority is monotonic | authority evaluation and lease tests | PASS |
| INV-46..INV-49 | Child lease capability/resource/expiry/budget narrowing | `test/authority/authority.test.ts` | PASS |
| INV-50 | Delegation depth is enforced | `test/authority/authority.test.ts` (`DELEGATION_DEPTH_EXCEEDED`) | PASS |
| INV-51 | Lease budget is consumed | lease unit test and gate callback path | PASS |
| INV-52..INV-53 | Parent/capsule revocation invalidates authority | revocation tests | PASS |
| INV-54..INV-55 | Receipt binds capsule and lease-chain digests | `test/authority-gateway.test.ts` | PASS |
| INV-56 | Containment profile validation | `test/containment/runner.test.ts` | PASS |
| INV-57..INV-60 | Hidden host/network/write/resource abuse denial | Docker secure-default profile and bounded probe source; current direct runtime execution timed out | NOT PROVEN |
| INV-61..INV-62 | Timeout and cleanup | `test/containment/runner.test.ts` | PASS |
| INV-63..INV-68 | Forge validation, determinism, and policy diffs | `test/forge/forge.test.ts` | PASS |
| INV-69..INV-71 | Guard unsafe/safe checks and SARIF | `test/guard/guard.test.ts` | PASS |
| INV-72 | Arena protected mode uses real Invock path | `pnpm arena` | PASS |
| INV-73 | Arena baseline remains local | `pnpm arena` | PASS |
| INV-74..INV-75 | Deterministic attack and benign outcomes | `test/arena/arena.test.ts`, `pnpm arena` | PASS |
| INV-76 | Arena reports measured latency | `test/arena/arena.test.ts`, `pnpm arena` | PASS |
| INV-77 | Protocol downgrade is rejected | `test/protocol/protocol.test.ts` | PASS |
| INV-78 | Protocol mediation uses the shared authorization core | `test/readiness.test.ts`, `test/mcp-sse.test.ts` | PASS |
| INV-79 | JSON Schema argument validation is enforced | `test/readiness.test.ts` authorization/schema cases | PASS |
| INV-80 | Protocol sessions bind effective authority | `test/authority-gateway.test.ts` cross-session denial | PASS |
| INV-81 | Dashboard uses real persistent state | `test/api.test.ts` activity/expansion endpoints | PASS |
| INV-82 | Dashboard never exposes raw secrets | `test/ui/ui.test.ts`, `test/api.test.ts` | PASS |
| INV-83 | Expanded API mutation routes require authentication | `test/api.test.ts` authenticated route checks | PASS |
| INV-84 | Full expanded demo | `node --import tsx scripts/expanded-certify.ts` | NOT PROVEN |
| INV-85 | Expanded certification twice independently | expanded certification runs base certification and Docker probe twice | NOT PROVEN |

Release status: NOT READY; this matrix contains scoped evidence and unresolved gates.
