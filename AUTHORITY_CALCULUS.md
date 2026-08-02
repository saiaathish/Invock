# Authority calculus

## Definitions

An action is the canonical tuple

```text
a = (principal, session, protocol, server, tool, args_digest,
     capabilities, effects, resources, data_labels, schema_digest,
     descriptor_digest, registry_version, lineage, containment, time, bytes)
```

The tuple is derived only after JSON-RPC and schema validation. `args_digest` is the digest of canonical arguments, not raw display text. `principal`, `session`, and `protocol` are identity/context bindings. `resources` are normalized paths, URLs, commands, recipients, and data. `lineage` is the set of source-invocation references and match kinds. `containment` is an actual enforcement result, not a requested profile.

The six authority components are:

* `P`: static policy decision and obligations from `evaluatePolicy` (`src/core/policy.ts:158-181`).
* `I`: active, unexpired, integrity-checked intent capsule (`src/authority/capsule.ts:40-61`).
* `L`: ordered, active, unexpired, integrity-checked capability-lease chain (`src/authority/lease.ts:29-46`).
* `S`: tool schema, descriptor, normalizer, registry version, and protocol profile. A quarantined or unknown registry is empty authority.
* `D`: data labels and lineage constraints. Tainted data cannot reach disclosure or communication sinks unless a separately explicit rule allows it.
* `C`: containment capability actually enforced for process/network/filesystem effects. `sandbox: "none"` is no containment authority.

`unknown` is an epistemic state, not an authority member. It may be recorded for diagnostics, but it is never an element of an allow set.

An approval is a state transition, not a seventh authority component. An action with `APPROVAL_REQUIRED` is not effective until the exact approval binding is atomically consumed. The binding must cover principal, client, session, server, tool, canonical argument digest, schema, descriptor, registry, protocol era, policy version, capabilities, effects, and decision reasons, matching `src/storage/store.ts:140-179`.

## Authority equation

The effective authority is the intersection of independently enforced action sets:

```text
A_effective = P ∩ I ∩ L ∩ S ∩ D ∩ C
```

For a candidate action `a`, the reference-monitor decision is:

```text
allow(a) =
  known(a)
  ∧ P.permits(a)
  ∧ I.permits(a)
  ∧ L.permits(a)
  ∧ S.matches(a)
  ∧ D.permits(a)
  ∧ C.enforces(a)
  ∧ approval_consumed_if_required(a)
  ∧ now < every_expiry(a)
  ∧ every_budget_sufficient(a)
```

Every conjunct is necessary. A BLOCK or UNKNOWN in any component yields BLOCK/UNSUPPORTED. `APPROVAL_REQUIRED` is not `allow`; it is a pending state. The only forwarding result permitted to a transport is `allow(a) = true`, after persistence of the interception and before the upstream write.

The current `evaluateMonotonicAuthority` checks capsule/lease/request membership and budgets at `src/authority/evaluate.ts:8-34`, while `InvocationGate` combines policy and authority at `src/gateway/engine.ts:85-117`. The equation is the target contract. Current code does not independently enforce all six components: the hostile normalizer probe demonstrated that `S` can be malformed and the `unknown` probe demonstrated that `known(a)` is not unconditional in the authority kernel.

Reference decision kernel, written as executable TypeScript pseudocode, is intentionally small and deterministic:

```ts
type Decision = "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED";
type Component = { status: "ALLOW" | "BLOCK" | "UNKNOWN"; permits: boolean };
type Candidate = { requiresApproval: boolean; approval: "absent" | "consumed" };

export function decide(candidate: Candidate, components: readonly Component[]): Decision {
  // UNKNOWN is never an allow state. Approval is evaluated only after all
  // authority components have positively permitted the same canonical action.
  if (components.some(component => component.status !== "ALLOW" || !component.permits)) return "BLOCK";
  if (candidate.requiresApproval && candidate.approval !== "consumed") return "APPROVAL_REQUIRED";
  return "ALLOW";
}
```

The production adapter must construct exactly six components in order `P, I, L, S, D, C`, and must set `permits=false` for any unknown or malformed projection. The function is deterministic for fixed inputs; it has no network, filesystem, clock, random-ID, or upstream behavior dependency.

## Partial orders

For authority sets, define `x ⊑ y` to mean “x is no more permissive than y.” The least element is deny/empty authority. A reduction must move downward (`new ⊑ old`).

For finite allow sets:

```text
Allowed_new ⊆ Allowed_old
```

For deny sets and required constraints:

```text
Forbidden_new ⊇ Forbidden_old
Required_new ⊇ Required_old
```

For temporal and budget bounds:

```text
expires_new ≤ expires_old
calls_new ≤ calls_old
bytes_new ≤ bytes_old
duration_new ≤ duration_old
```

For lease delegation, a child is valid only when tools, capabilities, effects, paths, domains, recipients, and allowed data labels are subsets of the parent; forbidden labels are a superset; expiry and remaining calls do not increase; issuer/subject and parent ID match. This is the intended reading of `src/authority/lease.ts:13-16,29-35`, with maximum chain depth 16 in `src/authority/evaluate.ts:6,14`.

For schemas and normalizers, a schema change is downward only when it removes accepted inputs or adds required constraints. Any added dangerous field, broadened `additionalProperties`, changed normalizer, unknown keyword, or unknown field type is not comparable and must map to quarantine, not to a permissive order. `src/registry/registry.ts:17-41` provides a bounded drift comparison but does not currently validate normalizer semantics.

For containment, `enforced` is below `requested`; a requested sandbox that is unavailable is not an approximation. `unsupported ⊑ denied`; it is never `allowed`.

For data, a transition that adds a secret/credential/private-key lineage edge is upward risk. It can only reduce authority to sinks, never increase it. Session changes create disjoint data domains.

## Monotonicity properties

These are executable properties for the authority kernel and integration. A property is marked PASS only when current tests directly execute it; otherwise it is a target or NOT PROVEN.

1. **Intersection safety:** if any component returns deny, `A_effective` cannot contain the action. Current policy/authority/forwarding tests cover known static descriptors; the hostile normalizer counterexample means the full property is NOT PROVEN.
2. **Downward closure:** replacing a capsule or lease by a narrower valid one cannot change BLOCK to ALLOW. Target: generate finite subsets of tools/capabilities/effects/resources and compare decisions.
3. **Delegation non-amplification:** a valid child lease cannot authorize a request outside its parent. Current `test/authority/authority.test.ts` covers capability and depth cases; property coverage over all dimensions is NOT PROVEN.
4. **No unknown authorization:** any unknown capability/effect/resource/schema/normalizer/protocol/principal/containment value yields BLOCK or UNSUPPORTED. Explicit `unknown` capability/effect values are rejected by the authority validator/evaluator and covered by `test/security-hardening.test.ts`; broader property coverage remains NOT PROVEN.
5. **Canonical determinism:** equivalent object key order yields the same digest, envelope decision, effective digest, and forwarded argument bytes. Current `test/security.test.ts:116-120` and authority digest test cover key order; full RFC8785 compatibility is NOT PROVEN.
6. **Decision determinism:** final decisions must depend only on canonical action, immutable policy/authority/registry snapshots, and an injected time value. `newId` and timestamps may decorate records but must not affect a verdict. Current `evaluatePolicy` is pure for a supplied `now` (`src/core/policy.ts:157-181`); complete end-to-end determinism is NOT PROVEN.
7. **Approval exactness:** changing any bound input or replaying a consumed approval cannot produce ALLOW. Current security/readiness tests and SQLite transaction at `src/storage/store.ts:168-179` PASS for covered bindings.
8. **Schema drift quarantine:** changing schema or normalizer after approval invalidates prior approval and blocks until a new trusted snapshot. Current persistent drift tests PASS for tested drift forms; malformed annotation behavior FAILS as TM-001.
9. **Lineage containment:** a matching taint reference plus external disclosure/communication cannot forward. Current tests PASS for exact, Base64, Base64URL, URL-encoded, JSON text, and query forms; arbitrary crypto/paraphrase remains outside the gate.
10. **Receipt/forward ordering:** a forward result must have an interception record before upstream write and a completed receipt after result/error. Current `InvocationGate` ordering is source-supported and tested for representative paths; process crash windows and cross-process concurrency are NOT PROVEN.
11. **Session non-interference:** taint or approval from session `s1` cannot authorize a request in `s2`. Current focused tests PASS for session-bound approvals and taint.
12. **Containment truthfulness:** a result may say network denied only if a policy enforces it. Current `runContained` returns `network: "unknown"` for `sandbox: "none"` and `unsupported` when a required runtime is unavailable; direct Docker/macOS enforcement remains NOT PROVEN on this host.

## Fail-closed unknowns

The following values are unknowns and must produce `BLOCK` or `UNSUPPORTED`, never `ALLOW` or `APPROVAL_REQUIRED` as a path to eventual forwarding:

* absent or malformed principal, client, session, protocol era, server, tool, request ID binding, or approval binding;
* unknown capability, effect, data label, resource kind, path resolution, URL scheme, hostname/address class, recipient, command representation, or byte/budget value;
* missing schema, descriptor, normalizer, registry version, policy version, policy digest, or containment proof;
* malformed capsule/lease digest, status, issuer/subject chain, expiry, budget, or revocation state;
* unknown schema keywords or normalizer field types, pointers, access modes, or method pointers;
* unresolved DNS, redirect destination, changed TLS identity, upstream response ID, or unsupported content type;
* receipt-chain corruption, missing chain head, key-ID mismatch, or persistence failure.

Diagnostic preservation is allowed: record a bounded reason code such as `UNKNOWN_NORMALIZER_FIELD_TYPE` or `DNS_RESOLUTION_REQUIRED`, but do not coerce it into a broad capability. `src/core/policy.ts:168-172` demonstrates default handling for some unknowns; the authority and registry layers must enforce the same rule independently.

## Canonicalization requirements

1. Parse exactly one JSON-RPC object. Reject duplicate keys, non-finite numbers, unsupported values, invalid UTF-8/control characters, and unknown protocol fields before hashing.
2. Canonicalize the complete action tuple, including sorted set-valued dimensions, exact schema/descriptor/registry/policy digests, session/principal/protocol bindings, normalized resource forms, lineage IDs/kinds, and containment proof.
3. Use one standards-conformant RFC8785 implementation for interoperability, or label the format as Invock-specific. `src/core/canonical.ts:3-17` is a custom implementation; `src/storage/receipts.ts:35` currently labels receipts `RFC8785-JCS`. This mismatch is a P2 finding until vectors prove equivalence.
4. Do not hash display strings or mutable object insertion order. Do not include random IDs or wall-clock timestamps in final verdict input. They may be receipt metadata only.
5. Bind approvals to the canonical action digest and all policy/registry/authority version digests. A canonical argument rewrite must be the exact object forwarded, as implemented at `src/gateway/engine.ts:114-116,129-130`.
6. Bind receipt sequence, previous receipt hash, upstream-forwarded bit, result digest, authority digests, and protocol profile. Verify the chain before accepting new forwarding, as `src/gateway/engine.ts:65-72` and `src/storage/store.ts:214-222` do.

## Property-test vectors

The following vectors are intended for new tests owned by the eventual implementation agent. They are not silently claimed to exist in the current test tree.

```ts
import assert from "node:assert/strict";
import test from "node:test";
import { evaluateMonotonicAuthority } from "../src/authority/evaluate.js";

test("unknown authority is never effective", () => {
  const result = evaluateMonotonicAuthority(activeCapsuleAllowingNoUnknowns,
    [activeLeaseAllowingNoUnknowns],
    { tool: "read", capabilities: ["unknown"], effects: ["data.observe"] },
    fixedNow);
  assert.equal(result.allowed, false);
});

test("narrowing cannot broaden", () => {
  for (const vector of finiteAuthorityVectors) {
    const wide = evaluate(vector.capsule, vector.leases, vector.request);
    const narrow = evaluate(vector.narrowedCapsule, vector.narrowedLeases, vector.request);
    assert.equal(narrow.allowed && !wide.allowed, false);
  }
});

test("malformed registry normalizer quarantines", async () => {
  const registry = persistentRegistry();
  registry.observeToolsList(hostileNormalizerToolsList);
  assert.equal(registry.isQuarantined("fetch"), true);
});

test("canonical equivalents have identical authority", () => {
  assert.equal(decide({ b: 2, a: 1 }), decide({ a: 1, b: 2 }));
});
```

Minimum vectors:

| Vector | Mutation | Expected |
|---|---|---|
| V01 | Proposed capsule instead of active | BLOCK |
| V02 | Expired/revoked capsule or lease | BLOCK |
| V03 | Parent lease child adds capability/effect/path/domain/recipient | ISSUE BLOCK; evaluation never ALLOW |
| V04 | Child expiry/calls/bytes greater than parent | ISSUE BLOCK |
| V05 | Lease chain reordered, duplicated, or depth 17 | BLOCK |
| V06 | Request has unknown capability/effect/resource/address | BLOCK |
| V07 | Schema adds a dangerous required field or broadens additional properties | QUARANTINE |
| V08 | Normalizer field type, pointer, access, or method pointer is unknown | QUARANTINE |
| V09 | Approval argument/session/protocol/schema/registry mutation | BLOCK |
| V10 | Same approval consumed twice concurrently | exactly one forward |
| V11 | Secret result exact/Base64/Base64URL/URL-encoded/JSON/query form to external sink | BLOCK |
| V12 | Secret result hash/paraphrase/unsupported transformation | BLOCK or explicit documented unsupported state, never silent ALLOW |
| V13 | Hostile same-host redirect or DNS address changes to private/link-local | BLOCK |
| V14 | `sandbox: "none"` presented as network denied | UNSUPPORTED or network unknown |
| V15 | Receipt row, order, signature, key ID, or chain head mutation | startup/readiness BLOCK |

## Bounded model-checking plan

The state space is finite for a useful safety check:

* `tools`: 2 values (`read`, `send`), capabilities/effects: one known safe, one dangerous, one `unknown`;
* resources: one project path, one protected path, one public URL, one private/link-local URL, one unresolved URL, one recipient;
* data: public, secret, and one tainted source; sessions `s1` and `s2`;
* authority states: proposed, active, expired, revoked, malformed; lease depth `0..17`; calls `0..2`;
* schema mutations: unchanged, added dangerous field, removed field, broadened `additionalProperties`, changed normalizer, unknown field type;
* approval states: absent, pending, approved, rejected, consumed, expired, invalidated;
* transport states: stdio, HTTP POST, local SSE, upstream JSON, upstream SSE, timeout, mismatched response, redirect;
* containment states: enforced, unsupported, none, timeout, output bound.

For each generated state:

1. Build the canonical action and all component snapshots.
2. Compute the reference decision from the six-set intersection and fail-closed rules.
3. Invoke the real `InvocationGate` or `evaluateMonotonicAuthority` with an injected fixed clock.
4. Assert equivalence of verdict, reason class, effective digest inputs, forwarded argument set, and side-effect count.
5. Mutate exactly one component and assert the result is either unchanged or narrower. Any broadening is a counterexample.
6. For transport runs, use only in-process fake forwarding and loopback sinks. Do not use public endpoints, real secrets, Docker, or persistent temp artifacts.

The bounded depth of 17 deliberately exercises the depth-16 boundary. A run is evidence only if it reports the vector count, all counterexamples, process exit code 0, and clean shutdown. A passing ordinary unit suite is not a substitute for this model check.

## Limitations

* This document defines the target calculus and test plan; it does not alter the source or add property tests because the task forbids source/test changes.
* Current tests executed for this revision: `pnpm test` passed 322/322; `pnpm typecheck` and `pnpm build` passed; the bounded property, fuzz, chaos, security, authority, transport, and API suites passed. These results are local evidence, not proof of every production or external-deployment vector in the calculus above.
* The hostile normalizer and explicit-unknown probes were local, in-memory, read-only reproductions. They did not contact a public service or use real secrets.
* No DNS-rebinding, public-network, Docker, dependency-audit, clean-install, or cross-process crash test was run. Those claims are NOT PROVEN in this audit.
* The current source has no `test/stdio.test.ts`; existing certification references to that path are false evidence pointers even though stdio behavior is exercised from `test/readiness.test.ts`.
* `scripts/certify.ts` now performs a bounded repository-scoped high-confidence scan and reports scanned-file counts. It does not provide a complete dependency, SBOM, or production secret-management audit.
* `FINAL_HACKATHON_CERTIFICATION.md:28` reports 116 tests; that historical claim is stale and FALSE as a current count.
* `HACKATHON_READINESS_REAUDIT.md:34` describes a `chain_head` table, while current code stores `chain-head.json` (`src/storage/store.ts:54,127-128`). The table claim is FALSE for this tree.
