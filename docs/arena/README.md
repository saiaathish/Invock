# Invock Arena

Arena is a local, reproducible benchmark harness for invocation-security
behavior. The checked-in runner executes the 18 research groups required by
Pillar 9 of the product mandate, three times each, using seed `20260801`.

## Execution paths

Every scenario/repetition produces three separately named results:

1. `protected`: the scenario callback prepares a bounded operation and the
   adapter authorizes it through the real `InvocationGate`.
2. `unprotected`: a bounded local upstream stub receives the same prepared
   operation without Invock authorization. It performs only local reads,
   parsing, and counters. It never contacts a public network, executes an
   attacker command, or mutates a production database.
3. `static-allowlist`: an explicit exact-tool/path allowlist admits only the
   benign `read` fixture under `fixtures/arena`. It is not reported as Invock.

The legacy `baselineOutcome` and `unprotectedOutcome` fields remain aliases
for the unprotected path. New consumers should use the typed `protected`,
`unprotected`, and `staticAllowlist` path objects.

## Scenario IDs

The stable order is exported as `ARENA_SCENARIO_IDS`:

| ID | Research group | Bounded operation |
| --- | --- | --- |
| `prompt-injection` | Indirect prompt injection | Read a fixture labeled untrusted content |
| `secret-exfiltration` | Secret exfiltration | Send a secret-shaped payload to an external recipient |
| `encoding-exfiltration` | Encoding-based exfiltration | Send an encoded secret-shaped payload externally |
| `path-escape` | Path escape | Read a path that resolves outside the fixture root |
| `command-injection` | Command injection | Submit a shell string containing metacharacters |
| `sql-mutation` | SQL mutation | Submit a bounded update statement to the local stub |
| `ssrf` | SSRF | Address a loopback URL without opening a socket |
| `approval-attacks` | Approval attacks | Consume an approval and replay the exact request |
| `protocol-attacks` | Protocol attacks | Add an unmodeled protocol metadata field |
| `tool-poisoning` | Tool poisoning | Call an unknown tool descriptor |
| `schema-drift` | Schema drift | Add an argument outside the declared schema |
| `delegation-escalation` | Delegation escalation | Use a read-only lease for a process operation |
| `cross-session-leakage` | Cross-session leakage | Use a lease bound to another session |
| `malicious-local-server` | Malicious local server behavior | Address a loopback redirect-shaped URL |
| `receipt-tampering` | Receipt tampering | Modify an isolated receipt row and re-authorize |
| `identity-misuse` | Identity misuse | Supply forged identity evidence digests |
| `policy-regression` | Policy regression | Request a protected path through the policy |
| `benign-workflow` | Benign developer workflow | Read the public fixture |

Each callback creates and removes a per-invocation marker. Cleanup failures
are recorded as benchmark failures rather than silently ignored.

## Running and consuming results

```bash
pnpm arena
```

The command emits one JSON document on stdout. It contains the fixed seed,
repetition count, ordered scenario IDs, environment metadata, raw per-path
outcomes, aggregate rates, and latency statistics. To save raw evidence for a
local run, redirect stdout to a file outside the source tree or to a
reviewed benchmark artifact.

Latency uses the monotonic JavaScript clock and reports count, mean, median,
nearest-rank p95, nearest-rank p99, and population standard deviation. A
metric is `measured`, `unknown`, or `unsupported`; unsupported measurements are
not converted into zeroes or passing claims.

## Evidence boundary

The runner is local research evidence. It proves that these bounded callbacks
and the selected local `InvocationGate` path execute and produce measured
results on the current host. It does not prove production throughput,
container containment, multi-host behavior, full fuzz/property/chaos or
accessibility coverage, or completion of every product-mandate release gate.
Those claims require their own direct evidence and must not be inferred from a
green Arena run.
