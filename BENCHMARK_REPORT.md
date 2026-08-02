# Invock Arena benchmark report

## Reproduction contract

Run from the repository root:

```bash
pnpm arena > /tmp/invock-arena.json
```

The runner uses:

- 18 fixed scenario IDs, in the order exported by `ARENA_SCENARIO_IDS`.
- Seed `20260801`.
- Three repetitions per scenario.
- 54 raw scenario records, each containing protected, unprotected, and
  static-allowlist path results.
- A real `InvocationGate` call for every protected result.
- A bounded local upstream callback and an explicit static allowlist for the
  two baselines.

The output JSON is the primary result artifact. Its `deterministicDigest`
excludes wall-clock latency and host metadata, while retaining scenario order,
seed, repetitions, path statuses, raw deterministic observations, and measured
count metrics.

## Reported measurements

For each path, `measurements` reports:

- attack success rate and attack block rate;
- benign completion rate;
- false-positive and false-negative rates;
- unauthorized upstream calls;
- secret sink calls;
- approval replay rate when the approval attack has a replay attempt;
- quarantine and containment-denial measurements when an adapter supplies
  them;
- decision and end-to-end latency statistics: mean, median, p95, p99, and
  standard deviation;
- throughput derived from the observed bounded invocation time.

Every raw result has a support status. `unknown` means the operation ran but
the requested fact could not be established. `unsupported` means that adapter
does not implement that measurement. Neither status is silently treated as a
successful block or a zero-cost operation.

## Current local evidence

The executable runner and Arena tests establish the following shape on the
current checkout:

| Check | Evidence |
| --- | --- |
| Scenario coverage | 18 IDs are emitted in stable order |
| Repetition coverage | 3 fixed-seed repetitions per ID |
| Raw result count | 54 records, three named paths per record |
| Protected execution | Calls the existing `InvocationGate` |
| Baseline separation | `unprotected` and `staticAllowlist` are distinct fields and adapters |
| Cleanup | Per-invocation markers are removed and `cleanupCompleted` is reported |
| Claims | Unknown and unsupported measurements stay labeled |

Re-run the command to obtain host-specific rates and latency values. Those
values are local observations, not production performance claims. The runner
does not contact public targets, execute attacker-supplied shell text, or
write to a production database.

## Research limitations

This is a serious executable benchmark artifact, not a declaration that the
whole Invock product transformation is complete. The local benchmark does not
by itself prove container runtime containment, production deployment, full
18-group external-world realism, property/fuzz/chaos/accessibility coverage,
confidence intervals for every metric, or independent release audits. The
final product verdict must continue to label those gates separately.
