# Adversarial verification

This document records the bounded verification added for mandate sections 16.2, 16.4, and 16.7. The suites use deterministic seeded generators and import the existing canonicalization, policy, normalizer, authority, receipt, store, gate, and API interfaces.

## Executed scope

- Property suite: 136 executed cases (64 canonicalization/digest, 32 authority monotonicity and child-lease non-amplification, 16 policy unknown-authority, 24 receipt mutations).
- Fuzz suite: 144 executed cases (18 each for JSON-RPC, tool schemas, nested arguments, policy YAML, URL/path/encoding, receipt payloads, delegation chains, and identity/session boundaries).
- Chaos suite: 11 bounded cases (upstream crash, upstream timeout recording, SQLite lock, corrupt chain head, truncated chain head, restart recovery, duplicate lease replay, truncated body, interrupted client connection, API restart, and signing-material replacement).

Every loop has a fixed case count. Temporary database roots are removed in `finally` blocks. A malformed or uncertain input is rejected, blocked, or reported as an unsupported fault; it is never counted as a successful authorization.

## Deliberate limitations

The current public APIs do not expose a disk-full simulator, migration interruption hook, container lifecycle control, or a real upstream process/network proxy. Those faults are not fabricated by these tests and are not PASS claims. The chaos suite covers the corresponding supported fail/ready boundaries and records the unsupported fault classes here.

## Commands

```sh
pnpm exec node --import tsx --test test/property/**/*.test.ts test/fuzz/**/*.test.ts test/chaos/**/*.test.ts
pnpm exec tsc --noEmit
git diff --check -- test/property test/fuzz test/chaos docs/testing fixtures/testing
```
