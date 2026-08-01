# Mutation adequacy review

Command: `pnpm mutation-review`

The harness creates an isolated temporary source copy, applies one critical mutation, runs the focused regression test, and requires a non-zero exit. It removes the temporary copy after each case.

| Mutation | Focused test | Result |
|---|---|---|
| Disable cross-host redirect denial | `test/net.test.ts` | KILLED |
| Disable lease tool-boundary enforcement | `test/authority/authority.test.ts` | KILLED |
| Bypass Arena execution adapter | `test/arena/arena.test.ts` | KILLED |

Result: 3/3 targeted critical mutations killed. This is targeted adequacy evidence, not a claim of exhaustive mutation coverage for every source line.
