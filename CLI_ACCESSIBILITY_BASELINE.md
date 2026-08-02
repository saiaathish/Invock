# Invock CLI Accessibility Baseline

## Repository

- Root: `/Users/saiaathishkarthik/Desktop/Invock`
- Branch: `main`
- Commit: `07c8b800c263fd82bf2297551a96773319e11db3`
- Initial Git status: `?? .freebuff/`

## Runtime

- Node: `v22.23.1`
- pnpm: `11.15.1`
- Platform: `Darwin`
- Architecture: `arm64`

## Existing Commands

- Existing CLI: `init`, `scan`, `serve`, `identity`, `demo`, `forge`, `guard`, `contain`, `run`, `certification`, plus existing security commands.

## Existing Package Structure

- Package: `invock@0.1.8`; no `bin` mapping.
- TypeScript source builds to `dist`.

## Existing CLI Structure

- Entry point: `src/cli.ts`.
- Existing `pnpm invock` script runs CLI through `tsx`.

## Existing Runtime Structure

- Canonical `InvocationGate`, SQLite `InvockStore`, loopback API, stdio proxy, authority, containment, evidence, and certification modules.

## Existing Dashboard Structure

- Dashboard/API served by `src/api/server.ts` through the existing `serve` command.

## Baseline Validation

- Frozen install: not separately surfaced; baseline commands ran with existing install.
- Typecheck: PASS
- Tests: PASS — 291 passed, 0 failed, 0 skipped
- Build: PASS
- Certification: PASS — 291 tests, secret scan 195 files / 0 high-confidence findings
- git diff --check: PASS

## Baseline Test Counts

- Passed: 291
- Failed: 0
- Skipped: 0
