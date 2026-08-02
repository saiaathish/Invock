# Contributing

1. Use Node `>=22.5.0` and pnpm `11.15.1`.
2. Preserve fail-closed behavior and do not weaken existing tests.
3. Keep security-sensitive changes narrowly scoped and add a regression test.
4. Run `pnpm typecheck`, `pnpm test`, `pnpm build`, and `git diff --check` before proposing a change.
5. Use fake secrets and loopback fixtures; never add real credentials or public exfiltration targets.
6. Label unsupported, unproven, and historical evidence explicitly. A passing local test is not a production claim.

Pull requests should describe the threat boundary, files changed, commands run, remaining limitations, and any required deployment-specific evidence.
