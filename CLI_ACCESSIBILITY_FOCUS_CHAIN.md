# Invock CLI Accessibility Focus Chain

## Stage 1 — CLI Foundation

- [ ] Global binary contract implemented
- [ ] `invock` works
- [ ] `invock help` works
- [ ] `invock --help` works
- [ ] `invock --version` works
- [ ] `invock init` works
- [ ] `invock doctor` works
- [ ] `invock doctor --json` works
- [ ] `invock status` works
- [ ] Initialization is idempotent
- [ ] Runtime files have safe permissions
- [ ] Stage 1 tests pass
- [ ] Full existing suite remains green

## Stage 2 — Claude Code

- [ ] Claude Code detection implemented
- [ ] Claude Code version detection implemented
- [ ] Claude configuration discovery implemented
- [ ] Claude configuration backup implemented
- [ ] `invock install claude` works
- [ ] `invock wrap claude` works
- [ ] `invock verify claude` works
- [ ] `invock unwrap claude` works
- [ ] Allowed invocation reaches the real Invock gate
- [ ] Blocked invocation reaches zero upstream executions
- [ ] Original Claude configuration restores exactly
- [ ] Stage 2 tests pass
- [ ] Full existing suite remains green

## Stage 3 — Codex

- [ ] Codex detection implemented
- [ ] Codex version detection implemented
- [ ] Codex configuration discovery implemented
- [ ] Codex configuration backup implemented
- [ ] `invock install codex` works
- [ ] `invock wrap codex` works
- [ ] `invock verify codex` works
- [ ] `invock unwrap codex` works
- [ ] Allowed invocation reaches the real Invock gate
- [ ] Blocked invocation reaches zero upstream executions
- [ ] Original Codex configuration restores exactly
- [ ] Stage 3 tests pass
- [ ] Full existing suite remains green

## Stage 4 — Cursor

- [ ] Cursor detection implemented
- [ ] Cursor version detection implemented
- [ ] Cursor configuration discovery implemented
- [ ] Cursor configuration backup implemented
- [ ] `invock install cursor` works
- [ ] `invock verify cursor` works
- [ ] `invock uninstall cursor` works
- [ ] Cursor traffic can use the Invock proxy
- [ ] Allowed invocation reaches the real Invock gate
- [ ] Blocked invocation reaches zero upstream executions
- [ ] Original Cursor configuration restores exactly
- [ ] Stage 4 tests pass
- [ ] Full existing suite remains green

## Stage 5 — Proof Experience

- [ ] `invock proxy` works
- [ ] `invock stats` works
- [ ] `invock stats --json` works
- [ ] `invock dashboard` works
- [ ] `invock dashboard --no-open` works
- [ ] `invock demo` works
- [ ] Stats come from real runtime metadata
- [ ] Dashboard uses real runtime state
- [ ] Demo uses synthetic data only
- [ ] Benign action succeeds
- [ ] Malicious action is blocked
- [ ] Unauthorized upstream executions equal zero
- [ ] Secret sink calls equal zero
- [ ] Signed receipt verifies
- [ ] Tampered receipt is rejected
- [ ] Stage 5 tests pass
- [ ] Full existing suite remains green

## Stage 6 — Packaging and Clean Install

- [ ] npm package name is correct
- [ ] npm `bin` mapping is correct
- [ ] Package files are correct
- [ ] `npm pack` succeeds
- [ ] Global tarball install succeeds
- [ ] Clean temporary HOME test succeeds
- [ ] No repository-relative path assumptions remain
- [ ] No absolute developer paths remain
- [ ] Installation smoke test passes
- [ ] Uninstall restores configuration
- [ ] Package contents contain no secrets
- [ ] Package contents contain no runtime databases
- [ ] Package contents contain no private keys
- [ ] Stage 6 tests pass
- [ ] Final CLI certification passes
- [ ] Full existing suite remains green
- [ ] `git diff --check` passes
