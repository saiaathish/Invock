# Invock five-minute local judge demo

This script is a design for a truthful judge mode. It uses only local processes, fake values, and loopback sinks. It never contacts a public exfiltration target and never uses a real credential.

## Prerequisites and truth labels

- Node `>=22.5.0` and the repository's installed pnpm dependencies: `IMPLEMENTED` prerequisite from `package.json`.
- Clean checkout or a recorded revision: required for reproducibility.
- `pnpm build`: `IMPLEMENTED`, executed for this handoff with exit 0.
- `pnpm test`: `IMPLEMENTED`, executed for this handoff with 291 passed, 0 failed, 0 skipped.
- `pnpm judge:certify`: `IMPLEMENTED` automated fake-data flow; it reports safe ALLOW, blocked attack, signed evidence, cleanup, and an honest `degraded` containment/browser status.

Use these fake values only: `FAKE_SECRET_123`, `http://127.0.0.1:<local-port>/sink`, and a disposable local database path. Never paste a real token into the terminal or dashboard.

## Five-minute flow

### 0:00-0:40, orient the judge

Say: “Invock judges visible MCP tool calls before forwarding. It can allow, require an exact one-time approval, or block. It does not claim to control hidden behavior inside an upstream server.”

Point to the boundary in `README.md` and `SECURITY.md`. Do not say “prevents exfiltration” without adding “at the visible mediation boundary.”

### 0:40-1:10, prove the current safe path

Run:

```sh
pnpm demo:safe
```

Expected current output includes `"decision": "ALLOW"` and `"message": "Would forward to upstream server"`. This is an in-memory gate decision. It is not proof that a real upstream server was contacted.

Checkpoint A: record the command, revision, exit code 0, and the exact output. Label the checkpoint `IMPLEMENTED / CLI / in-memory`.

### 1:10-1:45, prove the current blocked path

Run:

```sh
pnpm demo:attack
```

Expected current output includes `"verdict": "BLOCK"`, `"reasonCodes": ["PATH_PROTECTED"]`, and a receipt ID. The receipt ID is run-specific. Do not present it as a stable fixture identifier.

Checkpoint B: say “the protected `.env` path is blocked before a forward outcome.” Do not call this single CLI command a general exfiltration proof; the separate fake-only sink result is reported by `pnpm judge:certify`.

### 1:45-2:30, show the real dashboard surface

Run in a terminal that can be stopped with Ctrl-C:

```sh
pnpm invock serve --database .invock/judge.sqlite --key-directory .invock/judge-keys
```

Open the printed `http://127.0.0.1:<port>` URL and enter the printed token. The current page has token entry, Activity, and Approvals sections. The API source also has authenticated routes for ready, tools, expansions, policies, receipts, receipt lookup, approve, and reject.

Checkpoint C: show only redacted fields. The scoped browser runner passes keyboard focus, contrast, responsive, live-status, reduced-motion, and interaction checks; say `NOT PROVEN` for broad WCAG or screen-reader certification.

### 2:30-3:30, explain authority and approval

Use the existing authority tests as evidence, or the future fixture when available. The sequence is:

1. Create a capsule: status `PROPOSED`.
2. Activate it: status `ACTIVE`.
3. Issue a lease that is a subset of the capsule.
4. Evaluate an in-scope request: allowed with an effective digest.
5. Evaluate an out-of-scope, expired, revoked, malformed, or exhausted request: denied with reason codes.
6. For a policy approval, show that the exact binding is required, mutation is rejected, and replay is rejected.

Checkpoint D: cite `test/authority/authority.test.ts`, `test/authority-gateway.test.ts`, and `test/security.test.ts`. The dashboard does not currently offer capsule/lease editing, so do not imply that these controls are clickable in the current UI.

### 3:30-4:20, attack flow

`IMPLEMENTED` attack flow: `pnpm demo:attack` blocks a protected path and emits a signed/identified receipt result.

`IMPLEMENTED` stronger local judge flow: `pnpm judge:certify` runs fake-only local fixtures, records safe and blocked outcomes, reports zero sink deliveries for the blocked attack, verifies signed evidence, and cleans up. It does not claim broad accessibility or production containment; the separate scoped browser runner provides its own evidence.

### 4:20-4:45, baseline comparison

`IMPLEMENTED` in the Arena: `pnpm arena` runs the deterministic scenarios through protected, unprotected, and static-allowlist adapters, with repeated outcomes, sink counts, reason codes, and measured local latency. This is not production throughput evidence.

The current `demo:safe` message says “Would forward”; it is not a baseline benchmark and supplies no measured latency. Any claim otherwise is `FALSE`.

### 4:45-5:00, close with limits and cleanup

Say: “Current proof covers visible mediation, local policy/authority decisions, redacted evidence, protected-path blocking, and a scoped browser dashboard run. It does not prove upstream honesty, production key custody, external anchoring, production containment, or broad WCAG/screen-reader accessibility.”

Stop the server with Ctrl-C. Remove only the explicitly created disposable paths after verification:

```sh
rm -rf .invock/judge.sqlite .invock/judge-keys
```

This cleanup is allowed only for the disposable paths created by this script. Verify no server remains and run `git status --short`. Do not delete a pre-existing `.invock` directory.

## Evidence checkpoints

| Checkpoint | Evidence | Current status |
|---|---|---|
| A | `pnpm demo:safe` output and exit code | `IMPLEMENTED` |
| B | `pnpm demo:attack` BLOCK / `PATH_PROTECTED` / receipt ID | `IMPLEMENTED` |
| C | served dashboard and authenticated local API | API/UI source and tests `IMPLEMENTED`; scoped browser runner `PASS`; broad WCAG/screen-reader UX `NOT PROVEN` |
| D | authority, approval, receipt tests | `IMPLEMENTED` test evidence |
| E | fake-secret sink count is zero | `pnpm judge:certify` and Arena protected-path results `IMPLEMENTED` for local fake fixtures |
| F | baseline latency and comparison | Arena protected/unprotected/static measurements `IMPLEMENTED`; production performance `NOT PROVEN` |

## Accessibility run card

Before a judge-mode claim, test the actual page with keyboard only, visible focus, 320px layout, screen reader landmarks/labels, color-plus-text verdicts, contrast measurement, and reduced-motion preference. Save tool/version, URL, revision, and pass/fail. A screenshot can document appearance, but cannot prove keyboard, contrast, or screen-reader behavior by itself.

## Failure and fallback rules

- If build or tests fail, stop and report `BLOCKED`; do not continue to a PASS narrative.
- If the dashboard cannot start, use the CLI checkpoints and label dashboard `NOT PROVEN`.
- If any command wants a real secret, external URL, container, temp database, or unowned fixture, stop and replace it with fake/local inputs.
- If a result differs from the expected output, preserve the output and label the claim `NOT PROVEN` until investigated.
