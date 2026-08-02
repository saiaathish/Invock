# Double release rehearsal

Run the bounded clean-state release rehearsal with:

```bash
pnpm release:rehearsal
```

The command creates two independent temporary project copies. Each copy gets a
new empty pnpm store, a frozen install, an isolated Git index for the existing
certification scanner, fresh state/receipt/key directories, and an ephemeral
loopback API port. It runs the local test, typecheck, build, certification,
demo-certification, judge-certification, and CLI evidence checks in each copy.

Temporary copies and stores are removed strictly after the run. A removal
failure is an error and is reported with the rehearsal failure; cleanup is not
silently converted into success.

The report is evidence for these two local rehearsals only. Docker and browser
evidence are intentionally reported as `not-run`; this command does not claim
containment or accessibility proof.
