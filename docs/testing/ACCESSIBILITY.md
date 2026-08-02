# Dashboard browser accessibility evidence

The dashboard is an inline HTML page served by `startApi()` at `/`. The
certification command starts that real loopback API, launches a real Chromium
browser through Playwright, navigates to the served page, enters the real
dashboard token, calls the real `/api/v1/activity` and `/api/v1/approvals`
endpoints, and checks the resulting state change.

```sh
pnpm accessibility:certify
# machine-readable report
pnpm exec playwright install chromium # once per machine
NODE_NO_WARNINGS=1 pnpm --silent accessibility:certify -- --json
```

The command writes its JSON report and three screenshots (desktop initial,
desktop loaded, and mobile loaded) to a new directory under the operating
system temporary directory, never to the repository. It reports the exact
paths. Output is not a WCAG compliance claim.

Evidence covered by the current runner:

- served-page identity, non-blank content, and framework-overlay absence;
- semantic language/headings, labelled token input, button name, and table
  headers;
- keyboard focus reaching the token control and a visible browser focus
  indicator;
- measured body and secondary-text color contrast;
- a real token-entry/Load interaction with HTTP 200 responses and the visible
  empty approvals state;
- 390px responsive rendering, screenshot evidence, console/page errors, and
  failed requests.

The command deliberately reports `NOT_PROVEN` and exits nonzero when the
served page lacks a live status region for asynchronous state or a
`prefers-reduced-motion` rule. Those are findings, not hidden skips. If
Playwright or its Chromium runtime cannot launch, the command reports
`UNSUPPORTED` and exits with status 2; it never converts a static source check
into a browser PASS.

In this environment the in-app Browser plugin was not callable, so the report
identifies the path as `regular-playwright` and records the Browser-plugin
absence. The Playwright fallback was used only after that classification.
