# Design-partner guide

## Purpose and guardrails

Validate whether Invock’s current local MCP mediation boundary solves a real review problem. Use only synthetic data and loopback sinks (`SECURITY.md:19-20`). Do not claim production readiness, customer validation, or enterprise control coverage without evidence.

## 30-minute discovery guide

**0–5:** identify workflow, roles, and one concrete unsafe/audited-call problem.<br>
**5–10:** map tools, effects, schemas, transport, and current review process.<br>
**10–15:** confirm current support: newline-delimited stdio and authenticated loopback-by-default HTTP POST; explicitly reject unsupported GET/SSE, DNS pinning, OS/container sandboxing, and honest-upstream proof (`SECURITY.md:7-17`).<br>
**15–22:** run safe/attack demo and inspect CLI paths (`src/cli.ts:14-24`).<br>
**22–27:** agree pilot fixtures, owners, baseline, and metrics.<br>
**27–30:** confirm next action, evidence owner, and exit criteria.

## Readiness checklist

- [ ] Supported transport selected.
- [ ] Synthetic data and loopback sink approved.
- [ ] Tool schemas/descriptors and policy owner available.
- [ ] Local database/key-directory owner assigned.
- [ ] Baseline and target metrics recorded.
- [ ] Unsupported requirements written down as blockers or roadmap.

## Pilot metrics

Track mediated-call coverage; ALLOW/BLOCK/APPROVAL_REQUIRED counts; approval expiry/replay rejections; drift quarantines; receipt verification results; setup time; and reviewer time per decision. These metrics are proposed and have no current partner values.

## Deployment architecture

`MCP client → Invock local stdio proxy → upstream MCP command`, with local SQLite and signing-key storage; or authenticated loopback HTTP POST through the same gate and local dashboard/API (`src/gateway/stdio.ts:30-37`; `src/cli.ts:47-50`). Public deployment and unsupported HTTP GET/SSE lifecycle are not evidenced.

## Risk register

| Risk | Status | Action |
|---|---|---|
| Transport mismatch | Current boundary is narrow | Stop or narrow pilot |
| Secret/public exfiltration | Explicitly prohibited for demos | Synthetic data and loopback only |
| Upstream honesty | Not proven by Invock | Separate upstream assurance |
| Key/database lifecycle | Configurable but partner process not evidenced | Assign owner and document handling |
| Enterprise controls | Roadmap/unsupported | Label gap; do not sell as present |

## Integration worksheet

```text
Partner/workflow (no customer name in repository docs):
Client/server and version:
Transport:
Tools and schemas:
Policy owner:
Approval owner / TTL:
Database and key-directory owner:
Synthetic fixture and loopback sink:
Baseline / target:
Unsupported requirements:
Evidence location:
```

## Feedback template

```text
Role and date:
Workflow / transport:
What should have happened:
What happened:
Receipt IDs / verification result:
False positive or missed risk:
Onboarding blocker:
Most valuable evidence:
Requested change (mark NOT PROVEN until implemented and tested):
Continue pilot? Why?
```

## Exit criteria

The pilot exits successfully only after executed representative safe, blocked, and approval-required cases; receipt verification; recorded setup and reviewer-time metrics; documented boundary acceptance; and a written decision on continuation. A build, README claim, or demo output alone is not sufficient evidence.
