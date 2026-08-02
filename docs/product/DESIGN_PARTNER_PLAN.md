# Design-partner plan

## Hypothesis

**Product hypothesis:** one integration owner and one security reviewer can validate Invock on a non-production or synthetic-data MCP workflow, using the current stdio or authenticated loopback HTTP POST boundary.

**Market research:** NOT PROVEN. No customers, interviews, or external sources are in the repository.

## Ideal partner profile

- **Developer buyer/champion:** owns an MCP client/server integration and can run local commands (`src/cli.ts:20-24`).
- **Security buyer/influencer:** needs decision and receipt evidence; signed receipts and approvals are implemented (`IMPLEMENTATION_STATUS.md:12-16`).
- **Economic buyer:** NOT PROVEN; identify the budget owner during discovery.
- **Disqualifier:** requires unsupported GET/SSE lifecycle, DNS pinning, OS/container sandboxing, or honest-upstream proof (`SECURITY.md:10-17`).

## Pilot shape

Use synthetic or fake data and loopback sinks only, as required by `SECURITY.md:19-20`. Start with one integration, 3–5 representative tools, and a short review window. Do not claim customer validation until the partner supplies written evidence.

## 30-minute discovery guide

1. **0–5 min — context:** What MCP workflow is in scope? What may be synthetic? Who owns integration, security review, and budget?
2. **5–10 min — failure:** Which calls require blocking, approval, or audit evidence? Ask for one concrete recent review example.
3. **10–15 min — boundary:** Confirm stdio or authenticated loopback HTTP POST. Read the unsupported list aloud; record any required contradiction as a blocker.
4. **15–22 min — walkthrough:** Show `demo safe|attack`, `serve --stdio`, `doctor`, and `receipts verify` from `src/cli.ts:14-24`.
5. **22–27 min — pilot design:** Select tools, policy owner, synthetic fixtures, baseline, and review cadence.
6. **27–30 min — commitment:** Agree metrics, exit criteria, evidence owner, and next date. Do not record a PASS without executed evidence.

## Readiness checklist

- [ ] Synthetic data and loopback sink confirmed.
- [ ] One supported transport selected.
- [ ] Tool schemas/descriptors available for the selected calls.
- [ ] Policy and approval owner named.
- [ ] Database/key-directory ownership and retention agreed.
- [ ] Baseline counts and review time captured.
- [ ] Unsupported requirements recorded as gaps, not silently accepted.

## Pilot metrics

Measure before and during the pilot: percentage of in-scope calls mediated; BLOCK, APPROVAL_REQUIRED, and forwarded counts; approval replay/expiry rejection count; schema-drift quarantine count; receipt verification success/failure; median reviewer time per decision; and integration setup time. These are proposed metrics, not repository outcomes.

## Deployment architecture

Current evidenced shape: MCP client → local Invock stdio proxy → upstream MCP command, with local SQLite storage and signing-key directory; alternatively, authenticated loopback-by-default Streamable HTTP POST mediation and local dashboard/API (`src/cli.ts:47-50`; `src/gateway/stdio.ts:30-37`; `SECURITY.md:7-8`). GET/SSE lifecycle, public exposure, and OS/container sandboxing are out of scope.

## Risk register

| Risk | Evidence/status | Mitigation |
|---|---|---|
| Unsupported transport required | Explicitly unsupported (`SECURITY.md:10-13`) | Stop pilot or narrow workflow |
| Upstream behaves dishonestly after allow | Explicit limitation (`SECURITY.md:15-17`) | Use trusted synthetic fixtures and separate assurance |
| Key/database operations unclear | Local paths are CLI-configurable (`src/cli.ts:26-28`) | Document owner, backup, and rotation before pilot |
| Policy overblocks or underblocks | No customer baseline; NOT PROVEN | Compare fixture outcomes and review every decision |
| Enterprise controls expected | Roadmap includes anchoring/SBOM/provenance (`IMPLEMENTATION_STATUS.md:29-31`) | Treat as roadmap, not current capability |

## Integration worksheet

| Field | Record |
|---|---|
| Client/server and version | |
| Transport | stdio / authenticated loopback HTTP POST |
| Tool names and schemas | |
| Sensitive effects to block | |
| Approval owner and TTL | |
| Database/key-directory owner | |
| Synthetic fixture/sink | |
| Baseline and target metrics | |
| Unsupported needs | |

## Feedback template

```text
Date / participant role:
Workflow and transport:
Expected safe behavior:
Observed behavior and receipt IDs:
False blocks / missed blocks:
Setup friction:
Evidence that changed confidence:
Missing capability (mark NOT PROVEN until evidenced):
Priority and rationale:
```

## Exit criteria

Exit only when the partner has executed the agreed workflow, reviewed representative allow/block/approval results, verified receipt integrity, documented setup time and decision-review time, and either accepts the supported boundary or records concrete gaps. A successful build or demo alone is insufficient.
