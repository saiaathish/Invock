# Prior-art and standards review

## Scope

This review positions the repository's execution-trust thesis against primary-source standards, academic/security foundations, and product documentation. It is not a patentability opinion, exhaustive literature review, market-sizing study, or legal novelty determination.

The repository describes Invock as a deterministic MCP invocation authorization layer and, more narrowly, a local reference monitor for newline-delimited stdio and authenticated Streamable HTTP POST mediation. The review therefore compares the following claimed design themes: mediation before tool execution, canonical request/policy evaluation, capability-like authority capsules and leases, encoded-flow lineage, signed/hash-chained receipts, policy-as-code, optional containment, and principal/session identity.

The separately requested “pasted transformation specification” was not present as a distinct input in the working tree or user message. Repository README, SECURITY.md, implementation-status material, source exports, and tests were used instead. That absence is a research gap, not an assumption about the intended specification.

## Search method

Search date and access date: 2026-08-01. Repository inspection used `rg --files`, targeted `rg -n`, `sed`, `nl`, `git status --short`, and `pnpm build`. External research was restricted to official specifications, standards bodies, official project documentation, and directly hosted papers. Each source URL below was fetched with `curl -L --fail`; successful HTTP validation is recorded in the evidence column.

The search was deliberately bounded: MCP authorization/security guidance; OAuth resource indicators; reference monitors; capability security; provenance/lineage; sandboxing; signed evidence; policy-as-code; workload identity; and official MCP gateway/product documentation. It did not search patent databases, subscription indexes, unpublished vendor material, or every paper using “execution trust,” “agent firewall,” or “tool governance.” No interviews, telemetry, customer counts, or market-share claims were used.

## Primary-source table

| Source | Primary-source proposition | Relevance to Invock | Evidence / access date | Boundary |
|---|---|---|---|---|
| [MCP Authorization, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | MCP authorization uses OAuth concepts including protected resource metadata, authorization-server discovery, bearer-token use, and resource/audience binding. | Establishes protocol-level authorization and audience concerns around MCP; it does not define deterministic tool-argument policy, lineage, or signed receipts. | URL returned HTTP 200 on 2026-08-01. | Standard guidance, not proof of Invock or of novelty. |
| [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) | Calls out confused-deputy risks, token passthrough, SSRF, session hijacking, and local-server security considerations. | Directly frames transport and delegation threats that Invock claims to mediate or record. | URL returned HTTP 200 and redirected to the official MCP docs on 2026-08-01. | Guidance is broader than the repository’s implemented boundary. |
| [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707) | Defines a `resource` parameter to bind an access token to a protected resource/audience. | Prior art for audience/resource binding; an Invock server/tool/session binding is an application-specific composition, not a new authorization primitive by itself. | RFC Editor URL/info endpoint returned HTTP 200 on 2026-08-01. | OAuth token scope does not establish tool-call semantic authorization. |
| [NIST Reference Monitor glossary](https://csrc.nist.gov/glossary/term/reference_monitor) | Defines the reference-monitor concept as an access-control mechanism with mediation and protection requirements. | Supplies the correct security vocabulary for “before execution” mediation. | NIST URL returned HTTP 200 on 2026-08-01. | A label is not a certification that the implementation satisfies every reference-monitor property. |
| Miller, Yee, Shapiro, “Capability Myths Demolished” (2003), stable bibliographic citation | Describes object-capability security and authority conveyed by unforgeable references rather than ambient authority. | Closest conceptual prior art for least-authority, delegation, attenuation, and authority-bearing references. | Paper title/authors/year consulted 2026-08-01; the candidate E-language page was not network-validated in this run. | Invock’s JSON/digest capsule and lease model must not be called a novel capability system without formal comparison. |
| [W3C PROV Overview](https://www.w3.org/TR/prov-overview/) | Defines provenance concepts and relations among entities, activities, and agents. | Provides standards vocabulary for execution lineage and evidence graphs. | W3C URL returned HTTP 200 on 2026-08-01. | PROV is a provenance data model, not an authorization gate or tamper-proof log. |
| [gVisor Architecture Guide](https://gvisor.dev/docs/architecture_guide/) | Describes a user-space kernel boundary intended to isolate workloads and mediate system calls. | Important comparison for sandboxing: process/OS isolation is separate from semantic authorization and receipt evidence. | Official gVisor URL returned HTTP 200 on 2026-08-01. | SECURITY.md explicitly says OS/container sandboxing is outside Invock’s supported boundary. |
| [Open Policy Agent documentation](https://www.openpolicyagent.org/docs) | Presents policy-as-code and decoupled policy decision-making over structured input. | Direct prior art for declarative policy evaluation; Invock’s MCP envelope and fail-closed resource facts are integration choices. | OPA URL returned HTTP 200 on 2026-08-01. | Policy-as-code itself is established; no novelty follows from using YAML or deny-overrides. |
| [SPIFFE overview](https://spiffe.io/docs/latest/spiffe-about/overview/) | Defines workload identity, attestation, and verifiable identity documents such as SVIDs. | Prior art for agent/workload identity and identity-to-authority binding. | SPIFFE URL returned HTTP 200 on 2026-08-01. | Repository principal/session fields are not equivalent to SPIFFE attestation. |
| [Docker MCP Gateway documentation](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/) | Documents a gateway pattern for connecting MCP clients to MCP servers, with Docker-managed tool/server execution context. | Product-level adjacent prior art for centralized MCP routing and containment-oriented deployment. | Docker URL returned HTTP 200 on 2026-08-01. | Product documentation does not establish identical semantics, security proof, or market share. |
| [Cloudflare MCP documentation](https://developers.cloudflare.com/agents/model-context-protocol/) | Documents Cloudflare’s MCP/Agents integrations and deployment patterns at the network/platform edge. | Product-level adjacent prior art for hosted MCP connectivity and platform controls. | Cloudflare URL returned HTTP 200 on 2026-08-01. | Network/platform integration is not the same as local deterministic pre-execution authorization. |

## Standards map

| Area | Established prior art / standard | What Invock appears to add or compose | Claim discipline |
|---|---|---|---|
| MCP authorization | MCP authorization spec; OAuth resource/audience binding in RFC 8707 | Local policy evaluation around a normalized `tools/call` envelope, with protocol/session metadata attached to evidence. | Fact about repository composition; not novel protocol authorization. |
| Agent/tool authorization | MCP security guidance, OAuth, reference-monitor model | Tool, capability, effect, resource, data-label, budget, and approval checks in one gate. | Hypothesis for differentiation; requires independent end-to-end bypass testing. |
| Capability systems | Object-capability literature and attenuation/delegation practice | `IntentCapsule` and `CapabilityLease` types with digests, expiry, budgets, and subset checks. | Fact that code exists; formal capability-system novelty is unproven. |
| Reference monitors | NIST definition; classic access-control literature | A single `InvocationGate.authorizeInvocation` API is intended as the mediation point. | Repository comments say “non-bypassable,” but that property needs transport-complete proof. |
| Taint / lineage | Dynamic taint analysis and W3C PROV are established foundations | HMAC fingerprints for exact/base64/base64url/urlencoded values and receipt fields for invocation lineage. | Fact about implementation; semantic transformation coverage and general provenance claims are unproven. |
| Sandboxing | gVisor and container/OS isolation systems | A containment module can report required/available sandbox status and bounded execution. | SECURITY.md says OS/container sandboxing is not supported in the hackathon boundary; do not claim Invock itself is a sandbox. |
| Signed audit evidence | Digital signatures, hash chains, and provenance systems are established primitives | Ed25519 receipt signatures, SHA-256 previous-hash chaining, and signed chain heads in source. | Fact about code; external anchoring, independent key custody, and evidentiary sufficiency are unproven. |
| Policy-as-code | OPA and Cedar-style policy engines | Invock policy compilation evaluates MCP-specific normalized facts and reason codes. | Product differentiation may be credible; policy-as-code novelty is false. |
| Agent identity | SPIFFE/SVID and OAuth identity models | Principal, client, session, server, approval, capsule, and lease fields are included in the local model. | Identity-field presence is fact; cryptographic workload attestation or global agent identity is not proven. |

## Product landscape

The following are adjacent documented products, not a ranked competitor list. Official documentation was used only to establish the documented product surface.

| Product/documented pattern | Overlap | Distinguishing axis for Invock | What remains unknown |
|---|---|---|---|
| Docker MCP Gateway | MCP client/server gateway and managed execution context. | Invock’s thesis is deterministic, local, semantic pre-execution authorization plus receipts; Docker documentation alone does not establish those exact properties. | Relative adoption, performance, bypass resistance, and feature parity were not researched. |
| Cloudflare MCP / Agents platform | Hosted MCP connectivity and edge/platform controls. | Invock targets a local mediation boundary and explicit action envelope rather than a general hosted platform. | Cloudflare’s complete internal authorization and audit implementation is not inferable from public product pages. |
| OPA policy-as-code | Declarative authorization separated from application code. | Invock couples policy input to MCP tool descriptors, normalized resources, lineage, approvals, and receipt fields. | No benchmark or formal comparison was run; an OPA integration may also be possible. |
| SPIFFE/SPIRE ecosystem | Workload identity and attested identity documents. | Invock models action authority and per-invocation evidence; it does not replace workload identity infrastructure. | How a deployed Invock instance would consume SVIDs is not specified. |
| gVisor / container isolation | Runtime/system-call isolation. | Invock addresses semantic tool authorization and evidence; a sandbox addresses runtime isolation. | The repository’s containment claims are not sufficient to establish production isolation. |

Product differentiation is therefore a composition hypothesis: “MCP-specific deterministic authorization + attenuated authority + lineage-aware policy + signed receipts at a local mediation boundary.” It is not a claim that Invock invented any component or owns a category.

## Security boundary comparison

| Boundary / property | MCP/OAuth guidance | Capability/reference-monitor prior art | Runtime sandbox / provenance systems | Invock repository evidence | Assessment |
|---|---|---|---|---|---|
| Authenticate principal/client | OAuth and workload identity address identity. | Reference monitors consume an authenticated subject. | Sandboxes may isolate without authenticating a human/agent. | `ActionEnvelope` and authority types carry principal/client/session fields. | Implemented data model is evidenced; strong external identity is NOT PROVEN. |
| Decide before tool execution | MCP specifies protocol authorization concerns, not local semantic policy. | Reference monitors require mediation at the access boundary. | Sandboxes can constrain consequences after launch. | `InvocationGate` returns `forward` only after normalization/policy/store paths in source. | Direct gate behavior is evidenced; complete transport non-bypassability is contradicted by older audit findings and requires fresh E2E proof. |
| Narrow delegated authority | OAuth scopes and capabilities are established patterns. | Capability attenuation is established prior art. | Sandbox privileges can be bounded at runtime. | Capsules/leases include tools, capabilities, effects, resources, labels, expiry, and call budgets. | Composition fact; formal novelty UNPROVEN. |
| Track sensitive data | Taint and provenance literature provide broad prior art. | Capability systems do not automatically provide taint. | Sandboxes do not automatically provide semantic lineage. | HMAC fingerprints cover exact and selected encodings; `finish` records taint. | Narrow implementation fact; paraphrase/arbitrary transformation detection explicitly unsupported. |
| Produce tamper-evident evidence | Signed logs and provenance are established. | Reference monitors do not inherently prove log integrity. | Sandboxes do not inherently provide audit evidence. | Ed25519 receipt and chain-head code is present. | Code-level cryptographic mechanism is evidenced; independent operational evidence is NOT PROVEN. |
| Isolate execution | MCP security guidance warns about local/server and SSRF risks. | Reference monitors mediate but do not necessarily isolate. | gVisor/containers provide a different boundary. | SECURITY.md explicitly excludes OS/container sandboxing from supported boundary. | FALSE if stated as “Invock is a sandbox”; only containment-adjacent code exists. |
| Prove upstream honesty | No cited standard grants this property. | A reference monitor cannot prove arbitrary downstream behavior after release. | Runtime isolation can limit effects but not establish honesty. | SECURITY.md explicitly disclaims this proof. | Unsupported claim; should remain NOT PROVEN. |

## Unsupported claims

The following claims are deliberately not accepted as novelty or completion claims:

- “Invock invented execution trust,” “owns the execution-trust category,” or has formal patent novelty: NOT PROVEN. The reviewed foundations predate this repository and no patent/literature-complete search or claim construction was performed.
- “The combination is novel”: NOT PROVEN. A potentially useful composition is a hypothesis until compared against concrete implementations and prior publications claim by claim.
- “Every MCP tool call is non-bypassably authorized”: FALSE as a repository-wide claim unless the contradictory audit evidence is resolved and fresh stdio/HTTP notification tests are executed. `FINAL_READ_ONLY_AUDITS.md` and `HACKATHON_READINESS_AUDIT.md` record prior bypass findings, while current status text asserts the opposite.
- “Complete argument-schema validation” and “persistent live schema-drift quarantine” are NOT PROVEN at the whole-system boundary from the reviewed evidence; the earlier audit specifically recorded descriptor omission and registry-integration concerns.
- “Invock provides OS/container sandboxing,” DNS-rebinding proof, arbitrary secret-transformation detection, or proof of upstream honesty: FALSE relative to SECURITY.md’s explicit boundary.
- “Signed receipts are independently trustworthy evidence”: NOT PROVEN. Source-level Ed25519/hash-chain code is evidence of a mechanism, not independent key custody, external anchoring, secure time, or legal evidentiary sufficiency.
- Any market-share, customer, competitor-superiority, performance, or adoption claim: NOT PROVEN; no such primary evidence was collected.

## Research gaps

1. Obtain the missing transformation specification and map each proposed claim to a falsifiable property and concrete prior source.
2. Run a fresh transport-level test matrix for request and notification forms, including malformed input, duplicate IDs, schema drift, approval binding, and upstream response correlation; reconcile the contradictory audit and certification documents.
3. Compare concrete MCP gateways and agent-security products using versioned documentation, reproducible feature tests, pricing/licensing evidence, and stated threat models. Do not infer product internals from marketing pages.
4. Perform a patent and scholarly database search with claim terms such as “MCP tool authorization,” “agent tool reference monitor,” “capability lease,” “taint-aware tool execution,” and “signed execution receipt.” This review did not do that search.
5. Formalize the authority model: define whether capsules/leases are capabilities, bearer assertions, policy inputs, or a hybrid; prove non-amplification, revocation, replay, and binding properties.
6. Evaluate operational key custody, receipt export, independent verification, clock assumptions, deletion detection, and external anchoring before making audit/evidence claims.
7. Separate containment experiments from authorization experiments and document the exact runtime, OS, network, filesystem, and adversary assumptions.
