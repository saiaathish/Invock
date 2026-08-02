# Invock local API reference

This reference covers the local TypeScript APIs added by the control-plane and evidence work. It does not describe a hosted service, SSO, SCIM, enterprise RBAC, or remote evidence anchoring.

## `LocalControlPlane`

Import from `src/control/index.ts` and construct it with an injected JSON state path:

```ts
const control = new LocalControlPlane(".invock/control-plane.json");
```

The file is versioned, validated on load, written with owner-only permissions, and replaced using an atomic temporary-file rename. Organizations own projects; projects own agents and alerts. An agent or alert cannot be registered against another project or an unknown project.

Methods:

- `upsertOrganization({ id, displayName })`
- `upsertProject({ id, organizationId, displayName })`
- `registerAgent({ id, projectId, displayName, trustState })`
- `recordAlert({ projectId, severity, message })`
- `list("organizations" | "projects" | "agents" | "alerts")`
- `exportSnapshot()`

Inputs are bounded and printable. Alert messages redact private-key blocks, bearer tokens, and common secret assignments before persistence.

## Evidence bundle

Import `buildEvidenceBundle(store, sessionId?)` and `renderEvidenceBundle(bundle, format)` from `src/evidence/index.ts`. Formats are `json`, `ndjson`, and `markdown`.

The bundle contains the public verification key, signed chain-head metadata, redacted receipt projections, available policy/intent/lease/schema digests, and verification instructions. Raw invocation arguments and private signing keys are excluded. The bundle also reports unsupported enterprise/cloud integrations explicitly.

The source `InvockStore` remains the authority for receipt verification. The evidence renderer is a reporting projection and does not make authorization decisions.

## Bound authority

Production-shaped capsules can carry an `AuthorityBinding` covering agent, session, project, policy version/digest, registry version, and tool-schema digest. A bound capsule must be activated with signed human evidence, and the authorization request must supply the matching `authorityBinding`, `projectId`, agent, and session context. The gate compares those values before forwarding and writes `authorityBindingDigest` into signed receipt metadata.

`scanSupplyChain(root)` produces a deterministic local evidence inventory and CycloneDX-shaped component report. Advisory and signature verification are reported as `not-queried`/`not-verified` when those external proofs were not supplied.
