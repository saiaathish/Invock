# Invock deployment guide

## Local-first deployment

Use a dedicated state directory with owner-only permissions:

```bash
pnpm invock serve --database .invock/invock.sqlite --key-directory .invock/keys
```

The default bind is loopback. Do not expose the dashboard or bearer token to a public interface without an independently reviewed authentication and network boundary.

## State and keys

Back up the SQLite database and key directory together. Do not copy private signing or taint keys into SQLite, logs, receipts, bundles, or issue reports. Verify the chain after restoration with `pnpm invock receipts verify`.

## Containment

Use `sandbox: "required"` for a security boundary. Provide a digest-pinned image for Docker. If Docker or macOS sandboxing is unavailable, the runner returns `unsupported`; do not convert that result into a direct-process success claim.

## Production boundary

Hosted control plane, SSO/SCIM, multi-region operation, remote evidence anchoring, SIEM integrations, and production SLOs are design targets only. Obtain a security review, deployment-specific threat model, dependency/SBOM review, and clean release rehearsal before production use.
