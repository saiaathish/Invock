# Trusted release provenance

`.github/workflows/release.yml` is the release-only provenance boundary. It runs
for protected semantic-version `v*` tags whose commit is an ancestor of `main`,
or for manual dispatch from `main`. It does not deploy Invock to production.

## What the workflow proves

After a successful run, GitHub has executed the frozen dependency install and
these fail-closed checks from the tagged commit: typecheck, lint, tests, build,
and the repository's `pnpm supply-chain` report. The workflow extracts that
report's CycloneDX SBOM, records lockfile and Dockerfile hashes, builds the
digest-pinned containment image, pushes the image to GHCR under the commit SHA,
and records the resulting registry digest.

The workflow uploads one immutable Actions artifact named
`invock-release-evidence-<commit-sha>`. It then requests GitHub build
provenance attestations for the evidence files and the exact GHCR image digest.
The attestations use GitHub's OIDC identity and transparency-backed attestation
service; they are separate from Invock's locally generated Ed25519 evidence
signature.

Pinned action sources verified against the GitHub API and upstream tag sources:

| Action | Version | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `pnpm/action-setup` | v4.1.0 | `a7487c7e89a18df4991f7f222e4898a00d66ddda` |
| `actions/setup-node` | v4.4.0 | `49933ea5288caeca8642d1e84afbd3f7d682002d` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/attest-build-provenance` | v2.2.3 | `c074443f1aee8d4aeeae555aebba3282517141b2` |

The Docker image is built with the digest-pinned base in
`docker/containment.Dockerfile`. The release image's registry digest, not its
mutable tag, is the artifact identity.

Repository administrators must protect the `v*` tag namespace and restrict tag
creation to release maintainers. The workflow independently rejects non-semver
tags, tags that do not point into `main`, package/tag version mismatches, and
manual runs from any ref other than `main`.

## Verification

Set `OWNER`, `REPO`, `SHA`, and `DIGEST` from the release run:

```bash
gh attestation verify release-evidence.zip --repo "$OWNER/$REPO"
gh attestation verify "oci://ghcr.io/$OWNER/$REPO@$DIGEST" --repo "$OWNER/$REPO"
docker buildx imagetools inspect "ghcr.io/$OWNER/$REPO@$DIGEST"
docker pull "ghcr.io/$OWNER/$REPO@$DIGEST"
docker image inspect "ghcr.io/$OWNER/$REPO@$DIGEST"
```

Download the Actions artifact before the first command, or verify an individual
attested evidence file path after extraction. GitHub's verification output
must identify the expected repository and workflow; reject mismatched identity,
subject digest, or ref.

## Limits

This workflow proves build-time GitHub provenance for the uploaded files and
GHCR image digest. It does not prove that the source code is free of defects,
that every agent execution is contained, that a remote tool is benign, or that
production is deployed and running this digest. The local `pnpm supply-chain
-- --sign` signature remains self-generated local evidence. The workflow also
does not provide hardware attestation, customer validation, independent audit
approval, or signing custody outside GitHub's attestation service.

GHCR publication is an artifact publication step, not an automatic production
deployment. Repository administrators must protect `v*` tags and review the
workflow permissions before enabling releases.
