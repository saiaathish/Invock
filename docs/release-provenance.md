# Trusted release provenance

`.github/workflows/release.yml` is the release-only provenance boundary. It runs
only for protected semantic-version `v*` tag pushes whose commit is an ancestor
of `main` and whose version exactly matches `package.json`. Manual dispatch is
intentionally unavailable. It does not deploy Invock to production.

## What the workflow proves

The first job has read-only repository permissions and removes persisted checkout
credentials before executing repository code. It performs a frozen install,
typecheck, lint, the complete test suite, build, base certification, mutation
review, Arena, scoped Chromium accessibility, local and Docker containment,
double release rehearsal, demo certification, claim consistency, the production
advisory scan, and a parse-validated signed local supply-chain report. It extracts
that report's CycloneDX SBOM, records lockfile and Dockerfile hashes, builds the
containment image, saves the exact image candidate, and uploads one candidate
artifact bound to the release commit.

The credentialed `publish` job is isolated behind the `release-provenance`
GitHub Environment and does not check out or execute repository source. It
downloads only the candidate from the same workflow run, verifies its recorded
digest and evidence JSON, loads that exact image, pushes it to GHCR under the
commit SHA, and records the resulting registry digest.

The workflow uploads one immutable Actions artifact named
`invock-release-evidence-<commit-sha>`. It then requests GitHub build
provenance attestations for the evidence files and the exact GHCR image digest,
plus a dedicated SBOM attestation binding the CycloneDX document to that image
digest. The attestations use GitHub's OIDC identity and transparency-backed
attestation service; they are separate from Invock's locally generated Ed25519
evidence signature.

Pinned action sources verified against the GitHub API and upstream tag sources:

| Action | Version | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `pnpm/action-setup` | v4.1.0 | `a7487c7e89a18df4991f7f222e4898a00d66ddda` |
| `actions/setup-node` | v4.4.0 | `49933ea5288caeca8642d1e84afbd3f7d682002d` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/download-artifact` | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| `actions/attest-build-provenance` | v2.2.3 | `c074443f1aee8d4aeeae555aebba3282517141b2` |
| `actions/attest-sbom` | v2.4.0 | `bd218ad0dbcb3e146bd073d1d9c6d78e08aa8a0b` |

The Docker image is built with the digest-pinned base in
`docker/containment.Dockerfile`. The release image's registry digest, not its
mutable tag, is the artifact identity.

Repository administrators must protect the `v*` tag namespace and restrict tag
creation to release maintainers. They must also configure the
`release-provenance` Environment with required reviewers and restrict its
deployment tags to `v*`. The workflow independently rejects unprotected or
non-semver tags, tags that do not point into `main`, package/tag version
mismatches, and any event other than a tag push.

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
deployment. Repository administrators must protect `v*` tags, configure the
`release-provenance` Environment, and review the workflow permissions before
enabling releases. Until those repository settings and one successful tagged
run are independently inspected, external release provenance remains
`NOT_PROVEN`.
