# Changelog

## 0.1.7 — 2026-08-02

- Fixed the release-provenance workflow's signed SBOM verification import path and prepared the exact merged release candidate for external provenance verification.

## 0.1.6 — 2026-08-02

- Hardened authority, identity/session binding, containment proof cleanup, protocol negotiation, upstream HTTPS/DNS pinning, and release-evidence verification.
- Added Python SDK interoperability coverage and current release-provenance/SBOM validation.

## Unreleased — 2026-08-01

- Added authenticated `/api/v1/authorize` routing through the canonical gate.
- Added TypeScript/Python lease and session request fields.
- Bound validated identity evidence into signed receipt metadata.
- Hardened capsule/lease lifecycle digests and explicit unknown handling.
- Added bounded certification and Docker timeout behavior.
- Added live CLI/API, identity/evidence, certification, and root-export coverage.
- Marked historical READY artifacts as superseded and documented the current NOT READY boundary.
