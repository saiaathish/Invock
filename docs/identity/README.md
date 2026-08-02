# Software workload identity

`IdentityAuthority` provides deterministic, local identity state for Invock
agents. Enrollment creates an Ed25519 key pair, signs a short-lived canonical
enrollment token, and exposes only the public key through `AgentIdentity`.
Private keys remain inside the authority and are never returned in an identity,
token, or session structure.

Enrollment tokens are single-use. Verification rejects unknown, expired,
mutated, replayed, project-mismatched, suspended, and revoked identities.
Rotation keeps the agent ID while replacing key material and invalidating tokens
from the previous key. Sessions are explicitly bound to the identity's project
and have bounded TTLs.

This is software workload identity and software workload attestation wording
only. It is not hardware attestation and does not claim a hardware root of
trust, secure enclave, TPM, or equivalent device measurement.
