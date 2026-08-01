# Authority modules

`src/authority` provides deterministic intent-capsule and capability-lease primitives. Capsules are created as `PROPOSED` and require explicit activation. Leases can only narrow an active capsule or parent lease; calls consume the immutable lease budget. Expired, revoked, tampered, malformed, or out-of-scope objects fail closed.

Integration should import from `src/authority/index.ts`, persist the returned snapshots, and pass the full lease chain to `evaluateMonotonicAuthority` before invoking a tool. The returned `effectiveDigest` is suitable for the shared authority record.
