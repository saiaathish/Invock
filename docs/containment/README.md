# Local containment

`runContained` is fail-closed about what it claims. A profile with
`sandbox: "none"` is an explicit compatibility mode: it runs an allow-listed
fixture without OS isolation and returns `capabilities.network: "unknown"`.
It never reports network denial for that mode.

## Enforced profiles

Use `sandbox: "required"` for a security boundary. The runner selects Docker
when `image` and a full `sha256:` `imageDigest` are supplied. It applies:

- `--network none`
- `--read-only`
- numeric non-root user `65532:65532`
- `--cap-drop=ALL`
- `no-new-privileges`
- explicit read-only bind mounts
- a PID limit, memory limit, CPU limit, timeout, and bounded output
- a small writable `/tmp` tmpfs
- `--pull=never` and `--rm`

On macOS without a digest-pinned image, the runner returns `unsupported`. The
previous Seatbelt fallback was removed because a deny-list cannot establish a
complete host-read boundary and macOS does not expose Linux
`no-new-privileges`. Required execution never falls back to an unenforced or
partially enforced process.

`pnpm containment:certify` first checks for the locally cached
`invock-containment:local` image and reads its immutable `sha256:` image ID.
When present, the certification supplies that exact digest to `runContained`
and therefore certifies the Docker path. It never pulls an image or treats a
tag alone as evidence. If the image is absent, certification uses the
available runtime as `unsupported` and leaves all enforcement booleans false.

If the requested runtime is unavailable, the result is `unsupported` with
`sandbox: "unavailable"`, `network: "unknown"`, and all enforcement booleans
false. There is no direct-process fallback for a required profile.

## Input boundary

Fixture roots and command paths are canonicalized. Symlinks, absolute paths,
parent paths, shell syntax, network command names, secret-like environment
keys, invalid bounds, and unpinned images are rejected before a child starts.
Additional mounts must be canonical, existing, and read-only. They are only
available to Docker profiles because macOS `sandbox-exec` cannot provide a
portable mount namespace.

Child stdout and stderr are bounded and redacted before returning. Timeouts and
output-limit violations terminate the process group; cleanup is performed in a
`finally` path. The runner does not contact public endpoints.

## Docker fixture image

`docker/containment.Dockerfile` is a local fixture derivation used by the
repository probe. Its official Node base is a development build input; the
runner itself rejects every profile image that lacks a full digest. The runner
also uses `--pull=never`, so a profile never fetches an image at execution time.
Build the probe with its base available in the local Docker cache, then run:

```text
pnpm docker-containment-test
```

The probe runs both a direct flag smoke check and the product `runContained`
path with a temporary read-only host bind mount. It checks a host-only read
sentinel, a write attempt against the read-only `/fixture` mount, network
denial, non-root execution, read-only root, no-new-privileges, bounded cleanup,
and the digest-pinned image. It does not prove that an arbitrary image or every
host project path is safe; every runner Docker profile still requires its own
digest, and host-specific Docker file-sharing behavior remains separate
evidence.
