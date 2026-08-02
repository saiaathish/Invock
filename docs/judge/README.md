# Invock judge mode and five-minute onboarding

This is a local, fake-data integration example for evaluating the reference monitor. It exercises the real loopback API and TypeScript SDK, but it does not connect to a production repository, upstream MCP server, cloud service, browser, or Docker daemon.

## Compatibility

- Node.js 22.18.0 (the package declares >=22.5.0)
- pnpm 11.15.1 (declared by packageManager)
- TypeScript 5.9.2, tsx 4.20.5, YAML 2.8.1
- MCP behavior is exercised through the repository's local tools/call gate; no remote server is required.

## Automated judge (under ten minutes)

    pnpm install --frozen-lockfile
    pnpm build
    pnpm judge --automated

The command emits exactly one JSON document on stdout. Its schema is invock/judge-result/v1. A local run reports overall: "passed" only when every requested containment capability is reported as enforced; if the local sandbox completes but a requested capability is not enforced, or the sandbox is unavailable, it reports overall: "degraded" and names the limitation. overall: "failed" means a required local flow assertion or cleanup operation failed.

The flow performs, in order: prerequisite validation; fake control-plane initialization; fake-tool detection; fake-repository scan; policy draft generation and no-execution simulation; local gateway and dashboard startup; safe read contained execution; protected-path attack blocking; no-network containment probe; signed evidence verification; and cleanup.

## Presentation mode

    pnpm exec node --import tsx scripts/judge.ts --presentation

Presentation mode pauses at each checkpoint when attached to a TTY and writes pause instructions to stderr. It still writes the final machine-readable result to stdout. In a non-TTY environment it proceeds without pausing and records that behavior in the result. The dashboard URL appears in the gateway checkpoint; open it manually if desired. The judge does not claim browser, keyboard, contrast, or screen-reader evidence.

The automated gateway checkpoint performs only non-browser semantic/readiness checks on the returned HTML (main, heading, label, and button markers plus a 200 response). These checks are not an accessibility certification.

## Five-minute developer path

The existing CLI commands remain available:

    pnpm invock init
    pnpm invock scan
    pnpm invock policy learn --from-demo
    pnpm invock start

pnpm judge --automated is the repeatable integration example. It owns all state in a temporary directory and closes the API, SQLite store, signing-key directory, control-plane file, and fixture in finally blocks.

## Security boundary

The example uses a read-only intent capsule, a documentation-scoped capability lease with a 20-call budget and a fixed 15-minute expiry, and the canonical InvocationGate. The safe call is the only call counted as upstream execution. The .env attack is denied before any upstream or sink execution. Evidence contains public verification material and signed redacted receipts; raw fake content and private keys are not exported.

The local containment probe requests sandbox: required and network: none. If the host cannot provide the sandbox, the result is degraded/unsupported; the judge does not silently fall back to an unsandboxed success. Docker Compose is configuration-only until separately exercised.

## Failure instructions

- LOCAL_PREREQUISITES_UNAVAILABLE: use Node 22.18.0 or newer than the declared 22.5.0 floor and run from the repository root.
- overall: "failed" with a checkpoint: inspect that checkpoint's details and rerun pnpm judge --automated; do not interpret a partial JSON result as a security certification.
- resultStatus: "unsupported" or a containment reason such as SANDBOX_UNAVAILABLE: treat readiness as degraded. Run the host-specific containment test separately; do not claim Docker or browser proof.
- A nonzero command exit means the local flow or cleanup did not complete. Temporary resources are still attempted in finally; inspect the cleanup object.

Unsupported integrations are explicit in the JSON result: enterprise cloud control plane, SSO/SCIM, remote evidence anchoring, OpenAI agent adapter, secondary framework adapter, and browser accessibility verification.

## Docker Compose shape

The repository root docker-compose.yml defines an optional invock-judge job using Node 22.18.0. It mounts the source read-only, gives temporary storage to /tmp and node_modules, installs the locked dependencies, and runs the same automated judge flow. Use docker compose run --rm invock-judge only when the dependency-install policy and Docker runtime are available. This shape has not been treated as runtime evidence; the JSON result remains the authority for what was actually exercised.
