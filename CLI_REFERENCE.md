# Invock CLI reference

All commands are local-only and use fake or repository-local data. `invock --help` exits zero. Invalid command syntax exits nonzero. No command contacts a public endpoint.

## Local lifecycle

```text
invock init [--state <path>]
invock scan [--state <path>]
invock supply-chain scan [--root <path>]
invock start [--database <path>] [--key-directory <path>]
invock judge
```

`init` creates validated control-plane JSON. `scan` reports local state, a deterministic supply-chain evidence inventory, and unsupported integrations. `supply-chain scan` emits the same evidence report directly. `start` runs the authenticated loopback API. `judge` runs the fake-data judge flow and labels containment/browser evidence honestly.

## Policy lifecycle

```text
invock policy learn --from-demo
invock policy validate <file>
invock policy diff <from-json> <to-json>
invock policy simulate <policy-json> [<observations-json>]
invock policy activate <draft-json> --approved-by <name> --approval-id <id> --statement <text>
invock policy rollback <draft-json> --from <policy-id> --approved-by <name> --approval-id <id> --statement <text>
```

Learning creates a draft. Simulation evaluates observation data without executing a tool. Activation requires an attributable approval and uses a fixed epoch timestamp for reproducible CLI output. Rollback re-activates a supplied prior draft only after a new explicit approval and emits the source policy identifier; generated drafts never activate automatically.

## Receipts and evidence

```text
invock receipts verify [--database <path>] [--key-directory <path>]
invock receipts export --format json|ndjson|markdown [--session-id <id>] [--database <path>] [--key-directory <path>]
invock evidence bundle [<session-id>] [--format json|ndjson|markdown] [--database <path>] [--key-directory <path>]
```

Exports contain public verification material and redacted receipt fields only. They do not contain private keys, raw arguments, or secret values.

## Existing commands

`serve`, `serve --stdio`, `demo safe`, `demo attack`, `forge`, `guard`, `contain`, and `doctor` remain available. Required containment mode still fails closed when the secure sandbox is unavailable.

```text
invock serve [--strict-authority] [--database <path>] [--key-directory <path>]
invock serve --stdio [--strict-authority] [--database <path>] [--key-directory <path>] <command> [-- <args...>]
```

`--strict-authority` (also enabled by `INVOCK_STRICT_AUTHORITY=1`) rejects policy-only API calls and requires agent, project, session, a bound human-activated Intent Capsule, and its Capability Lease chain. The stdio mode uses the persistent `tools/list` registry; schema drift is recorded and quarantines the tool before later calls. This mode is an explicit local enforcement boundary, not a claim of hardware attestation or hosted identity.

## Explicit limits

Enterprise cloud control planes, SSO/SCIM, and remote evidence anchoring are not implemented here. The OpenAI-shaped and secondary adapters are local pre-execution SDK boundaries; official hosted framework hooks remain caller-owned and must not be presented as bundled by this CLI.
