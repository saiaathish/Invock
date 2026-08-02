# Strict MCP stdio containment

`runStdioProxy` has two execution paths:

- Strict gates (`InvocationGate.requiresContainment() === true`) never start the configured ordinary child. Tool calls run only through `StdioProxyConfig.containedForward`.
- An uncontained child is available only for an explicit `requireContainment: false` fixture created with `allowUnboundForTests: true` while `INVOCK_TEST_MODE=1`.

## Contained-forward contract

```ts
containedForward: async (authorized, signal) => ({
  response: { jsonrpc: "2.0", id: authorized.request.id ?? null, result },
  containment: signedCompletedRun,
})
```

The handler receives the already-authorized `ForwardedCall` and an abort signal. It must return a signed `ContainmentRunRecord` with:

- `result.status === "completed"`;
- matching `invocationId` and `sessionId`;
- `authorizedRequestDigest` equal to the gate envelope request digest; and
- a profile digest present in the gate's approved containment profiles.

Production gates must also configure `trustedContainmentKeys`; the record's
signer key ID and embedded public key must match that allowlist. A self-signed
record with an unconfigured key, an unapproved profile, or weaker recorded
capabilities is rejected. The unanchored verifier is limited to explicit test
fixtures running with `INVOCK_TEST_MODE=1` and `allowUnboundForTests: true`.

Invock verifies and attaches the record before parsing or completing the response. A missing handler, invalid signature, mismatched binding, malformed response, or timeout produces a durable fail-closed receipt and no ordinary forward.

## Control plane

Strict stdio does not start an upstream process for `initialize`, `tools/list`, or other control-plane messages. Since this bounded contract covers tool execution only, those messages receive JSON-RPC error `-32051` (`CONTAINMENT_REQUIRED_FOR_CONTROL_PLANE`). A future implementation may add a separately enforced contained control-plane contract.

## Scope

This boundary proves that Invock does not spawn or forward to an ordinary stdio child in strict mode. The caller-provided contained handler remains responsible for selecting and enforcing the sandbox/container runtime represented by its signed run record.
