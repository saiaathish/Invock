# Server-side contained execution API

`POST /api/v1/execute` accepts the same canonical authorization input as
`POST /api/v1/authorize`:

```json
{"tool":"read","arguments":{"path":"safe.txt"},"agent":"agent-1"}
```

The authenticated server runs the single configured `InvocationGate`. A
forwardable call is not executed by the authorization endpoint. The explicit
`/api/v1/execute` endpoint must have an `onContainedForward` handler. That handler runs the tool inside the server's
containment implementation and returns a signed `ContainmentRunRecord` plus a
tool result. It receives only the canonical authorized forward, never the raw
HTTP body. Invock verifies the signature and binds invocation ID, session ID,
and the exact authorized-request digest before finishing the receipt.

In production, the gate and store must be configured with the same
`trustedContainmentKeys` and `approvedContainmentProfiles`. The trusted key
must match the record's key ID and embedded public key; the approved profile
must match both the profile digest and the recorded runtime capabilities. If
either trust set is absent or mismatched, Invock rejects the proof and emits a
fail-closed denial. The unanchored verifier is available only to explicit test
fixtures running with `INVOCK_TEST_MODE=1` and `allowUnboundForTests: true`.

Successful response:

```json
{
  "verdict":"ALLOW",
  "reasonCodes":["READ"],
  "receiptId":"receipt-…",
  "result":{"content":[{"type":"text","text":"…"}]}
}
```

Only text content is returned. Results are bounded to 128 KiB, 128 content
items, 64 KiB per text value, finite JSON numbers, depth 16, and 4096 JSON
nodes. Private result metadata is not returned. Denials, missing handlers,
malformed results, containment failures, and incorrect bindings fail closed;
the caller receives a denial receipt when the gate has already produced a
forwardable call.

`InvockClient.execute`, `OpenAIInvockAdapter.executeContained`,
`SecondaryInvockAdapter.executeContained`, and Python
`InvockClient.execute` use this endpoint. Existing callback-based `execute`
methods remain compatibility APIs and refuse forwarding when containment is
required.
