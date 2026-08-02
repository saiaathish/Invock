# Invock SDK reference

The owned SDK surface is dependency-free. TypeScript uses the standard `fetch` API; Python uses only `urllib`. Both clients send a bearer token and a JSON request to `POST /api/v1/authorize`:

```json
{
  "agent": "agent-1",
  "projectId": "project-1",
  "tool": "read",
  "arguments": { "path": "safe.txt" },
  "sessionId": "<server-bound-session-id>",
  "authorityBinding": { "...": "matching binding for the capsule" },
  "intentCapsule": { "...": "active signed capsule" },
  "capabilityLeases": [{ "...": "active signed lease" }]
}
```

The response must be an object with `verdict` equal to `ALLOW`, `BLOCK`, or `APPROVAL_REQUIRED`, plus a string array `reasonCodes`. `receiptId` and `approvalId` are optional strings. `/api/v1/authorize` is strictly non-executing: an `ALLOW` is a pre-forward decision and does not complete a receipt. Use `/api/v1/execute` (through `InvockClient.execute` or an adapter's `executeContained`) for server-owned contained execution. Non-HTTP endpoints, non-2xx responses, oversized or invalid JSON, malformed verdicts, and missing/malformed reason codes fail closed. Error messages never include bearer tokens or request arguments.

TypeScript:

```ts
import { InvockClient } from "./src/sdk/index.js";
const invock = new InvockClient({ endpoint: "http://127.0.0.1:4317", token: "local-token" });
const decision = await invock.authorize({ tool: "read", arguments: { path: "safe.txt" } });
```

Python:

```python
from sdk.python.invock_client import InvockClient
invock = InvockClient("http://127.0.0.1:4317", "local-token")
decision = invock.authorize("read", {"path": "safe.txt"})
```

`OpenAIInvockAdapter` accepts an `OpenAIToolCall` with `name` and object-or-JSON-string `arguments`. `SecondaryInvockAdapter` accepts a `SecondaryToolCall` with `name` and object `input`. Their `execute` methods are pre-execution mediation boundaries: they call Invock first, never invoke the supplied executor after `BLOCK` or `APPROVAL_REQUIRED`, and pass only `authorizedArguments` after `ALLOW`. They do not claim to install hooks inside an external framework package; the caller owns that framework callback.

For `executeContained`, the server must own the containment handler and return a
signed run bound to the exact authorized request. Production deployments must
anchor the handler's signer and capability profile in the `InvocationGate` and
`InvockStore` configuration; missing trust configuration fails closed.

## Current boundary limitation

The local CLI server exposes `/api/v1/authorize` and routes it through the canonical `InvocationGate`. An active Intent Capsule must be accompanied by an agent ID, the server-bound API session, and at least one validated Capability Lease whose leaf subject matches that agent; a bound capsule additionally requires its matching binding and project context. The CLI prints the trusted API session when it starts. A request may repeat that exact value, but an arbitrary body `sessionId` is rejected and cannot select a lineage partition. The server never synthesizes a lease or silently ignores capsule input. A successful authorization is a pre-forward decision; the caller remains responsible for forwarding only the canonical authorized request and completing the receipt through the gateway integration. No framework-wide or production deployment claim is made here.

For an explicit fail-closed policy-only boundary, run the server with `--strict-authority` or `INVOCK_STRICT_AUTHORITY=1`. The strict route rejects requests without the complete bound-authority metadata before policy-only authorization can proceed. The cryptographic workload-identity evidence-binding API remains a separate integration surface; strict mode does not turn self-asserted agent strings into hardware attestation.
