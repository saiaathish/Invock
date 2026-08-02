# Invock integration guide

## Local server

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm invock serve --database .invock/local.sqlite --key-directory .invock/keys
```

The command prints a loopback URL and bearer token. Keep the token local. Health is available at `GET /api/v1/health`; authenticated authorization is `POST /api/v1/authorize`.

## TypeScript

```ts
import { InvockClient } from "./src/index.js";

const client = new InvockClient({ endpoint, token });
const decision = await client.authorize({
  agent: "agent-1",
  tool: "read_file",
  arguments: { path: "/workspace/README.md" },
});
```

When intent is supplied, include the active capsule, its validated lease chain, and the leaf-agent ID. The API server owns the session partition: configure a trusted `sessionId` when starting `startApi` (the CLI prints its generated value), and only repeat that exact value in a client payload if needed. Caller-selected session IDs are rejected. The server rejects malformed or incomplete authority instead of synthesizing it.

## Python

```python
from sdk.python.invock_client import InvockClient

client = InvockClient(endpoint, token)
decision = client.authorize("read_file", {"path": "/workspace/README.md"}, agent="agent-1")
```

## Framework adapters

`OpenAIInvockAdapter` and `SecondaryInvockAdapter` provide typed pre-execution boundaries. Call `execute(call, forward)` from the framework's tool callback; Invock runs first, the callback is not invoked for `BLOCK` or `APPROVAL_REQUIRED`, and only the returned canonical arguments reach `forward`. These adapters do not install hooks into an external framework package automatically.

## Failure handling

Treat `BLOCK`, `APPROVAL_REQUIRED`, `UNSUPPORTED`, malformed responses, and transport errors as non-forwarding outcomes. Forward only the canonical request produced by the gate and complete the receipt through the gateway integration.
