# Arena scenario contract

The runner deliberately keeps each scenario bounded and local. A scenario
callback builds a concrete MCP-shaped request, observes a fixture or parses a
payload, and registers cleanup. The protected adapter sends that request to
`InvocationGate`; the unprotected adapter records what a local upstream would
receive; the static adapter applies an exact allowlist.

The attack scenarios are expected to be blocked by the protected policy in the
current fixture. If a future policy or adapter produces `completed`, the raw
outcome is a false negative and must remain visible. If an adapter cannot
measure a fact, it must return `unknown` or `unsupported`, not a fabricated
pass.

The only external-looking values are fake local fixtures such as
`ARENA_FAKE_SECRET`. No public host is contacted and no attacker command is
executed. This keeps the benchmark repeatable and safe while preserving the
authorization boundary under test.
