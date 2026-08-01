# Expansion integration

The expansion facade is `src/expansions.ts`. It exposes Arena, authority, containment, Forge, Guard, protocol, and redacted UI contracts.

`InvocationGate.authorizeInvocation` accepts an optional authority context and applies the effective authority result after static policy evaluation. Authority failures are fail-closed. Optional expansion metadata is carried through `ForwardedCall` and signed receipts.

CLI surfaces:

- `pnpm arena`
- `pnpm forge [observation-json]`
- `pnpm guard <workflow-file>`
- `pnpm contain <fixture-root> <command> [-- <args...>]`

Containment reports `unsupported` when the required OS sandbox is unavailable. It never claims isolation from capability detection alone. Forge drafts require explicit human approval before activation. Guard is local static analysis and makes no GitHub/network claim.
