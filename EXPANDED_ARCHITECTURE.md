# Invock expanded architecture

## Execution path

```text
Agent or MCP transport
  -> request shape and protocol checks
  -> canonical ActionEnvelope
  -> policy evaluation
  -> optional active Intent Capsule and Capability Lease intersection
  -> lineage and containment constraints
  -> ALLOW / BLOCK / APPROVAL_REQUIRED
  -> canonical forwarded request only
  -> signed receipt and redacted evidence bundle
```

`InvocationGate.authorizeInvocation` is the only source of a `forward` outcome in the supported adapters. The API authorization route injects the same gate rather than implementing a second policy path.

## State

SQLite stores invocation, approval, taint, registry, expansion, and receipt state. Signing and taint keys are kept in an owner-only key directory. A signed chain head detects terminal receipt deletion. The local control plane uses validated atomic JSON state for organizations, projects, agents, and alerts.

## Authority

Effective authority is narrowed by static policy, active intent, lease chain, request schema, data lineage, and containment. Child leases cannot exceed parent scope, expiry, or call budget. The API refuses an Intent Capsule without an agent, session, and validated lease chain.

## Trust boundaries

The upstream server, agent runtime, local filesystem, API bearer token, workflow actions, and container image are separate trust inputs. A valid receipt proves what Invock observed and decided; it does not prove an upstream service's behavior after forwarding.

## Deployment modes

The supported default is loopback local operation. Required containment selects Docker with a digest-pinned image or macOS sandboxing when available; otherwise it returns `unsupported`. Remote binding requires explicit configuration and remains outside the default threat model.
