# Invock

> Invock is a zero-trust execution and privacy layer that controls, contains, and cryptographically proves AI-agent actions before they reach tools or external systems.

Invock acts as an inline reference monitor between autonomous AI agents (such as Claude Code or OpenAI Codex) and external execution environments (MCP servers, system shells, file systems, APIs). It guarantees that no action executes without explicit policy authorization, valid identity bindings, bounded capability leases, and strict privacy mode compliance.

---

## The Problem

Modern AI coding agents are granted powerful system access to read codebases, run shell commands, invoke APIs, and manage databases. However:

* **Prompt instructions are not security boundaries**: Prompt injections or model hallucination can cause agents to exceed intended operational scopes.
* **Unbounded tool execution**: Standard MCP or SDK tool calls carry side effects that can destroy local state, leak sensitive keys, or perform unauthorized network egress.
* **Historical data exposure**: Installing a protective agent tool today does not retroactively clean pre-existing sensitive artifacts, conversation caches, or external provider logs created prior to installation.

---

## What Invock Does

Invock enforces a strict **fail-closed, deterministic pre-execution boundary**:

* **Deterministic Pre-Execution Authorization**: Evaluates tool calls against structured security policies, intent capsules, and delegated capability leases before execution occurs.
* **Claude Code & Codex Integration**: Wraps standard CLI clients and MCP transports to intercept and sanitize tool invocations transparently.
* **Signed Receipt Chains**: Issues Ed25519-signed cryptographic receipts for every authorization decision and execution outcome.
* **Local & End-to-End Zero Data Retention (ZDR)**: Guarantees content-free local persistence (`LOCAL_ZDR`) and blocks unverified third-party data routes (`END_TO_END_ZDR`).
* **Legacy Privacy Remediation & Protection Boundary**: Discovers pre-installation privacy risks, enables safe local artifact removal, provides provider-history guidance, and issues signed protection boundary certificates.
* **Local Dashboard & Visual Telemetry**: Exposes content-free real-time monitoring and approval interfaces over a local loopback server.

---

## Quick Start

### Prerequisites

* Node.js `>=22.5.0`
* pnpm `11.15.1`

### Installation & Initialization

```bash
# Install dependencies and build project
pnpm install --frozen-lockfile
pnpm build

# Initialize local Invock control plane
pnpm invock init

# Run safe legacy privacy onboarding
pnpm invock privacy onboard --yes
```

---

## Five-Minute Demo

Experience Invock's protection layer and legacy privacy onboarding in under five minutes:

```bash
# 1. Run the interactive safe policy demo
pnpm invock demo:safe

# 2. Run the adversarial attack prevention demo
pnpm invock demo:attack

# 3. Run the synthetic legacy privacy onboarding demo
pnpm invock privacy legacy demo

# 4. View real-time content-free stats
pnpm invock stats
```

---

## Everyday Usage

### Agent Wrapping & Protection

Wrap your preferred AI coding agent CLI to enforce Invock policy mediation automatically:

```bash
# Launch Claude Code under Invock protection
pnpm invock wrap claude -- --help

# Launch Codex under Invock protection
pnpm invock wrap codex -- --help
```

### Legacy Privacy Commands

Inspect and manage historical data risks created before Invock was installed:

```bash
# Check onboarding and privacy status
pnpm invock privacy legacy status

# Run local legacy artifact scan
pnpm invock privacy legacy scan --yes

# View external provider history guidance
pnpm invock privacy legacy provider-actions

# Inspect signed Protection Boundary certificate
pnpm invock privacy boundary show

# Verify Protection Boundary signature
pnpm invock privacy boundary verify
```

---

## Architecture

```text
  Claude Code / Codex / MCP Client
                 |
                 v
            Invock CLI
                 |
  +--------------+--------------+
  |                             |
  v                             v
Policy Gate               Privacy Engine
(Capsules, Leases,       (Local ZDR, E2E ZDR,
 Policy Matrix)           Legacy Scanner)
  |                             |
  +--------------+--------------+
                 |
                 v
       Execution / Isolation
   (Contained Runner, MCP Stdio)
                 |
                 v
 Signed Ed25519 Receipt Chain & Store
```

### Request Lifecycle

1. **Invocation Capture**: The agent attempts a tool execution (e.g., file read, terminal execution, HTTP request).
2. **Canonical Normalization**: The raw tool call is converted into a canonical `ActionEnvelope`.
3. **Identity & Context Binding**: Active workload identity, project context, and session parameters are verified.
4. **Policy Evaluation**: Invock checks the requested tool and exact arguments against active policy rules.
5. **Privacy Mode Check**: Verifies retention profiles against active `LOCAL_ZDR` or `END_TO_END_ZDR` constraints.
6. **Authorization Decision**: Returns `ALLOW`, `BLOCK`, or `APPROVAL_REQUIRED`.
7. **Execution & Receipt Signing**: If allowed, execution occurs within a contained runner and a signed Ed25519 receipt is recorded in the immutable local store.

---

## Security Model

* **Pre-Execution Control Point**: Authorization occurs prior to side effects.
* **Fail-Closed Default**: Mismatched signatures, unhandled schema drift, or unknown capabilities immediately yield a `BLOCK` verdict.
* **Exact Argument Authorization**: Policies bind to canonicalized argument values, preventing path traversal or parameter tampering.
* **Cryptographic Attestation**: Software identities and receipts are signed using Ed25519 key pairs.
* **Honest Mediation Boundary**: Invock strictly controls actions visible at its supported local proxy and gateway interfaces.

> **Note**: Invock controls actions visible at its supported mediation and containment boundaries. It does not prove that external infrastructure or an allowed remote service behaves honestly beyond those boundaries.

---

## Privacy

Invock implements a multi-tier privacy framework designed to enforce Zero Data Retention (ZDR):

### Local ZDR
Ensures that no customer prompt content, code snippets, or tool arguments are written to local logs or persistent databases. Only content-free hashes, timestamps, and reason codes are retained.

### End-to-End ZDR
Evaluates downstream processor profiles before request forwarding. If a downstream provider retains customer data or lacks a verified retention profile, invocation is blocked.

### Legacy Privacy Onboarding
Discovers legacy local history (Claude logs, Codex caches, old Invock artifacts) created before Invock installation, allowing safe user-confirmed removal of disposable files.

### Protection Boundary
Issues an Ed25519-signed receipt certifying the exact timestamp when Invock protection became active, providing cryptographic proof of boundary enforcement without claiming false retroactive erasure of external provider logs.

---

## Core Command Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `invock init` | Initialize local control plane state | `pnpm invock init` |
| `invock status` | Inspect CLI state and integrations | `pnpm invock status` |
| `invock privacy status` | Check active privacy mode and contract | `pnpm invock privacy status` |
| `invock privacy onboard` | Run guided legacy privacy onboarding | `pnpm invock privacy onboard --yes` |
| `invock privacy legacy status` | View legacy audit status and findings | `pnpm invock privacy legacy status` |
| `invock privacy boundary show` | Display active signed protection boundary | `pnpm invock privacy boundary show` |
| `invock privacy boundary verify` | Verify cryptographic boundary signature | `pnpm invock privacy boundary verify` |
| `invock privacy legacy demo` | Run synthetic onboarding demonstration | `pnpm invock privacy legacy demo` |
| `invock wrap <agent>` | Launch agent binary under Invock protection | `pnpm invock wrap claude` |
| `invock stats` | Output content-free telemetry statistics | `pnpm invock stats --json` |

---

## Configuration

Invock defaults to secure, local-only defaults stored in `.invock/`:

* `INVOCK_HOME`: Base directory for local state (defaults to `~/.invock`).
* `INVOCK_PRIVACY_DIR`: Custom directory for privacy configurations and boundaries.
* **Loopback Binding**: Local server and proxy bind strictly to `127.0.0.1`.
* **Zero Content Logging**: Logging of sensitive prompts and tool outputs is disabled by default.

---

## Supported Integrations

| Integration | Status | Usage | Limitations |
| :--- | :--- | :--- | :--- |
| **Claude Code** | Supported | `pnpm invock wrap claude` | Requires local Claude CLI installation |
| **OpenAI Codex** | Supported | `pnpm invock wrap codex` | Requires local Codex CLI installation |
| **Cursor** | Preview | `pnpm invock wrap cursor` | Experimental wrapper; live verification pending |

---

## Receipts and Verification

Every authorization decision produces a tamper-evident, Ed25519-signed receipt:

* **Ed25519 Signature**: Covers canonical receipt metadata and policy digests.
* **Content-Free Telemetry**: Receipts store SHA-256 hashes of actions rather than raw data.
* **Verification**: Verify receipt authenticity via `pnpm certify` or the local dashboard API.

---

## Dashboard

Invock includes a local, loopback-only visual dashboard for monitoring activity:

```bash
pnpm invock dashboard
```

* Displays real-time content-free invocation statistics.
* Shows active policy rules, privacy mode status, and receipt digests.
* Runs entirely locally without external telemetry.

---

## Development & Testing

Run the full validation suite:

```bash
# Typecheck TypeScript sources
pnpm typecheck

# Run unit and integration tests (322 tests)
pnpm test

# Build production bundle
pnpm build

# Execute security, CLI, and ZDR certification suites
pnpm certify
pnpm cli:certify
pnpm zdr:certify
pnpm zdr:audit
```

---

## Repository Structure

```text
src/
├── authority/      # Intent capsules and capability leases
├── containment/    # Contained execution runner and isolation
├── core/           # Canonical serialization and policy engine
├── evidence/       # Content-free telemetry and evidence bundles
├── gateway/        # MCP stdio & HTTP invocation gates
├── identity/       # Workload identity authority
├── privacy/        # ZDR engine and Legacy Privacy remediation
└── storage/        # Ed25519 signed receipt store & SQLite DB
scripts/            # Validation, certification, and audit scripts
test/               # Unit, integration, and security test suite
```

---

## Troubleshooting

### Invock Command Not Found
Ensure the project is built via `pnpm build` or run commands using `pnpm invock <command>`.

### Agent Not Detected
Ensure `claude` or `codex` binaries are installed and accessible in your system `PATH`.

### End-to-End ZDR Blocked
If `END_TO_END_ZDR` returns `BLOCK`, an unlisted or non-compliant AI processor was detected in the execution route. Register verified retention profiles via `pnpm invock privacy processors add`.

---

## Honest Limitations

* **Supported Mediation Boundaries**: Invock mediates tool invocations routed through its gateway or wrappers. Unwrapped direct shell calls bypass local interception.
* **Provider-Side Retained Data**: Invock can clean local legacy files and issue signed protection boundaries, but cannot forcibly delete data stored inside third-party cloud provider logs.
* **Memory & Storage**: High-frequency tool execution produces receipt records in SQLite; periodic cleanup or pruning may be configured.

---

## License

This project is licensed under the [MIT License](LICENSE).
