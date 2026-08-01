# Parallel ownership freeze

Shared contracts: `src/core/authority.ts`, `test/authority-contract.test.ts`. Frozen before delegation.

Agent 1: `src/arena/**`, `test/arena/**`, `fixtures/arena/**`, `scripts/arena/**`, `docs/arena/**`.
Agent 2: `src/authority/**`, `test/authority/**`, `docs/authority/**`.
Agent 3: `src/containment/**`, `test/containment/**`, `fixtures/containment/**`, `scripts/containment/**`, `docs/containment/**`.
Agent 4: `src/forge/**`, `src/guard/**`, `test/forge/**`, `test/guard/**`, `docs/forge/**`.
Agent 5: `src/protocol/**`, `src/ui/**`, `test/protocol/**`, `test/ui/**`, `docs/protocol/**`.

Forbidden for all agents: shared contracts, `package.json`, `pnpm-lock.yaml`, `tsconfig*.json`, existing authorization core, storage, receipt signer, API, CLI, dashboard files.
