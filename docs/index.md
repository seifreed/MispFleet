# MispFleet

MispFleet is an asynchronous Python library and CLI for operating multiple
[MISP](https://www.misp-project.org/) instances as a coordinated fleet.

Its differentiator is the orchestration layer: query, compare, govern and
synchronize multiple MISP instances through one consistent asynchronous
interface — without losing source provenance, security boundaries or
operational control.

## Core capabilities

- **Multi-instance configuration** with groups, roles, tags and per-server limits.
- **Federated search** running concurrently across servers, preserving provenance.
- **Health and capability discovery** distinguishing DNS, TLS, authentication,
  permission and application failures.
- **Event comparison** with deterministic, classified differences.
- **Safe event copy** through an explicit plan → validate → apply workflow.
- **Policy engine** governing tags, distribution and content before mutation.
- **Secure credentials** resolved from environment, OS keyring, prompt or memory —
  never stored in configuration or state.
- **Local SQLite state** for checkpoints and secret-free audit records.

## Design principles

1. Library first — the CLI is a thin presentation layer over the public API.
2. Async by default — all network operations are asynchronous (`httpx` + `asyncio.TaskGroup`).
3. Multiserver by design — the fleet is a first-class abstraction.
4. Safe by default — mutations require explicit plans and re-validation.
5. Partial failure tolerance — one down server never silently poisons a result.
6. Typed everywhere — public APIs, models and exceptions are fully typed (`py.typed`).
