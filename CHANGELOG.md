# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial project scaffolding: packaging, quality gates and governance documents.
- Multi-instance configuration model with groups, roles and credential references.
- Async MISP HTTP transport with retry, redaction and error mapping.
- Single-server async client with service namespaces and pagination.
- Fleet execution layer: registry, selectors, bounded concurrent executor.
- Federated search, health checks, event diff and copy plan/apply services.
- Policy engine with configuration-driven built-in policies.
- SQLite and in-memory state backends.
- Typer-based CLI with JSON, JSONL, YAML and table output.
- MariaDB state backend for shared operational state (`mariadb` extra).
- Declarative bidirectional synchronization jobs with conflict strategies.
- STIX 2.1 export and TAXII 2.1 push client.
- OpenCTI integration pushing STIX bundles over GraphQL.
- Normalized models for object references, galaxies, sightings, proposals,
  sharing groups and attachment payloads.
- Complete search criteria: organisations, threat level, analysis level,
  object name, timestamp range, distribution and numeric event id, with
  matching CLI filters.
- Event diff over object references, galaxies, sightings and proposals, plus
  the `--format patch` output; objects are keyed by UUID.
- Policy operations for value redaction, organisation and sharing-group
  mapping, `to_ids` enforcement, attribute-level rejection, unsupported-object
  rejection and attachment size limits.
- Real TLS certificate expiry in health checks and a capability cache in the
  state backends with TTL and explicit invalidation (`--refresh`).
- `mispfleet attribute` command group (with `--download`) and
  `mispfleet completion` for bash, zsh and fish.
- Optional HTTP/2 (`http2` extra), configurable keepalive and response-size
  limits, a metrics callback sink and structured log context.
- `--no-verify-tls` with a visible warning, `security.forbid_insecure_tls`,
  and attachment safety helpers (filename sanitization, secure temporary
  files, archive traversal and symlink rejection).
- `docs` and `test` extras, TestPyPI validation stage, build provenance
  attestations, gitleaks secret scanning and a pinned `requirements.lock`.
- Contract tests against real MISP releases, performance targets, snapshot
  tests and additional property-based tests.
- Documentation for server groups, error handling, migration and the
  multiserver acceptance runbook.
