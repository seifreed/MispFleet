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
