# MispFleet

Async Python library and CLI to operate multiple [MISP](https://www.misp-project.org/)
instances as a coordinated fleet.

MispFleet is not another thin wrapper around a single MISP REST API. Its differentiator
is the orchestration layer: query, compare, govern and synchronize multiple MISP
instances through one consistent asynchronous interface.

## Features

- Multi-instance configuration with server groups, roles and tags.
- Asynchronous MISP HTTP client (`httpx`) usable standalone.
- Concurrent fleet-wide execution with bounded concurrency and failure policies.
- Federated search preserving source provenance.
- Automatic pagination and memory-safe streaming.
- Health and capability checks per server.
- Event retrieval, comparison (diff) and safe copy with plan / dry-run / apply.
- Policy engine for tag, distribution and content governance.
- Secure credential resolution (environment, OS keyring, prompt, in-memory).
- Local SQLite state for checkpoints and audit records.
- JSON, JSONL, YAML and terminal-table output.

## Installation

```bash
python3.14 -m pip install mispfleet
```

Python 3.14 is the only supported runtime for the first major version.

## Quick start (CLI)

```bash
mispfleet config init
mispfleet config validate
mispfleet servers health --all
mispfleet search value evil.example --all --format json
mispfleet event diff EVENT_UUID --left production --right research
mispfleet event copy EVENT_UUID --from research --to production --dry-run
```

## Quick start (Python)

```python
import asyncio
from pathlib import Path

from mispfleet import MispFleet, SearchQuery, ServerSelector


async def main() -> None:
    async with await MispFleet.from_file(Path("mispfleet.yml")) as fleet:
        result = await fleet.search(
            SearchQuery(value="evil.example", metadata_only=True),
            selector=ServerSelector.group("all"),
        )
        for match in result.matches:
            print(match.server, match.event_uuid)


if __name__ == "__main__":
    asyncio.run(main())
```

## Configuration

```yaml
version: 1
defaults:
  verify_tls: true
  request_timeout: 60
  connect_timeout: 10
  concurrency: 5
servers:
  production:
    url: https://misp.company.example
    credential:
      provider: env
      key: MISPFLEET_PRODUCTION_API_KEY
    role: primary
    groups: [internal, all]
  partner-cert:
    url: https://misp.partner.example
    credential:
      provider: env
      key: MISPFLEET_PARTNER_CERT_API_KEY
    role: partner
    read_only: true
    groups: [partners, all]
```

API keys are never stored in the configuration file: credentials are references to
environment variables, the OS keyring, an interactive prompt or in-memory values.

## Safety model

- Read operations run directly; mutating and cross-server operations support plan
  and dry-run modes.
- Copying an event is a two-stage operation: `plan` produces a deterministic,
  credential-free plan file; `apply` re-validates it before mutating anything.
- Partial fleet failures are represented as data, never as silent total success.
- Secrets are redacted from logs, exceptions, plans and debug output.

## Development

```bash
python3.14 -m venv .venv && .venv/bin/pip install -e '.[dev]'
black --check . && ruff check . && mypy .
pytest
bandit -r . && pip-audit
```

## License

Apache-2.0. See [LICENSE](LICENSE).
