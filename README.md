<p align="center">
  <img src="https://img.shields.io/badge/MispFleet-MISP%20Fleet%20Orchestration-blue?style=for-the-badge" alt="MispFleet">
</p>

<h1 align="center">MispFleet</h1>

<p align="center">
  <strong>Async Python library and CLI to operate many MISP instances as one coordinated fleet</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/mispfleet/"><img src="https://img.shields.io/pypi/v/mispfleet?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/mispfleet/"><img src="https://img.shields.io/pypi/pyversions/mispfleet?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/MispFleet/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/MispFleet/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/MispFleet/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/MispFleet/stargazers"><img src="https://img.shields.io/github/stars/seifreed/MispFleet?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/MispFleet/issues"><img src="https://img.shields.io/github/issues/seifreed/MispFleet?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**MispFleet** is not another thin wrapper around a single MISP REST API. Its differentiator is the orchestration layer: query, compare, govern, and synchronize multiple [MISP](https://www.misp-project.org/) instances through one consistent asynchronous interface — as a CLI or as a Python library.

### Key Features

| Feature | Description |
|---------|-------------|
| **Fleet orchestration** | Multi-instance config with server groups, roles, and tags |
| **Async client** | Non-blocking MISP HTTP client (`httpx`), usable standalone |
| **Bounded concurrency** | Concurrent fleet-wide execution with failure policies |
| **Federated search** | Fleet-wide search that preserves source provenance |
| **Diff & safe copy** | Event comparison and two-stage copy (plan → apply) |
| **Synchronization** | Bidirectional sync jobs with conflict-resolution strategies |
| **Policy engine** | Tag, distribution, and content governance |
| **Threat-intel export** | STIX 2.1 export, TAXII 2.1 push, OpenCTI integration |
| **Secure credentials** | Environment, OS keyring, interactive prompt, in-memory |
| **Durable state** | Local SQLite or shared MariaDB checkpoints and audit records |
| **Streaming** | Automatic pagination and memory-safe streaming |

### Supported Outputs

```text
Data           JSON, JSONL, YAML, terminal tables
Threat Intel   STIX 2.1 export, TAXII 2.1 push, OpenCTI
State          SQLite (local) or MariaDB (shared) checkpoints & audit
Credentials    env vars, OS keyring, interactive prompt, in-memory
```

---

## Why MispFleet if PyMISP already exists?

[PyMISP](https://github.com/MISP/PyMISP) is the official Python library for MISP, and it is excellent at what it does: a rich, typed object model (`MISPEvent`, `MISPAttribute`, `MISPObject`, …) over the REST API of **one** MISP instance. If you work against a single server, PyMISP is the right tool — and MispFleet does **not** replace it.

MispFleet solves a different problem: **operating many MISP instances as one coordinated fleet.** PyMISP gives you `PyMISP(url, key)`, a single synchronous connection; everything beyond that — iterating over servers, running requests concurrently, aggregating partial failures, preserving provenance, comparing or reconciling instances — is left for you to hand-roll. MispFleet makes that orchestration layer a first-class, typed, tested library.

| | PyMISP (official) | MispFleet |
|---|---|---|
| **Scope** | One MISP instance per client | A fleet: many instances with groups, roles, tags |
| **Transport** | Synchronous (`requests`) ¹ | Asynchronous (`httpx`) with bounded concurrency |
| **Failures** | Per-call exceptions | Partial-fleet failures as data + failure policies |
| **Search** | Query one server | Federated search that preserves source provenance |
| **Compare instances** | — | Deterministic event diff between servers |
| **Move data safely** | Manual add/update | Two-stage copy: `plan` (credential-free) → `apply` (re-validated) |
| **Keep instances in sync** | — | Bidirectional sync jobs with conflict-resolution strategies |
| **Governance** | — | Policy engine (tag / distribution / content) applied on transfer |
| **State & audit** | — | Durable SQLite / MariaDB checkpoints and audit records |
| **Interop export** | — | STIX 2.1, TAXII 2.1 push, OpenCTI |
| **Interface** | Library | CLI **and** typed library |

¹ An experimental `pymisp-async` (aiohttp) exists as a separate project; the mainline PyMISP is synchronous.

In short: **use PyMISP to talk to a MISP instance; use MispFleet to run a set of them.** The two are complementary — MispFleet ships its own async client rather than wrapping PyMISP, but they target different layers of the same problem. For deep single-instance API coverage and MISP's canonical object generators, reach for PyMISP; for fleet-wide search, diffing, governed copy, and synchronization, reach for MispFleet.

---

## Installation

### From PyPI (Recommended)

```bash
python3.14 -m pip install mispfleet
```

Python 3.14 is the only supported runtime for the first major version.

### From Source

```bash
git clone https://github.com/seifreed/MispFleet.git
cd MispFleet
python3.14 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

### Optional Extras

```bash
pip install "mispfleet[all]"       # keyring + mariadb + telemetry + http2
pip install "mispfleet[keyring]"   # OS keyring credential provider
pip install "mispfleet[mariadb]"   # shared MariaDB state backend
pip install "mispfleet[telemetry]" # OpenTelemetry metrics
pip install "mispfleet[http2]"     # HTTP/2 transport
```

---

## Quick Start

```bash
# Create and validate a fleet configuration
mispfleet config init
mispfleet config validate

# Check health across every configured server
mispfleet servers health --all

# Federated search across the fleet
mispfleet search value evil.example --all --format json
```

---

## Usage

### Command Line Interface

```bash
# Compare one event between two servers
mispfleet event diff EVENT_UUID --left production --right research

# Plan a copy without mutating anything, then apply the reviewed plan
mispfleet event copy EVENT_UUID --from research --to production --dry-run
mispfleet apply plan.json
```

### Main Commands

| Command | Description |
|--------|-------------|
| `mispfleet config` | Create, validate, and edit fleet configuration |
| `mispfleet servers` | Per-server health and capability checks |
| `mispfleet search` | Federated search preserving source provenance |
| `mispfleet event` | Retrieve, diff, and safely copy events (plan / apply) |
| `mispfleet attribute` | Attribute-level operations across the fleet |
| `mispfleet policy` | Tag, distribution, and content governance policies |
| `mispfleet sync` | Bidirectional synchronization jobs |
| `mispfleet sightings` | Federated sightings |
| `mispfleet stix` | STIX 2.1 export |
| `mispfleet opencti` | Push to OpenCTI |
| `mispfleet state` | Inspect and prune local state |
| `mispfleet plugins` | Manage plugins |
| `mispfleet apply` | Re-validate and apply a copy plan |

---

## Python Library

### Basic Usage

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

---

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

API keys are never stored in the configuration file: credentials are references to environment variables, the OS keyring, an interactive prompt, or in-memory values.

---

## Safety Model

- Read operations run directly; mutating and cross-server operations support plan and dry-run modes.
- Copying an event is a two-stage operation: `plan` produces a deterministic, credential-free plan file; `apply` re-validates it before mutating anything.
- Partial fleet failures are represented as data, never as silent total success.
- Secrets are redacted from logs, exceptions, plans, and debug output.

---

## Requirements

- Python 3.14
- See [pyproject.toml](pyproject.toml) for dependencies and extras

---

## Development

```bash
python3.14 -m venv .venv && .venv/bin/pip install -e '.[dev]'
black --check . && ruff check . && mypy .
pytest
bandit -r . && pip-audit
```

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/MispFleet](https://github.com/seifreed/MispFleet)

---

<p align="center">
  <sub>Built for practical multi-instance MISP operations and threat-intel automation</sub>
</p>
