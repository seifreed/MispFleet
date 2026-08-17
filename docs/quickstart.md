# Installation & Quick start

## Installation

```bash
python3.14 -m pip install mispfleet
```

Python 3.14 is the only supported runtime for the first major version.
Optional extras: `keyring` (OS keyring credentials), `mariadb` (shared state
backend), `telemetry` (OpenTelemetry metrics), `http2`, plus `docs`, `test` and
`dev` for development. `mispfleet[all]` installs every runtime extra.

## First steps (CLI)

```bash
mispfleet config init          # create the config file with 0600 permissions
mispfleet config add-server production \
  --url https://misp.company.example \
  --credential-key MISPFLEET_PRODUCTION_API_KEY --groups all
mispfleet config validate
mispfleet servers health --all
mispfleet search value evil.example --all --format json
```

## First steps (Python)

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

See `examples/` in the repository for runnable scripts.
