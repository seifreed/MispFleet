"""Fleet-wide health check tolerating partial failures.

Run with: python examples/health_check.py path/to/config.yml
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mispfleet import MispFleet
from mispfleet.fleet import ServerSelector


async def main(config_path: Path) -> None:
    async with await MispFleet.from_file(config_path, interactive=False) as fleet:
        result = await fleet.health(ServerSelector.all())
        for server, health in result.results.items():
            status = "ok" if health.reachable and health.authenticated else "DEGRADED"
            print(
                f"{server}: {status} version={health.misp_version} " f"latency={health.latency_ms}"
            )
        for server, error in result.errors.items():
            print(f"{server}: FAILED {error.kind}: {error.message}")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
