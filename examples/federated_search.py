"""Federated search across every configured server, preserving provenance.

Run with: python examples/federated_search.py path/to/config.yml VALUE
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mispfleet import MispFleet, SearchQuery, ServerSelector


async def main(config_path: Path, value: str) -> None:
    async with await MispFleet.from_file(config_path, interactive=False) as fleet:
        result = await fleet.search(
            SearchQuery(value=value, metadata_only=True),
            selector=ServerSelector.all(),
        )
        for match in result.matches:
            print(match.server, match.attribute_type, match.value, match.event_uuid)
        for server, error in result.errors.items():
            print(f"warning: {server} failed: {error.message}", file=sys.stderr)
        if result.partial:
            print("result is partial", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]), sys.argv[2]))
