"""Plan and apply a configured synchronization job between two servers.

Run with: python examples/sync_fleet.py config.yml JOB_NAME
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mispfleet import MispFleet


async def main(config_path: Path, job_name: str) -> None:
    async with await MispFleet.from_file(config_path, interactive=False) as fleet:
        plan = await fleet.plan_sync(job_name)
        print(
            f"plan {plan.plan_id}: "
            f"{len(plan.copies_left_to_right)} left→right, "
            f"{len(plan.copies_right_to_left)} right→left, "
            f"{len(plan.conflicts)} conflict(s), {plan.in_sync} in sync"
        )
        if plan.blocked:
            print("plan has blocking errors; not applying", file=sys.stderr)
            return
        result = await fleet.apply_sync(plan)
        print(f"applied {len(result.applied)} change(s), {len(result.failures)} failure(s)")
        for event_uuid, message in sorted(result.failures.items()):
            print(f"  failed {event_uuid}: {message}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]), sys.argv[2]))
