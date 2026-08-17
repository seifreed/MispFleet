"""Plan and apply a policy-governed event copy between two servers.

Run with: python examples/copy_with_policy.py config.yml EVENT_UUID research production
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mispfleet import MispFleet


async def main(config_path: Path, event_uuid: str, source: str, destination: str) -> None:
    async with await MispFleet.from_file(config_path, interactive=False) as fleet:
        plan = await fleet.plan_copy(event_uuid, source, destination)
        print(f"plan {plan.plan_id} fingerprint {plan.fingerprint()}")
        for transformation in plan.transformations:
            print(f"  transform: {transformation.action} {transformation.target}")
        if plan.blocking_errors:
            for issue in plan.blocking_errors:
                print(f"  blocking: {issue.code}: {issue.message}")
            return
        outcome = await fleet.apply(plan)
        print(f"applied={outcome.applied} destination_event={outcome.destination_event_uuid}")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]))
