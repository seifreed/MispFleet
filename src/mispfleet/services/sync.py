"""Bidirectional synchronization: enumerate, plan and apply per direction."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mispfleet.client import MispClient
from mispfleet.exceptions import MispFleetError
from mispfleet.models.plan import ConflictAction, CopyPlan
from mispfleet.models.sync import (
    SyncConflict,
    SyncConflictStrategy,
    SyncDirection,
    SyncJobSpec,
    SyncPlan,
    SyncResult,
)
from mispfleet.policies.engine import PolicyEngine
from mispfleet.services.copy import apply_copy_plan, build_copy_plan


def _index_by_uuid(entries: list[dict[str, Any]]) -> dict[str, str | None]:
    return {
        str(entry["uuid"]): (str(entry["timestamp"]) if entry.get("timestamp") else None)
        for entry in entries
        if entry.get("uuid")
    }


def _as_int(timestamp: str | None) -> int:
    return int(timestamp) if timestamp and timestamp.isdigit() else 0


def _conflict_resolution(
    job: SyncJobSpec,
    left_timestamp: str | None,
    right_timestamp: str | None,
) -> str:
    """Decide the flow for one diverging event, honoring the job direction."""
    strategy = job.on_conflict
    if strategy is SyncConflictStrategy.PREFER_LEFT:
        wanted = "copy-left-to-right"
    elif strategy is SyncConflictStrategy.PREFER_RIGHT:
        wanted = "copy-right-to-left"
    elif strategy is SyncConflictStrategy.NEWER_WINS:
        if _as_int(left_timestamp) >= _as_int(right_timestamp):
            wanted = "copy-left-to-right"
        else:
            wanted = "copy-right-to-left"
    else:
        return "skip"
    if wanted == "copy-left-to-right" and job.direction is SyncDirection.PULL:
        return "skip"
    if wanted == "copy-right-to-left" and job.direction is SyncDirection.PUSH:
        return "skip"
    return wanted


async def plan_sync(
    left: MispClient,
    right: MispClient,
    engine: PolicyEngine,
    job_name: str,
    job: SyncJobSpec,
) -> SyncPlan:
    """Build a reviewable synchronization plan without mutating anything."""
    left_index = _index_by_uuid(await left.events.index(job.filter_tags))
    right_index = _index_by_uuid(await right.events.index(job.filter_tags))
    copies_left_to_right: list[CopyPlan] = []
    copies_right_to_left: list[CopyPlan] = []
    conflicts: list[SyncConflict] = []
    in_sync = 0

    if job.direction in (SyncDirection.PUSH, SyncDirection.BOTH):
        for event_uuid in sorted(set(left_index) - set(right_index)):
            copies_left_to_right.append(
                await build_copy_plan(
                    left, right, event_uuid, engine, policy=job.policy_left_to_right
                )
            )
    if job.direction in (SyncDirection.PULL, SyncDirection.BOTH):
        for event_uuid in sorted(set(right_index) - set(left_index)):
            copies_right_to_left.append(
                await build_copy_plan(
                    right, left, event_uuid, engine, policy=job.policy_right_to_left
                )
            )
    for event_uuid in sorted(set(left_index) & set(right_index)):
        left_event = await left.events.get(event_uuid)
        right_event = await right.events.get(event_uuid)
        if left_event.canonical_fingerprint() == right_event.canonical_fingerprint():
            in_sync += 1
            continue
        resolution = _conflict_resolution(job, left_event.timestamp, right_event.timestamp)
        conflicts.append(
            SyncConflict(
                event_uuid=event_uuid,
                left_timestamp=left_event.timestamp,
                right_timestamp=right_event.timestamp,
                resolution=resolution,
            )
        )
        if resolution == "copy-left-to-right":
            copies_left_to_right.append(
                await build_copy_plan(
                    left,
                    right,
                    event_uuid,
                    engine,
                    policy=job.policy_left_to_right,
                    on_conflict=ConflictAction.UPDATE,
                )
            )
        elif resolution == "copy-right-to-left":
            copies_right_to_left.append(
                await build_copy_plan(
                    right,
                    left,
                    event_uuid,
                    engine,
                    policy=job.policy_right_to_left,
                    on_conflict=ConflictAction.UPDATE,
                )
            )
    return SyncPlan(
        plan_id=uuid4(),
        job=job_name,
        left_server=left.config.name,
        right_server=right.config.name,
        generated_at=datetime.now(tz=UTC),
        copies_left_to_right=copies_left_to_right,
        copies_right_to_left=copies_right_to_left,
        conflicts=conflicts,
        in_sync=in_sync,
    )


async def apply_sync(left: MispClient, right: MispClient, plan: SyncPlan) -> SyncResult:
    """Apply every proposed copy, tolerating per-event failures."""
    result = SyncResult(plan_id=plan.plan_id)
    for source, destination, copies in (
        (left, right, plan.copies_left_to_right),
        (right, left, plan.copies_right_to_left),
    ):
        for copy in copies:
            try:
                result.applied.append(await apply_copy_plan(source, destination, copy))
            except MispFleetError as error:
                result.failures[str(copy.source_event_uuid)] = error.message
    return result
