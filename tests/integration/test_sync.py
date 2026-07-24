"""Integration tests for bidirectional synchronization between real servers."""

from __future__ import annotations

from typing import Any

import pytest

from mispfleet import MispFleet
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.models.server import ServerConfig
from mispfleet.models.sync import SyncConflictStrategy, SyncDirection, SyncJobSpec
from mispfleet.policies.base import PolicySpec, RejectRules
from mispfleet.state import MemoryStateBackend
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, not_contains, ok

UUID_LEFT = "11111111-0000-4000-8000-000000000001"
UUID_RIGHT = "22222222-0000-4000-8000-000000000002"
UUID_SHARED = "33333333-0000-4000-8000-000000000003"


def event(uuid: str, info: str, timestamp: str, tags: list[str] | None = None) -> dict[str, Any]:
    return {
        "uuid": uuid,
        "info": info,
        "timestamp": timestamp,
        "Tag": [{"name": name} for name in (tags or ["sync:me"])],
        "Attribute": [{"type": "domain", "value": f"{info.lower().replace(' ', '')}.example"}],
    }


def fleet_for(
    left: FakeMisp,
    right: FakeMisp,
    job: SyncJobSpec,
    policies: dict[str, PolicySpec] | None = None,
    state: MemoryStateBackend | None = None,
    right_read_only: bool = False,
) -> MispFleet:
    servers: dict[str, ServerConfig] = {
        "left": config_for(left, name="left"),
        "right": config_for(right, name="right", read_only=right_read_only),
    }
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(
        servers,
        policies=policies,
        sync_jobs={"job": job},
        resolver=resolver,
        interactive=False,
        state=state,
    )


async def test_bidirectional_sync_copies_missing_events_both_ways(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Left only", "100"))
    fake_misp.add_event(event(UUID_SHARED, "Shared", "100"))
    second_fake_misp.add_event(event(UUID_RIGHT, "Right only", "100"))
    second_fake_misp.add_event(event(UUID_SHARED, "Shared", "100"))
    state = MemoryStateBackend()
    job = SyncJobSpec(left="left", right="right")
    async with fleet_for(fake_misp, second_fake_misp, job, state=state) as fleet:
        plan = await fleet.plan_sync("job")
        eq([str(c.source_event_uuid) for c in plan.copies_left_to_right], [UUID_LEFT])
        eq([str(c.source_event_uuid) for c in plan.copies_right_to_left], [UUID_RIGHT])
        eq(plan.in_sync, 1)
        eq(plan.conflicts, [])
        ok(not plan.blocked)
        result = await fleet.apply_sync(plan)
    ok(result.complete)
    eq(len(result.applied), 2)
    contains(second_fake_misp.events, UUID_LEFT)
    contains(fake_misp.events, UUID_RIGHT)
    operations = await state.list_operations()
    eq(operations[0].kind, "sync-apply")
    contains(operations[0].result, "2 applied")


async def test_push_direction_never_pulls(fake_misp: FakeMisp, second_fake_misp: FakeMisp) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Left only", "100"))
    second_fake_misp.add_event(event(UUID_RIGHT, "Right only", "100"))
    job = SyncJobSpec(left="left", right="right", direction=SyncDirection.PUSH)
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq(len(plan.copies_left_to_right), 1)
        eq(plan.copies_right_to_left, [])
        await fleet.apply_sync(plan)
    not_contains(fake_misp.events, UUID_RIGHT)
    contains(second_fake_misp.events, UUID_LEFT)


async def test_pull_direction_never_pushes(fake_misp: FakeMisp, second_fake_misp: FakeMisp) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Left only", "100"))
    second_fake_misp.add_event(event(UUID_RIGHT, "Right only", "100"))
    job = SyncJobSpec(left="left", right="right", direction=SyncDirection.PULL)
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.copies_left_to_right, [])
        eq(len(plan.copies_right_to_left), 1)


async def test_conflicts_skipped_by_default(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_SHARED, "Version A", "100"))
    second_fake_misp.add_event(event(UUID_SHARED, "Version B", "200"))
    job = SyncJobSpec(left="left", right="right")
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.total_copies, 0)
        eq(len(plan.conflicts), 1)
        eq(plan.conflicts[0].resolution, "skip")
        result = await fleet.apply_sync(plan)
    ok(result.complete)
    eq(fake_misp.events[UUID_SHARED]["info"], "Version A")
    eq(second_fake_misp.events[UUID_SHARED]["info"], "Version B")


async def test_newer_wins_updates_the_stale_side(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_SHARED, "Old version", "100"))
    second_fake_misp.add_event(event(UUID_SHARED, "New version", "200"))
    job = SyncJobSpec(left="left", right="right", on_conflict=SyncConflictStrategy.NEWER_WINS)
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.conflicts[0].resolution, "copy-right-to-left")
        result = await fleet.apply_sync(plan)
    ok(result.complete)
    eq(fake_misp.events[UUID_SHARED]["info"], "New version")


async def test_newer_wins_prefers_left_on_tie_or_newer_left(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_SHARED, "Fresh left", "300"))
    second_fake_misp.add_event(event(UUID_SHARED, "Old right", "200"))
    job = SyncJobSpec(left="left", right="right", on_conflict=SyncConflictStrategy.NEWER_WINS)
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.conflicts[0].resolution, "copy-left-to-right")
        await fleet.apply_sync(plan)
    eq(second_fake_misp.events[UUID_SHARED]["info"], "Fresh left")


async def test_prefer_strategies_respect_direction(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_SHARED, "Version A", "100"))
    second_fake_misp.add_event(event(UUID_SHARED, "Version B", "200"))
    prefer_left = SyncJobSpec(
        left="left", right="right", on_conflict=SyncConflictStrategy.PREFER_LEFT
    )
    async with fleet_for(fake_misp, second_fake_misp, prefer_left) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.conflicts[0].resolution, "copy-left-to-right")
    blocked_by_direction = SyncJobSpec(
        left="left",
        right="right",
        direction=SyncDirection.PULL,
        on_conflict=SyncConflictStrategy.PREFER_LEFT,
    )
    async with fleet_for(fake_misp, second_fake_misp, blocked_by_direction) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.conflicts[0].resolution, "skip")
    prefer_right_push = SyncJobSpec(
        left="left",
        right="right",
        direction=SyncDirection.PUSH,
        on_conflict=SyncConflictStrategy.PREFER_RIGHT,
    )
    async with fleet_for(fake_misp, second_fake_misp, prefer_right_push) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.conflicts[0].resolution, "skip")
    prefer_right = SyncJobSpec(
        left="left", right="right", on_conflict=SyncConflictStrategy.PREFER_RIGHT
    )
    async with fleet_for(fake_misp, second_fake_misp, prefer_right) as fleet:
        plan = await fleet.plan_sync("job")
        eq(plan.conflicts[0].resolution, "copy-right-to-left")


async def test_filter_tags_limit_the_job_scope(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_LEFT, "In scope", "100", tags=["sync:me"]))
    fake_misp.add_event(event(UUID_SHARED, "Out of scope", "100", tags=["private"]))
    job = SyncJobSpec(left="left", right="right", filter_tags={"sync:me"})
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq([str(c.source_event_uuid) for c in plan.copies_left_to_right], [UUID_LEFT])


async def test_sync_policies_apply_per_direction(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Left only", "100"))
    policies = {"outbound": PolicySpec(add_tags={"synced-by:mispfleet"})}
    job = SyncJobSpec(left="left", right="right", policy_left_to_right="outbound")
    async with fleet_for(fake_misp, second_fake_misp, job, policies=policies) as fleet:
        plan = await fleet.plan_sync("job")
        result = await fleet.apply_sync(plan)
    ok(result.complete)
    stored = second_fake_misp.events[UUID_LEFT]
    contains({tag["name"] for tag in stored["Tag"]}, "synced-by:mispfleet")


async def test_blocked_copies_surface_as_failures(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Rejected", "100"))
    policies = {"strict": PolicySpec(reject_if=RejectRules(tags={"sync:me"}))}
    job = SyncJobSpec(left="left", right="right", policy_left_to_right="strict")
    async with fleet_for(fake_misp, second_fake_misp, job, policies=policies) as fleet:
        plan = await fleet.plan_sync("job")
        ok(plan.blocked)
        result = await fleet.apply_sync(plan)
    ok(not result.complete)
    contains(result.failures, UUID_LEFT)
    eq(second_fake_misp.events, {})


async def test_read_only_destination_blocks_and_reports(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Left only", "100"))
    job = SyncJobSpec(left="left", right="right", direction=SyncDirection.PUSH)
    async with fleet_for(fake_misp, second_fake_misp, job, right_read_only=True) as fleet:
        plan = await fleet.plan_sync("job")
        ok(plan.blocked)
        result = await fleet.apply_sync(plan)
    contains(result.failures[UUID_LEFT], "read-only")


async def test_unknown_sync_job_is_a_configuration_error(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    job = SyncJobSpec(left="left", right="right")
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        with pytest.raises(InvalidConfigurationError) as excinfo:
            await fleet.plan_sync("ghost")
        contains(str(excinfo.value), "ghost")


async def test_sync_plan_is_deterministic(fake_misp: FakeMisp, second_fake_misp: FakeMisp) -> None:
    fake_misp.add_event(event(UUID_LEFT, "Left only", "100"))
    second_fake_misp.add_event(event(UUID_RIGHT, "Right only", "100"))
    job = SyncJobSpec(left="left", right="right")
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        first = await fleet.plan_sync("job")
        second = await fleet.plan_sync("job")
    eq(
        [c.fingerprint() for c in first.copies_left_to_right],
        [c.fingerprint() for c in second.copies_left_to_right],
    )
    eq(
        [c.fingerprint() for c in first.copies_right_to_left],
        [c.fingerprint() for c in second.copies_right_to_left],
    )
