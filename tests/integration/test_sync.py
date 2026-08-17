"""Integration tests for bidirectional synchronization between real servers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from mispfleet import MispFleet
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.models.event import MISPEvent
from mispfleet.models.server import ServerConfig
from mispfleet.models.sync import SyncConflictStrategy, SyncDirection, SyncJobSpec, SyncPlan
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


async def test_apply_sync_records_unexpected_failures(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """A copy raising something untyped is recorded, not left half-applied."""
    from mispfleet.models.plan import CopyPlan
    from mispfleet.services.sync import apply_sync

    broken = CopyPlan(
        plan_id=uuid4(),
        source_server="left",
        destination_server="right",
        source_event_uuid=UUID(UUID_LEFT),
        source_fingerprint="fp",
        generated_at=datetime.now(tz=UTC),
        proposed_event=MISPEvent(uuid=UUID_LEFT, info="broken"),
    )
    plan = SyncPlan(
        plan_id=uuid4(),
        job="job",
        left_server="left",
        right_server="right",
        generated_at=datetime.now(tz=UTC),
        copies_left_to_right=[broken],
    )

    class Namespace:
        def __getattr__(self, item: str) -> Any:
            raise TypeError("malformed client namespace")

    class Stub:
        def __init__(self, name: str) -> None:
            self.config = type("C", (), {"name": name, "read_only": False})()
            self.events = Namespace()
            self.system = Namespace()

    result = await apply_sync(Stub("left"), Stub("right"), plan)  # type: ignore[arg-type]
    eq(result.applied, [])
    contains(result.failures[UUID_LEFT], "unexpected")


async def test_a_transforming_policy_converges_after_one_apply(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """Re-planning after apply must not re-propose the copy it just made.

    The in-sync check compares fingerprints; what apply writes is the
    policy-transformed event, so comparing the raw source against the
    destination made every transforming job diverge permanently.
    """
    fake_misp.add_event(event(UUID_LEFT, "Enriched", "100"))
    policies = {"outbound": PolicySpec(add_tags={"synced-by:mispfleet"})}
    job = SyncJobSpec(
        left="left",
        right="right",
        direction=SyncDirection.PUSH,
        policy_left_to_right="outbound",
    )
    async with fleet_for(fake_misp, second_fake_misp, job, policies=policies) as fleet:
        first = await fleet.plan_sync("job")
        eq(len(first.copies_left_to_right), 1)
        ok((await fleet.apply_sync(first)).complete)

        second = await fleet.plan_sync("job")
        eq(len(second.copies_left_to_right), 0)
        eq(second.conflicts, [])
        eq(second.in_sync, 1)


async def test_an_untagged_destination_copy_is_a_conflict_not_a_fresh_copy(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """The indexes are tag-scoped; existence on the destination is not.

    An event the destination held without the job's filter tag looked
    one-sided, so it was planned as a fresh copy whose default ABORT blocked
    on destination-conflict — and apply_sync failed on that dead plan on every
    run, forever, with no strategy able to resolve it.
    """
    fake_misp.add_event(event(UUID_SHARED, "Tagged on the left", "200", tags=["sync:me"]))
    second_fake_misp.add_event(event(UUID_SHARED, "Untagged on the right", "100", tags=["other"]))
    job = SyncJobSpec(
        left="left",
        right="right",
        filter_tags={"sync:me"},
        on_conflict=SyncConflictStrategy.NEWER_WINS,
    )
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq([conflict.event_uuid for conflict in plan.conflicts], [UUID_SHARED])
        for copy in plan.copies_left_to_right:
            eq(copy.blocking_errors, [])
        result = await fleet.apply_sync(plan)
    ok(result.complete)
    eq(result.failures, {})
    eq(second_fake_misp.events[UUID_SHARED]["info"], "Tagged on the left")


async def test_an_untagged_left_copy_is_a_conflict_when_pulling(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """The pull direction has the same tag-scoped blind spot as the push."""
    second_fake_misp.add_event(event(UUID_SHARED, "Tagged on the right", "200", tags=["sync:me"]))
    fake_misp.add_event(event(UUID_SHARED, "Untagged on the left", "100", tags=["other"]))
    job = SyncJobSpec(
        left="left",
        right="right",
        direction=SyncDirection.PULL,
        filter_tags={"sync:me"},
        on_conflict=SyncConflictStrategy.NEWER_WINS,
    )
    async with fleet_for(fake_misp, second_fake_misp, job) as fleet:
        plan = await fleet.plan_sync("job")
        eq([conflict.event_uuid for conflict in plan.conflicts], [UUID_SHARED])
        result = await fleet.apply_sync(plan)
    eq(result.failures, {})
    eq(fake_misp.events[UUID_SHARED]["info"], "Tagged on the right")
