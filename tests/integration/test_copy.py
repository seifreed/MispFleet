"""Integration tests for event diff, copy planning and safe application."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mispfleet import MispFleet
from mispfleet.client import MispClient
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import StalePlanError, UnsafePlanError
from mispfleet.models.plan import ConflictAction
from mispfleet.models.server import ServerConfig
from mispfleet.policies.base import PolicySpec, RejectRules
from mispfleet.services.copy import apply_copy_plan
from mispfleet.state import MemoryStateBackend
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, not_contains, ok

EVENT_UUID = "9c5c1c2e-0000-4000-8000-00000000000e"

SOURCE_EVENT: dict[str, Any] = {
    "id": "7",
    "uuid": EVENT_UUID,
    "info": "Campaign X",
    "date": "2026-01-01",
    "published": True,
    "distribution": "3",
    "Tag": [{"name": "internal-only"}, {"name": "tlp:green"}],
    "Attribute": [
        {"type": "domain", "value": "evil.example", "comment": "internal detail"},
        {"type": "sha256", "value": "aa" * 32},
    ],
}

POLICIES = {
    "production-import": PolicySpec(
        remove_tags={"internal-only"},
        add_tags={"imported-by:mispfleet"},
        maximum_distribution="connected-communities",
        remove_comments=True,
    ),
    "strict": PolicySpec(reject_if=RejectRules(tags={"tlp:green"})),
}


def fleet_for(
    servers: dict[str, ServerConfig],
    state: MemoryStateBackend | None = None,
) -> MispFleet:
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(servers, policies=POLICIES, resolver=resolver, interactive=False, state=state)


def two_servers(source: FakeMisp, destination: FakeMisp) -> dict[str, ServerConfig]:
    return {
        "research": config_for(source, name="research"),
        "production": config_for(destination, name="production"),
    }


async def test_compare_event_across_servers(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    changed = dict(SOURCE_EVENT)
    changed["info"] = "Campaign X (edited)"
    second_fake_misp.add_event(changed)
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        diff = await fleet.compare_event(EVENT_UUID, "research", "production")
    ok(not diff.equivalent)
    eq(diff.left_server, "research")
    eq(diff.summary.changed, 1)
    same = dict(SOURCE_EVENT)
    second_fake_misp.add_event(same)
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        diff = await fleet.compare_event(EVENT_UUID, "research", "production")
    ok(diff.equivalent)


async def test_plan_copy_applies_policy_without_mutating_destination(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production", "production-import")
    eq(plan.blocking_errors, [])
    eq(second_fake_misp.events, {})
    proposed = plan.proposed_event
    contains(proposed.tags, "imported-by:mispfleet")
    not_contains(proposed.tags, "internal-only")
    eq(proposed.distribution, "2")
    eq(proposed.attributes[0].comment, "")
    not_contains(plan.model_dump_json(), API_KEY)
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        regenerated = await fleet.plan_copy(
            EVENT_UUID, "research", "production", "production-import"
        )
    eq(plan.fingerprint(), regenerated.fingerprint())
    ok(plan.plan_id != regenerated.plan_id)


async def test_plan_copy_blocks_on_policy_violation(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production", "strict")
        codes = [issue.code for issue in plan.blocking_errors]
        contains(codes, "policy-violation")
        with pytest.raises(UnsafePlanError):
            await fleet.apply(plan)
    eq(second_fake_misp.events, {})


async def test_plan_copy_blocks_on_read_only_destination(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    servers = two_servers(fake_misp, second_fake_misp)
    servers["production"] = config_for(second_fake_misp, name="production", read_only=True)
    async with fleet_for(servers) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production")
    contains([issue.code for issue in plan.blocking_errors], "destination-read-only")


async def test_plan_copy_blocks_on_unreachable_destination(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    servers = {
        "research": config_for(fake_misp, name="research"),
        "production": config_for(
            fake_misp, name="production", url="http://127.0.0.1:9", connect_timeout=0.5
        ),
    }
    async with fleet_for(servers) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production")
    contains([issue.code for issue in plan.blocking_errors], "destination-unreachable")


async def test_plan_copy_conflict_actions(fake_misp: FakeMisp, second_fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    second_fake_misp.add_event(dict(SOURCE_EVENT))
    servers = two_servers(fake_misp, second_fake_misp)
    async with fleet_for(servers) as fleet:
        aborted = await fleet.plan_copy(EVENT_UUID, "research", "production")
        contains([issue.code for issue in aborted.blocking_errors], "destination-conflict")
        skipped = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.SKIP
        )
        eq(skipped.blocking_errors, [])
        renewed = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.CREATE_NEW_UUID
        )
        eq(renewed.blocking_errors, [])
        ok(renewed.proposed_event.uuid != EVENT_UUID)
        skip_result = await fleet.apply(skipped)
        ok(not skip_result.applied)
        contains(skip_result.messages[0], "skipped")


async def test_apply_valid_plan_creates_event_and_records_audit(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    state = MemoryStateBackend()
    async with fleet_for(two_servers(fake_misp, second_fake_misp), state=state) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production", "production-import")
        result = await fleet.apply(plan)
    ok(result.applied)
    eq(str(result.destination_event_uuid), EVENT_UUID)
    stored = second_fake_misp.events[EVENT_UUID]
    tag_names = {tag["name"] for tag in stored["Tag"]}
    contains(tag_names, "imported-by:mispfleet")
    not_contains(tag_names, "internal-only")
    operations = await state.list_operations()
    eq(len(operations), 1)
    eq(operations[0].result, "applied")
    eq(operations[0].policy, "production-import")
    eq(operations[0].plan_fingerprint, plan.fingerprint())
    not_contains(operations[0].model_dump_json(), API_KEY)


async def test_apply_update_conflict_action_updates_existing_event(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    stale = dict(SOURCE_EVENT)
    stale["info"] = "Old copy"
    second_fake_misp.add_event(stale)
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.UPDATE
        )
        result = await fleet.apply(plan)
    ok(result.applied)
    contains(result.messages[0], "updated")
    eq(second_fake_misp.events[EVENT_UUID]["info"], "Campaign X")


async def test_apply_rejects_stale_plan_when_source_changed(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    state = MemoryStateBackend()
    async with fleet_for(two_servers(fake_misp, second_fake_misp), state=state) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production")
        changed = dict(SOURCE_EVENT)
        changed["info"] = "Campaign X (edited after planning)"
        fake_misp.add_event(changed)
        with pytest.raises(StalePlanError):
            await fleet.apply(plan)
    eq(second_fake_misp.events, {})
    operations = await state.list_operations()
    eq(operations[0].result, "failed")
    ok(operations[0].error is not None)


async def test_apply_rejects_expired_and_mismatched_plans(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production")
        expired = plan.model_copy(
            update={"expires_at": datetime.now(tz=UTC) - timedelta(minutes=1)}
        )
        with pytest.raises(StalePlanError):
            await fleet.apply(expired)
        research = fleet.client("research")
        production = fleet.client("production")
        with pytest.raises(UnsafePlanError) as source_mismatch:
            await apply_copy_plan(production, production, plan)
        contains(str(source_mismatch.value), "plan source")
        with pytest.raises(UnsafePlanError) as dest_mismatch:
            await apply_copy_plan(research, research, plan)
        contains(str(dest_mismatch.value), "plan destination")
        read_only_dest = MispClient(
            config_for(second_fake_misp, name="production", read_only=True), api_key=API_KEY
        )
        try:
            with pytest.raises(UnsafePlanError) as read_only:
                await apply_copy_plan(research, read_only_dest, plan)
            contains(str(read_only.value), "read-only")
        finally:
            await read_only_dest.aclose()


async def test_apply_rejects_conflict_that_appeared_after_planning(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production")
        second_fake_misp.add_event(dict(SOURCE_EVENT))
        with pytest.raises(UnsafePlanError) as excinfo:
            await fleet.apply(plan)
        contains(str(excinfo.value), "no implicit overwrite")
