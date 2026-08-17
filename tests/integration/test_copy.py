"""Integration tests for event diff, copy planning and safe application."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mispfleet import MispFleet
from mispfleet.client import MispClient
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import ConflictError, NotFoundError, StalePlanError, UnsafePlanError
from mispfleet.models.attribute import MISPAttribute, MISPObject, ObjectReference
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import ConflictAction
from mispfleet.models.server import ServerConfig
from mispfleet.policies.base import PolicySpec, RejectRules
from mispfleet.redaction import REDACTED
from mispfleet.services.copy import apply_copy_plan
from mispfleet.state import MemoryStateBackend
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, ne, not_contains, not_none, ok

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
    "Object": [
        {
            "uuid": "cc000000-0000-4000-8000-000000000001",
            "name": "file",
            "Attribute": [
                {
                    "uuid": "cc000000-0000-4000-8000-000000000002",
                    "type": "sha256",
                    "value": "bb" * 32,
                }
            ],
            "ObjectReference": [
                {
                    "uuid": "cc000000-0000-4000-8000-000000000003",
                    "object_uuid": "cc000000-0000-4000-8000-000000000001",
                    "referenced_uuid": "cc000000-0000-4000-8000-000000000002",
                    "relationship_type": "contains",
                },
                {
                    "referenced_uuid": "cc000000-0000-4000-8000-000000000002",
                    "relationship_type": "derived-from",
                },
            ],
        }
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
    actor: str | None = None,
) -> MispFleet:
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(
        servers,
        policies=POLICIES,
        resolver=resolver,
        interactive=False,
        state=state,
        actor=actor,
    )


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


async def test_compare_event_reports_either_side_missing_as_a_typed_error(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """Both fetches are awaited, so neither side is left running orphaned.

    The typed NotFoundError must still reach the caller unchanged: the CLI
    maps it onto an exit code.
    """
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        with pytest.raises(NotFoundError):
            await fleet.compare_event(EVENT_UUID, "research", "production")
    second_fake_misp.add_event(dict(SOURCE_EVENT))
    fake_misp.events.clear()
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        with pytest.raises(NotFoundError):
            await fleet.compare_event(EVENT_UUID, "research", "production")


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


async def test_plan_metadata_and_actor_are_recorded(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    state = MemoryStateBackend()
    servers = two_servers(fake_misp, second_fake_misp)
    async with fleet_for(servers, state=state, actor="analyst@example") as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production", "production-import")
        await fleet.apply(plan)
    plans = await state.list_plans()
    eq(len(plans), 1)
    eq(plans[0].plan_id, plan.plan_id)
    eq(plans[0].fingerprint, plan.fingerprint())
    eq(plans[0].kind, "copy")
    eq(plans[0].policy, "production-import")
    eq(plans[0].source_server, "research")
    eq(plans[0].destination_server, "production")
    ok(plans[0].transformations > 0)
    not_contains(plans[0].model_dump_json(), API_KEY)
    operations = await state.list_operations()
    eq(operations[0].actor, "analyst@example")


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
        with pytest.raises(ConflictError) as excinfo:
            await fleet.apply(plan)
        contains(str(excinfo.value), "no implicit overwrite")


async def test_apply_honors_create_new_uuid_for_a_conflict_that_appeared_late(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """The plan-time new-uuid branch never runs when the event is absent.

    Apply then hit the conflict and refused outright, ignoring the resolution
    the operator had explicitly chosen.
    """
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.CREATE_NEW_UUID
        )
        eq(plan.proposed_event.uuid, EVENT_UUID)
        second_fake_misp.add_event(dict(SOURCE_EVENT))
        result = await fleet.apply(plan)
    ok(result.applied)
    ne(str(result.destination_event_uuid), EVENT_UUID)
    contains(result.messages[0], "new UUID")


async def test_apply_merge_unites_destination_and_proposed_content(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    existing = dict(SOURCE_EVENT)
    existing["Attribute"] = [
        {"type": "ip-dst", "value": "203.0.113.9", "uuid": "dd000000-0000-4000-8000-000000000001"}
    ]
    existing["Tag"] = [{"name": "reviewed"}]
    second_fake_misp.add_event(existing)
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.MERGE
        )
        result = await fleet.apply(plan)
    ok(result.applied)
    contains(result.messages[0], "merged")
    merged = second_fake_misp.events[EVENT_UUID]
    values = {(a["type"], a["value"]) for a in merged["Attribute"]}
    ok(("ip-dst", "203.0.113.9") in values)
    for attribute in SOURCE_EVENT["Attribute"]:
        ok((attribute["type"], attribute["value"]) in values)
    names = {tag["name"] for tag in merged["Tag"]}
    ok("reviewed" in names)


async def test_create_new_uuid_renumbers_children_so_the_copy_is_not_empty(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """Only the event UUID was regenerated.

    MISP enforces server-wide uniqueness for attribute and object UUIDs, so
    every child collided with the original event already on the destination
    and the "copy" arrived as an empty shell reporting success. Verified
    against MISP 2.5.44: 5 attributes became 0.
    """
    fake_misp.add_event(dict(SOURCE_EVENT))
    second_fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.CREATE_NEW_UUID
        )
        source = await fleet.client("research").events.get(EVENT_UUID)
    ne(plan.proposed_event.uuid, EVENT_UUID)
    eq(len(plan.proposed_event.attributes), len(source.attributes))
    original_uuids = {attribute.uuid for attribute in source.attributes if attribute.uuid}
    copied_uuids = {a.uuid for a in plan.proposed_event.attributes if a.uuid}
    eq(original_uuids & copied_uuids, set())
    for obj, source_object in zip(plan.proposed_event.objects, source.objects, strict=True):
        ne(obj.uuid, source_object.uuid)
        eq(len(obj.attributes), len(source_object.attributes))
        targets = {attribute.uuid for attribute in obj.attributes}
        for reference in obj.references:
            contains(targets, reference.referenced_uuid)


def test_merge_carries_over_objects_and_galaxies() -> None:
    """The merge united only attributes and tags.

    The reviewed plan promised an object-borne indicator and a galaxy; apply
    updated the destination without either ever arriving.
    """
    from mispfleet.models.event import Galaxy
    from mispfleet.services.copy import merge_events

    destination = MISPEvent(
        uuid=EVENT_UUID,
        info="destination",
        attributes=[MISPAttribute(type="domain", value="known.example")],
        galaxies=[
            Galaxy(name="Threat Actor", clusters={"APT-A"}),
            Galaxy(name="Ransomware", clusters={"Locker"}),
        ],
    )
    proposed = MISPEvent(
        uuid=EVENT_UUID,
        info="proposed",
        attributes=[MISPAttribute(type="domain", value="new.example")],
        objects=[
            MISPObject(
                uuid="bb000000-0000-4000-8000-000000000001",
                name="file",
                attributes=[MISPAttribute(type="sha256", value="d" * 64)],
            )
        ],
        galaxies=[Galaxy(name="Threat Actor", clusters={"APT-B"}), Galaxy(name="Tool")],
    )
    merged = merge_events(destination, proposed)
    eq(sorted(a.value for a in merged.attributes), ["known.example", "new.example"])
    eq([obj.name for obj in merged.objects], ["file"])
    galaxies = {galaxy.name: sorted(galaxy.clusters) for galaxy in merged.galaxies}
    eq(
        galaxies,
        {"Ransomware": ["Locker"], "Threat Actor": ["APT-A", "APT-B"], "Tool": []},
    )


def test_merge_does_not_duplicate_an_indicator_held_in_a_destination_object() -> None:
    from mispfleet.services.copy import merge_events

    destination = MISPEvent(
        uuid=EVENT_UUID,
        info="destination",
        objects=[
            MISPObject(name="file", attributes=[MISPAttribute(type="sha256", value="e" * 64)])
        ],
    )
    proposed = MISPEvent(
        uuid=EVENT_UUID,
        info="proposed",
        attributes=[MISPAttribute(type="sha256", value="e" * 64)],
    )
    eq(merge_events(destination, proposed).attributes, [])


async def test_apply_refuses_when_the_destination_changed_after_review(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """Only the source side was re-checked before a rewriting apply.

    An analyst enriching the destination between review and apply had their
    work silently overwritten with older content, reported as a success.
    """
    fake_misp.add_event(dict(SOURCE_EVENT))
    second_fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.UPDATE
        )
        ok(plan.destination_fingerprint is not None)
        enriched = dict(SOURCE_EVENT)
        enriched["Attribute"] = [
            *SOURCE_EVENT["Attribute"],
            {"type": "ip-dst", "value": "203.0.113.55"},
        ]
        second_fake_misp.add_event(enriched)
        with pytest.raises(StalePlanError) as excinfo:
            await fleet.apply(plan)
    contains(str(excinfo.value), "destination event changed")


async def test_apply_updates_when_the_destination_is_unchanged(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    second_fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(
            EVENT_UUID, "research", "production", on_conflict=ConflictAction.UPDATE
        )
        result = await fleet.apply(plan)
    ok(result.applied)


async def test_non_rewriting_plans_carry_no_destination_fingerprint(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.add_event(dict(SOURCE_EVENT))
    async with fleet_for(two_servers(fake_misp, second_fake_misp)) as fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "research", "production")
    eq(plan.destination_fingerprint, None)


def test_renumbering_covers_sightings_and_proposals() -> None:
    """Every UUID MISP treats as globally unique must be regenerated.

    In the create-new-uuid path the original event is still on the
    destination, so a sighting left pointing at the original attribute_uuid
    attaches the telemetry to that event instead of the copy.
    """
    from mispfleet.models.event import Proposal, Sighting
    from mispfleet.services.copy import renumber_event

    attribute_uuid = "aaaaaaaa-0000-4000-8000-00000000000a"
    event = MISPEvent(
        uuid="eeeeeeee-0000-4000-8000-00000000000e",
        info="Cloned",
        attributes=[MISPAttribute(uuid=attribute_uuid, type="domain", value="a.example")],
        sightings=[
            Sighting(uuid="55555555-0000-4000-8000-000000000005", attribute_uuid=attribute_uuid),
            # An event-wide sighting carries no attribute_uuid to remap.
            Sighting(uuid="66666666-0000-4000-8000-000000000006"),
        ],
        proposals=[
            Proposal(
                uuid="99999999-0000-4000-8000-000000000009",
                type="domain",
                value="b.example",
            )
        ],
    )
    renumber_event(event)

    ne(event.sightings[0].uuid, "55555555-0000-4000-8000-000000000005")
    ne(event.proposals[0].uuid, "99999999-0000-4000-8000-000000000009")
    # The sighting must now follow the renumbered attribute, not the original.
    ne(event.sightings[0].attribute_uuid, attribute_uuid)
    eq(event.sightings[0].attribute_uuid, event.attributes[0].uuid)
    ne(event.sightings[1].uuid, "66666666-0000-4000-8000-000000000006")
    eq(event.sightings[1].attribute_uuid, None)


def test_merge_unions_attributes_inside_an_object_present_on_both_sides() -> None:
    """Enrichment added inside an existing object must survive the merge."""
    from mispfleet.services.copy import merge_events

    shared = "0b1ec700-0000-4000-8000-00000000000b"
    destination = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d",
        info="Destination",
        objects=[
            MISPObject(
                uuid=shared,
                name="file",
                attributes=[MISPAttribute(type="md5", value="d41d8cd98f00b204e9800998ecf8427e")],
            )
        ],
    )
    proposed = destination.model_copy(deep=True)
    proposed.objects[0].attributes.append(MISPAttribute(type="sha256", value="ab" * 32))

    merged = merge_events(destination, proposed)
    eq(len(merged.objects), 1)
    eq(
        sorted(a.type for a in merged.objects[0].attributes),
        ["md5", "sha256"],
    )


def test_merge_never_guesses_which_same_named_object_was_enriched() -> None:
    """Objects without a UUID have an ambiguous identity, so they are not paired.

    Guessing moves indicators onto the wrong object, and which one it picks
    depends on each server's storage order. Appending instead loses nothing
    and overwrites nothing.
    """
    from mispfleet.services.copy import merge_events

    def file_object(value: str) -> MISPObject:
        return MISPObject(name="file", attributes=[MISPAttribute(type="md5", value=value)])

    destination = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d",
        info="Destination",
        objects=[file_object("a" * 32), file_object("b" * 32)],
    )
    proposed = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d",
        info="Proposed",
        objects=[file_object("c" * 32)],
    )
    merged = merge_events(destination, proposed)
    eq(len(merged.objects), 3)
    eq(sorted(len(obj.attributes) for obj in merged.objects), [1, 1, 1])
    # Neither destination object absorbed the proposed one's indicator.
    eq([obj.attributes[0].value for obj in merged.objects[:2]], ["a" * 32, "b" * 32])


def test_merge_is_independent_of_the_order_servers_store_objects_in() -> None:
    """The same logical merge must produce the same event either way round."""
    from mispfleet.services.copy import merge_events

    def file_object(uuid: str, *hashes: tuple[str, str]) -> MISPObject:
        return MISPObject(
            uuid=uuid,
            name="file",
            attributes=[MISPAttribute(type=t, value=v) for t, v in hashes],
        )

    first = "0b1ec700-0000-4000-8000-00000000000b"
    second = "0b1ec700-0000-4000-8000-00000000000c"
    destination = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d",
        info="Destination",
        objects=[file_object(first, ("md5", "a" * 32)), file_object(second, ("md5", "b" * 32))],
    )
    objects = [
        file_object(first, ("md5", "a" * 32), ("sha256", "c" * 64)),
        file_object(second, ("md5", "b" * 32), ("sha256", "d" * 64)),
    ]
    forward = MISPEvent(uuid=destination.uuid, info="P", objects=list(objects))
    reverse = MISPEvent(uuid=destination.uuid, info="P", objects=list(reversed(objects)))
    eq(
        merge_events(destination, forward).canonical_fingerprint(),
        merge_events(destination, reverse).canonical_fingerprint(),
    )


def test_merge_keeps_the_clusters_of_every_proposed_galaxy() -> None:
    """Two proposed galaxies of one name used to collapse, dropping clusters."""
    from mispfleet.models.event import Galaxy
    from mispfleet.services.copy import merge_events

    destination = MISPEvent(uuid="dddddddd-0000-4000-8000-00000000000d", info="Destination")
    proposed = MISPEvent(
        uuid=destination.uuid,
        info="Proposed",
        galaxies=[
            Galaxy(name="mitre-attack", clusters={"T1001"}),
            Galaxy(name="mitre-attack", clusters={"T2002"}),
        ],
    )
    merged = merge_events(destination, proposed)
    eq(
        [(g.name, sorted(g.clusters)) for g in merged.galaxies],
        [("mitre-attack", ["T1001", "T2002"])],
    )


def test_merge_keeps_two_galaxies_that_share_a_name() -> None:
    """Stock MISP ships mitre-ics and disarm galaxies both named "Techniques".

    Keying the union on the name alone deleted one of them and grafted its
    clusters onto the other, even when the proposal carried no galaxies.
    """
    from mispfleet.models.event import Galaxy
    from mispfleet.services.copy import merge_events

    ics = Galaxy(
        uuid="99261a7e-2270-40eb-823f-834cc1ad3159",
        name="Techniques",
        clusters={"Activate Firmware Update Mode"},
    )
    disarm = Galaxy(
        uuid="a90f2bb6-11e1-58a7-9962-ba37886720ec",
        name="Techniques",
        clusters={"Facilitate State Propaganda"},
    )
    destination = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d", info="Destination", galaxies=[ics, disarm]
    )
    merged = merge_events(destination, MISPEvent(uuid=destination.uuid, info="Proposed"))
    eq(
        sorted((g.uuid, sorted(g.clusters)) for g in merged.galaxies),
        sorted((g.uuid, sorted(g.clusters)) for g in destination.galaxies),
    )


def test_merge_fills_object_metadata_the_destination_never_had() -> None:
    """A merged object that drops the plan's metadata can never converge.

    diff_events treats comment, distribution and the template fields as
    conflicts, so an object that silently lost them diffed against the
    proposal forever and no further merge closed it.
    """
    from mispfleet.services.copy import merge_events

    shared = "0b1ec700-0000-4000-8000-00000000000b"
    destination = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d",
        info="Destination",
        objects=[MISPObject(uuid=shared, name="file", comment="")],
    )
    proposed = MISPEvent(
        uuid=destination.uuid,
        info="Proposed",
        objects=[
            MISPObject(
                uuid=shared,
                name="file",
                comment="ransomware config",
                distribution="1",
                meta_category="file",
                description="File object",
                template_version="1",
            )
        ],
    )
    merged = merge_events(destination, proposed).objects[0]
    eq(merged.comment, "ransomware config")
    eq(merged.distribution, "1")
    eq(merged.meta_category, "file")
    eq(merged.description, "File object")
    eq(merged.template_version, "1")

    # The destination's own value still wins where it has one.
    destination.objects[0].comment = "already reviewed"
    eq(merge_events(destination, proposed).objects[0].comment, "already reviewed")


def test_merge_keeps_the_destination_galaxy_record_not_the_proposal_s() -> None:
    """Destination metadata wins for galaxies as it does for every other field.

    Two fleet servers running different misp-galaxy versions carry the same
    galaxy UUID under different names; seeding from the proposal discarded the
    destination's record and kept only its clusters.
    """
    from mispfleet.models.event import Galaxy
    from mispfleet.services.copy import merge_events

    shared = "99261a7e-2270-40eb-823f-834cc1ad3159"
    destination = MISPEvent(
        uuid="dddddddd-0000-4000-8000-00000000000d",
        info="Destination",
        galaxies=[Galaxy(uuid=shared, name="Techniques", clusters={"Alarm Suppression"})],
    )
    proposed = MISPEvent(
        uuid=destination.uuid,
        info="Proposed",
        galaxies=[Galaxy(uuid=shared, name="ICS Techniques", clusters={"Data Destruction"})],
    )
    merged = merge_events(destination, proposed).galaxies[0]
    eq(merged.name, "Techniques")
    eq(sorted(merged.clusters), ["Alarm Suppression", "Data Destruction"])


def test_merge_carries_over_sightings_and_proposals() -> None:
    """Both dimensions were left out of the merge entirely.

    apply reported "merged with the proposed copy" while the sightings and
    proposals the operator reviewed in the plan never reached the destination.
    """
    from mispfleet.models.event import Proposal, Sighting
    from mispfleet.services.copy import merge_events

    destination = MISPEvent(
        uuid=EVENT_UUID,
        info="destination",
        sightings=[Sighting(uuid="s-kept", attribute_uuid="a-1")],
    )
    proposed = MISPEvent(
        uuid=EVENT_UUID,
        info="proposed",
        sightings=[
            Sighting(uuid="s-kept", attribute_uuid="a-1"),
            Sighting(uuid="s-new", attribute_uuid="a-2", organisation="CIRCL"),
        ],
        proposals=[Proposal(uuid="p-new", type="domain", value="proposed.example")],
    )
    merged = merge_events(destination, proposed)
    eq(sorted(not_none(s.uuid) for s in merged.sightings), ["s-kept", "s-new"])
    eq([not_none(p.uuid) for p in merged.proposals], ["p-new"])

    # Neither side's storage order may decide the result, and merging what was
    # already merged must change nothing.
    reversed_proposed = proposed.model_copy(deep=True)
    reversed_proposed.sightings.reverse()
    eq(
        [s.uuid for s in merge_events(destination, reversed_proposed).sightings],
        [s.uuid for s in merged.sightings],
    )
    eq(
        [s.uuid for s in merge_events(merged, proposed).sightings],
        [s.uuid for s in merged.sightings],
    )


def test_merge_never_emits_two_attributes_under_one_uuid() -> None:
    """The union pairs by (type, value) while the UUID rides along unchanged.

    A policy that rewrote the value — any redact_values rule — offers the
    destination its own UUID attached to different content. MISP enforces
    server-wide uniqueness and stores the colliding event as an empty shell
    while reporting success.
    """
    from mispfleet.services.copy import merge_events

    shared = "aaaaaaaa-0000-4000-8000-000000000001"
    destination = MISPEvent(
        uuid=EVENT_UUID,
        attributes=[MISPAttribute(uuid=shared, type="domain", value="evil.example")],
        objects=[
            MISPObject(
                uuid="o1",
                name="file",
                attributes=[MISPAttribute(uuid="bb-1", type="md5", value="d" * 32)],
            )
        ],
    )
    proposed = MISPEvent(
        uuid=EVENT_UUID,
        attributes=[MISPAttribute(uuid=shared, type="domain", value=REDACTED)],
        objects=[
            MISPObject(
                uuid="o1",
                name="file",
                attributes=[MISPAttribute(uuid="bb-1", type="md5", value=REDACTED)],
            )
        ],
    )
    merged = merge_events(destination, proposed)
    uuids = [
        attribute.uuid
        for attribute in (*merged.attributes, *(a for o in merged.objects for a in o.attributes))
        if attribute.uuid is not None
    ]
    eq(len(uuids), len(set(uuids)))
    # The redacted content still arrives; only the colliding identity is dropped.
    contains([a.value for a in merged.attributes], REDACTED)
    contains([a.value for o in merged.objects for a in o.attributes], REDACTED)

    # A set built once from the destination missed duplicates originating
    # inside the proposal itself, across both containers.
    twinned = MISPEvent(
        uuid=EVENT_UUID,
        attributes=[MISPAttribute(uuid="dup-1", type="ip-dst", value="2.2.2.2")],
        objects=[
            MISPObject(
                uuid="o2",
                name="file",
                attributes=[MISPAttribute(uuid="dup-1", type="sha1", value="a" * 40)],
            )
        ],
    )
    both = merge_events(MISPEvent(uuid=EVENT_UUID), twinned)
    emitted = [
        attribute.uuid
        for attribute in (*both.attributes, *(a for o in both.objects for a in o.attributes))
        if attribute.uuid is not None
    ]
    eq(len(emitted), len(set(emitted)))
    contains([a.value for a in both.attributes], "2.2.2.2")

    # The destination's own attributes are in the reserved set because it
    # already stores them under those UUIDs; running them through the guard
    # stripped the very identities the destination is keyed on.
    kept = MISPEvent(
        uuid=EVENT_UUID,
        objects=[
            MISPObject(
                uuid="o3",
                name="file",
                attributes=[MISPAttribute(uuid="keep-me", type="md5", value="f" * 32)],
            )
        ],
    )
    untouched = merge_events(kept, MISPEvent(uuid=EVENT_UUID))
    eq([a.uuid for o in untouched.objects for a in o.attributes], ["keep-me"])
    # And the result must not alias the input: it used to hand back the
    # destination's own objects, so touching the merge wrote into the event
    # it had merged from.
    ok(untouched.objects[0] is not kept.objects[0])
    untouched.objects[0].name = "rewritten"
    eq(kept.objects[0].name, "file")


def test_repeated_merges_do_not_readopt_an_object_whose_uuids_were_reserved() -> None:
    """Reservation may strip an adopted object's attribute UUIDs.

    Keying adoption on the full content hash then stopped the stripped copy
    from matching its own proposal next time, so every repeated merge adopted
    it again and the event grew without bound.
    """
    from mispfleet.services.copy import merge_events

    proposed = MISPEvent(
        uuid=EVENT_UUID,
        objects=[
            MISPObject(
                name="file",
                attributes=[MISPAttribute(uuid="shared", type="md5", value="a" * 32)],
            ),
            MISPObject(
                name="file",
                attributes=[MISPAttribute(uuid="shared", type="sha1", value="b" * 40)],
            ),
        ],
    )
    once = merge_events(MISPEvent(uuid=EVENT_UUID), proposed)
    twice = merge_events(once, proposed)
    eq(len(twice.objects), len(once.objects))
    eq(twice.canonical_fingerprint(), once.canonical_fingerprint())


def test_attributes_inside_one_object_do_not_follow_the_source_storage_order() -> None:
    """(type, value) leaves two attributes alike but for their UUID tied.

    The event-level union was given the total key; the object-level one kept
    the partial key, so the stable sort handed the order back to the source.
    """
    from mispfleet.services.copy import merge_events

    def proposal(reverse: bool) -> MISPEvent:
        attributes = [
            MISPAttribute(uuid="aaa", type="sha1", value="b" * 40),
            MISPAttribute(uuid="bbb", type="sha1", value="b" * 40),
        ]
        if reverse:
            attributes.reverse()
        return MISPEvent(
            uuid=EVENT_UUID,
            objects=[MISPObject(uuid="o1", name="file", attributes=attributes)],
        )

    destination = MISPEvent(
        uuid=EVENT_UUID,
        objects=[
            MISPObject(
                uuid="o1",
                name="file",
                attributes=[MISPAttribute(uuid="zzz", type="md5", value="c" * 32)],
            )
        ],
    )
    forward = merge_events(destination, proposal(reverse=False))
    backward = merge_events(destination, proposal(reverse=True))
    eq(
        [a.uuid for o in forward.objects for a in o.attributes],
        [a.uuid for o in backward.objects for a in o.attributes],
    )


def test_adoption_identity_ignores_only_the_attribute_uuids() -> None:
    """A hand-rolled join collided on MISP's composite types.

    "regkey" + "value|X" and "regkey|value" + "X" produced one key, so a
    genuinely different object was never adopted. Ignoring references and
    metadata suppressed an enriched object the same way — both are data loss.
    """
    from mispfleet.services.copy import merge_events

    composite = merge_events(
        MISPEvent(
            uuid=EVENT_UUID,
            objects=[
                MISPObject(name="file", attributes=[MISPAttribute(type="regkey", value="value|X")])
            ],
        ),
        MISPEvent(
            uuid=EVENT_UUID,
            objects=[
                MISPObject(name="file", attributes=[MISPAttribute(type="regkey|value", value="X")])
            ],
        ),
    )
    eq(len(composite.objects), 2)

    indicator = MISPAttribute(type="md5", value="a" * 32)
    enriched = merge_events(
        MISPEvent(
            uuid=EVENT_UUID,
            objects=[MISPObject(name="file", attributes=[indicator.model_copy(deep=True)])],
        ),
        MISPEvent(
            uuid=EVENT_UUID,
            objects=[
                MISPObject(
                    name="file",
                    attributes=[indicator.model_copy(deep=True)],
                    references=[ObjectReference(referenced_uuid="r9", relationship_type="drops")],
                    comment="enriched",
                )
            ],
        ),
    )
    contains([r.referenced_uuid for o in enriched.objects for r in o.references], "r9")
