"""Unit and property tests for the event diff engine."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.diff import DiffOperation
from mispfleet.models.event import MISPEvent
from mispfleet.services.diff import diff_events
from tests.support import eq, ok

UUID_A = "9c5c1c2e-0000-4000-8000-00000000000e"


def event(**overrides: object) -> MISPEvent:
    fields: dict[str, object] = {
        "uuid": UUID_A,
        "info": "Campaign",
        "published": True,
        "distribution": "1",
        "tags": {"tlp:green"},
        "attributes": [
            MISPAttribute(type="domain", value="evil.example", to_ids=True),
            MISPAttribute(type="sha256", value="aa" * 32),
        ],
        "objects": [
            MISPObject(
                name="file",
                attributes=[MISPAttribute(type="filename", value="dropper.exe")],
            )
        ],
    }
    fields.update(overrides)
    return MISPEvent.model_validate(fields)


def test_identical_events_are_equivalent() -> None:
    diff = diff_events(UUID_A, "left", "right", event(), event())
    ok(diff.equivalent)
    eq(diff.differences, [])
    eq(diff.summary.added + diff.summary.removed + diff.summary.changed, 0)


def test_metadata_changes_are_classified_as_change() -> None:
    diff = diff_events(UUID_A, "left", "right", event(), event(info="Renamed", published=False))
    ok(not diff.equivalent)
    paths = {d.path: d for d in diff.differences}
    eq(paths["info"].operation, DiffOperation.CHANGE)
    eq(paths["info"].left, "Campaign")
    eq(paths["info"].right, "Renamed")
    eq(paths["published"].operation, DiffOperation.CHANGE)
    eq(diff.summary.changed, 2)


def test_tag_additions_and_removals_are_distinguished() -> None:
    diff = diff_events(
        UUID_A, "left", "right", event(tags={"tlp:green", "old"}), event(tags={"tlp:green", "new"})
    )
    operations = {d.path: d.operation for d in diff.differences}
    eq(operations["tags[new]"], DiffOperation.ADD)
    eq(operations["tags[old]"], DiffOperation.REMOVE)
    eq(diff.summary.added, 1)
    eq(diff.summary.removed, 1)


def test_attribute_add_remove_and_conflict() -> None:
    left = event()
    right = event(
        attributes=[
            MISPAttribute(type="domain", value="evil.example", to_ids=False),
            MISPAttribute(type="ip-dst", value="203.0.113.7"),
        ]
    )
    diff = diff_events(UUID_A, "left", "right", left, right)
    operations = {d.path: d.operation for d in diff.differences}
    eq(operations["attributes[ip-dst|203.0.113.7]"], DiffOperation.ADD)
    eq(operations[f"attributes[sha256|{'aa' * 32}]"], DiffOperation.REMOVE)
    eq(operations["attributes[domain|evil.example].to_ids"], DiffOperation.CONFLICT)
    eq(diff.summary.conflicts, 1)


def test_attribute_tag_conflicts_are_reported() -> None:
    left = event(attributes=[MISPAttribute(type="domain", value="x", tags={"a"})])
    right = event(attributes=[MISPAttribute(type="domain", value="x", tags={"b"})])
    diff = diff_events(UUID_A, "left", "right", left, right)
    conflict = diff.differences[0]
    eq(conflict.path, "attributes[domain|x].tags")
    eq(conflict.left, ["a"])
    eq(conflict.right, ["b"])


def test_object_add_remove_and_nested_conflicts() -> None:
    left = event()
    right = event(
        objects=[
            MISPObject(
                name="file",
                attributes=[MISPAttribute(type="filename", value="dropper.exe", comment="new")],
            ),
            MISPObject(name="network", attributes=[]),
        ]
    )
    diff = diff_events(UUID_A, "left", "right", left, right)
    operations = {d.path: d.operation for d in diff.differences}
    eq(operations["objects[network]"], DiffOperation.ADD)
    eq(
        operations["objects[file].attributes[filename|dropper.exe].comment"],
        DiffOperation.CONFLICT,
    )
    removed = diff_events(UUID_A, "left", "right", right, left)
    eq(
        {d.path: d.operation for d in removed.differences}["objects[network]"],
        DiffOperation.REMOVE,
    )


@given(
    left_tags=st.sets(st.sampled_from(["a", "b", "c", "d"]), max_size=4),
    right_tags=st.sets(st.sampled_from(["a", "b", "c", "d"]), max_size=4),
)
def test_diff_symmetry_between_adds_and_removes(left_tags: set[str], right_tags: set[str]) -> None:
    forward = diff_events(UUID_A, "l", "r", event(tags=left_tags), event(tags=right_tags))
    backward = diff_events(UUID_A, "r", "l", event(tags=right_tags), event(tags=left_tags))
    eq(forward.summary.added, backward.summary.removed)
    eq(forward.summary.removed, backward.summary.added)
    eq(forward.equivalent, backward.equivalent)
