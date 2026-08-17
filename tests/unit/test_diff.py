"""Unit and property tests for the event diff engine."""

from __future__ import annotations

from collections.abc import Callable
from itertools import product
from typing import Any

from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel

from mispfleet.models.attribute import MISPAttribute, MISPObject, ObjectReference
from mispfleet.models.diff import DiffOperation
from mispfleet.models.event import Galaxy, MISPEvent, Proposal, Sighting
from mispfleet.output.renderers import patch_from_diff
from mispfleet.services.diff import diff_events
from tests.support import contains, eq, ne, not_contains, ok

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


def test_case_only_tag_differences_are_equivalent_like_the_fingerprint() -> None:
    """MISP tags are case-insensitive, so the diff must fold case as the

    fingerprint does; otherwise ``event diff`` reports a phantom tag conflict
    for a pair the fingerprint (and ``sync plan``) consider identical.
    """
    left = event(
        tags={"TLP:GREEN"},
        attributes=[MISPAttribute(type="domain", value="evil.example", tags={"Malware:Emotet"})],
        objects=[],
    )
    right = event(
        tags={"tlp:green"},
        attributes=[MISPAttribute(type="domain", value="evil.example", tags={"malware:emotet"})],
        objects=[],
    )
    diff = diff_events(UUID_A, "left", "right", left, right)
    ok(diff.equivalent)
    eq(diff.differences, [])
    eq(left.canonical_fingerprint(), right.canonical_fingerprint())


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


def test_objects_with_same_name_are_keyed_by_uuid() -> None:
    left = event(
        objects=[
            MISPObject(uuid="obj-1", name="file", attributes=[]),
            MISPObject(uuid="obj-2", name="file", attributes=[]),
        ]
    )
    right = event(objects=[MISPObject(uuid="obj-1", name="file", attributes=[])])
    diff = diff_events(UUID_A, "left", "right", left, right)
    eq({d.path: d.operation for d in diff.differences}, {"objects[obj-2]": DiffOperation.REMOVE})


def test_object_reference_differences_are_reported() -> None:
    reference = ObjectReference(referenced_uuid="attr-1", relationship_type="related-to")
    left = event(objects=[MISPObject(uuid="obj-1", name="file", references=[reference])])
    right = event(objects=[MISPObject(uuid="obj-1", name="file")])
    diff = diff_events(UUID_A, "left", "right", left, right)
    eq(
        {d.path: d.operation for d in diff.differences},
        # uuid and object_uuid lead the entry: canonical_fingerprint hashes
        # them, so the diff has to report a change in either.
        {"objects[obj-1].references[||attr-1|related-to]": DiffOperation.REMOVE},
    )


def test_galaxy_sighting_and_proposal_differences() -> None:
    left = event(
        galaxies=[Galaxy(name="Threat Actor", clusters={"APT-X"})],
        sightings=[Sighting(attribute_uuid="a-1", date_sighting="1700000000")],
        proposals=[Proposal(type="domain", value="old.example")],
    )
    right = event(
        galaxies=[Galaxy(name="Threat Actor", clusters={"APT-Y"})],
        sightings=[],
        proposals=[Proposal(type="domain", value="new.example")],
    )
    diff = diff_events(UUID_A, "left", "right", left, right)
    operations = {d.path: d.operation for d in diff.differences}
    # The owning galaxy is part of the path: two galaxies can share a name, so
    # a bare "name/cluster" could not say which one gained or lost the cluster.
    # Composed through the escaping join, not "=" and "/" separators the data
    # can contain: a uuid of "u/x" collided with a cluster of "x/a".
    eq(operations["galaxies[Threat Actor||cluster|APT-Y]"], DiffOperation.ADD)
    eq(operations["galaxies[Threat Actor||cluster|APT-X]"], DiffOperation.REMOVE)
    # Every field of a sighting and of a proposal takes part: comparing three
    # of five hid a changed organisation, uuid, category or to_ids entirely.
    eq(operations["sightings[|a-1|0|1700000000|]"], DiffOperation.REMOVE)
    eq(operations["proposals[|domain|new.example||False]"], DiffOperation.ADD)
    eq(operations["proposals[|domain|old.example||False]"], DiffOperation.REMOVE)


def test_composite_attribute_types_do_not_collide_into_one_key() -> None:
    """MISP's composite types put a "|" in both the type and the value.

    ``("regkey", "value|X")`` and ``("regkey|value", "X")`` built the same key,
    so the two attributes paired up, their difference became invisible, and
    `sync plan` re-proposed the pair forever against a disagreeing fingerprint.
    """
    left = event(attributes=[MISPAttribute(uuid="u1", type="regkey", value="value|HKLM|data")])
    right = event(attributes=[MISPAttribute(uuid="u1", type="regkey|value", value="HKLM|data")])
    diff = diff_events(UUID_A, "left", "right", left, right)
    ok(not diff.equivalent)
    ne(left.canonical_fingerprint(), right.canonical_fingerprint())


def test_sightings_keep_their_cardinality_and_every_field() -> None:
    one = event(sightings=[Sighting(attribute_uuid="a-1")])
    two = event(sightings=[Sighting(attribute_uuid="a-1"), Sighting(attribute_uuid="a-1")])
    ok(not diff_events(UUID_A, "left", "right", one, two).equivalent)

    org_a = event(sightings=[Sighting(uuid="s1", attribute_uuid="a", organisation="ORG-A")])
    org_b = event(sightings=[Sighting(uuid="s2", attribute_uuid="a", organisation="ORG-B")])
    ok(not diff_events(UUID_A, "left", "right", org_a, org_b).equivalent)


def test_patch_from_diff_renders_all_operations() -> None:
    left = event(tags={"old"}, info="Campaign")
    right = event(tags={"new"}, info="Renamed")
    diff = diff_events(UUID_A, "left", "right", left, right)
    text = patch_from_diff(diff)
    contains(text, f"--- left/{UUID_A}")
    contains(text, f"+++ right/{UUID_A}")
    contains(text, "+ tags[new]")
    contains(text, "- tags[old]")
    contains(text, "~ info: 'Campaign' -> 'Renamed'")
    contains(text, "@@ added=1 removed=1 changed=1 conflicts=0")
    empty = diff_events(UUID_A, "left", "right", event(), event())
    contains(patch_from_diff(empty), "@@ added=0 removed=0 changed=0 conflicts=0")


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


def test_duplicate_attributes_are_not_silently_collapsed() -> None:
    duplicated = event(
        attributes=[
            MISPAttribute(type="domain", value="evil.example"),
            MISPAttribute(type="domain", value="evil.example"),
            MISPAttribute(type="domain", value="evil.example"),
        ]
    )
    single = event(attributes=[MISPAttribute(type="domain", value="evil.example")])
    diff = diff_events(UUID_A, "left", "right", duplicated, single)
    ok(not diff.equivalent)
    counts = [d for d in diff.differences if d.path.endswith(".count")]
    eq(len(counts), 1)
    eq((counts[0].left, counts[0].right), (3, 1))
    same = diff_events(UUID_A, "left", "right", duplicated, duplicated)
    ok(same.equivalent)


def test_equal_counts_of_duplicates_are_compared_copy_by_copy() -> None:
    """Comparing only the first copy reported diverging events as equivalent."""
    left = event(
        attributes=[
            MISPAttribute(type="domain", value="evil.example", comment="a"),
            MISPAttribute(type="domain", value="evil.example", comment="b"),
        ]
    )
    right = event(
        attributes=[
            MISPAttribute(type="domain", value="evil.example", comment="a"),
            MISPAttribute(type="domain", value="evil.example", comment="c"),
        ]
    )
    diff = diff_events(UUID_A, "left", "right", left, right)
    ok(not diff.equivalent)
    conflicts = [d for d in diff.differences if d.path.endswith(".comment")]
    eq(len(conflicts), 1)
    eq((conflicts[0].left, conflicts[0].right), ("b", "c"))


def test_reordered_duplicates_stay_equivalent() -> None:
    """The same multiset of copies must not diff just because it is reordered."""
    left = event(
        attributes=[
            MISPAttribute(type="domain", value="evil.example", comment="a"),
            MISPAttribute(type="domain", value="evil.example", comment="b"),
        ]
    )
    right = event(
        attributes=[
            MISPAttribute(type="domain", value="evil.example", comment="b"),
            MISPAttribute(type="domain", value="evil.example", comment="a"),
        ]
    )
    ok(diff_events(UUID_A, "left", "right", left, right).equivalent)


def test_diff_reports_everything_the_fingerprint_counts() -> None:
    """sync decides "in sync" by canonical_fingerprint().

    Any field it hashes but the diff ignored made `event diff` print
    "equivalent" for a pair `sync plan` re-proposed on every run, with no way
    for the operator to see what differed.
    """

    def build(attribute: dict[str, object], obj: dict[str, object]) -> MISPEvent:
        return event(
            attributes=[
                MISPAttribute(
                    **{"type": "domain", "value": "evil.example", **attribute}  # type: ignore[arg-type]
                )
            ],
            objects=[MISPObject(**{"name": "file", "uuid": "bb00", **obj})],  # type: ignore[arg-type]
        )

    variations: list[tuple[dict[str, object], dict[str, object]]] = [
        ({"uuid": "aa000000-0000-4000-8000-000000000001"}, {}),
        ({"distribution": "3"}, {}),
        ({"sharing_group_id": "9"}, {}),
        ({"data": "aGVsbG8="}, {}),
        ({}, {"comment": "changed"}),
        ({}, {"distribution": "3"}),
        ({}, {"sharing_group_id": "9"}),
        ({}, {"template_uuid": "tpl-2"}),
    ]
    base = build({}, {})
    for attribute, obj in variations:
        other = build(attribute, obj)
        diff = diff_events(UUID_A, "left", "right", base, other)
        equal_fingerprints = base.canonical_fingerprint() == other.canonical_fingerprint()
        eq(diff.equivalent, equal_fingerprints)
    ok(diff_events(UUID_A, "left", "right", base, build({}, {})).equivalent)


def test_attachment_payloads_are_diffed_by_size_not_content() -> None:
    left = event(attributes=[MISPAttribute(type="domain", value="e.example", data="AAAA")])
    right = event(attributes=[MISPAttribute(type="domain", value="e.example", data="BBBBBB")])
    diff = diff_events(UUID_A, "left", "right", left, right)
    payload = next(d for d in diff.differences if d.path.endswith(".data"))
    eq((payload.left, payload.right), (4, 6))


def test_diff_covers_galaxies_references_and_object_names() -> None:
    """The previous sweep fixed attributes and object scalars only.

    canonical_fingerprint also hashes Galaxy.uuid, ObjectReference.uuid,
    ObjectReference.object_uuid and MISPObject.name, so a pair differing only
    in those still diffed as equivalent while sync re-proposed it forever.
    """

    def build(galaxy_uuid: str, reference_uuid: str, object_name: str) -> MISPEvent:
        return event(
            galaxies=[Galaxy(name="apt", clusters={"c1"}, uuid=galaxy_uuid)],
            objects=[
                MISPObject(
                    name=object_name,
                    uuid="bb000000-0000-4000-8000-000000000001",
                    references=[ObjectReference(uuid=reference_uuid, referenced_uuid="target-1")],
                )
            ],
        )

    base = build("ga-1", "ref-1", "file")
    for label, other in [
        ("galaxy uuid", build("ga-2", "ref-1", "file")),
        ("reference uuid", build("ga-1", "ref-2", "file")),
        ("object name", build("ga-1", "ref-1", "url")),
    ]:
        diff = diff_events(UUID_A, "left", "right", base, other)
        eq(
            (label, diff.equivalent),
            (label, base.canonical_fingerprint() == other.canonical_fingerprint()),
        )
    ok(diff_events(UUID_A, "left", "right", base, build("ga-1", "ref-1", "file")).equivalent)


def test_duplicate_objects_are_not_collapsed() -> None:
    """Objects were indexed into a plain dict keyed by uuid-or-name.

    Uuid-less objects fall back to their name and two objects of the same
    template per event is normal, so every copy but the last vanished and an
    event losing a whole object diffed as equivalent.
    """
    left = event(
        objects=[
            MISPObject(name="file", comment="first"),
            MISPObject(name="file", comment="second"),
        ]
    )
    right = event(objects=[MISPObject(name="file", comment="second")])
    diff = diff_events(UUID_A, "left", "right", left, right)
    ok(not diff.equivalent)
    counts = [d for d in diff.differences if d.path.endswith(".count")]
    eq((counts[0].left, counts[0].right), (2, 1))
    ok(diff_events(UUID_A, "left", "right", left, left).equivalent)


def test_event_uuid_difference_is_reported() -> None:
    """canonical_fingerprint hashes the event uuid; the metadata sweep missed it.

    compare_event fetches by numeric id, so server A's event 7 and server B's
    event 7 are routinely different events entirely.
    """
    left = event()
    right = event(uuid="9c5c1c2e-0000-4000-8000-00000000000f")
    diff = diff_events(UUID_A, "left", "right", left, right)
    ok(not diff.equivalent)
    contains([d.path for d in diff.differences], "uuid")


def test_duplicate_objects_are_compared_copy_by_copy() -> None:
    """Object groups were paired in stored order, comparing only the first.

    That reported identical content as different when two servers held it in
    a different sequence, and hid a real difference in any copy past the
    first — the same defect duplicate attributes already had.
    """

    def build(order: str, second: str = "beta") -> MISPEvent:
        objects = {
            "a": MISPObject(name="file", comment="alpha"),
            "b": MISPObject(name="file", comment=second),
        }
        return event(objects=[objects[key] for key in order])

    ok(diff_events(UUID_A, "left", "right", build("ab"), build("ba")).equivalent)
    diverging = diff_events(UUID_A, "left", "right", build("ab"), build("ab", second="gamma"))
    ok(not diverging.equivalent)
    conflicts = [d for d in diverging.differences if d.path.endswith(".comment")]
    eq((conflicts[0].left, conflicts[0].right), ("beta", "gamma"))


_FINGERPRINT_EXCLUDED = ("timestamp", "sightings", "proposals")
_CONTAINER_FIELDS = ("attributes", "objects", "galaxies", "references", "clusters", "tags")


def _mutated_value(model: BaseModel, field: str) -> object:
    """A value different from the current one, derived from the annotation."""
    current = getattr(model, field)
    annotation = str(type(model).model_fields[field].annotation)
    if "bool" in annotation and "str" not in annotation:
        return not current
    if "set[str]" in annotation:
        return (current or set()) | {"mutated-entry"}
    return "mutated" if current != "mutated" else "mutated-2"


def _invariant_event() -> MISPEvent:
    reference = ObjectReference(
        uuid="ref-1", object_uuid="obj-1", referenced_uuid="tgt-1", relationship_type="related-to"
    )
    return event(
        attributes=[MISPAttribute(uuid="ea-1", type="domain", value="e.example")],
        objects=[
            MISPObject(
                uuid="obj-1",
                name="file",
                template_uuid="tpl-1",
                template_version="1",
                meta_category="file",
                description="File object",
                attributes=[
                    MISPAttribute(uuid="oa-1", type="md5", value="a" * 32, object_relation="md5")
                ],
                references=[reference],
            )
        ],
        galaxies=[Galaxy(uuid="g-1", name="g", clusters={"C1"})],
    )


def _mutation_targets() -> list[tuple[str, str, Callable[[MISPEvent], None]]]:
    """One mutation per model field, discovered from the models themselves.

    Enumerating beats listing: three separate rounds of hand-written examples
    each missed the next field someone added.
    """
    targets: list[tuple[str, str, Callable[[MISPEvent], None]]] = []

    def add(where: str, field: str, reach: Callable[[MISPEvent], BaseModel]) -> None:
        def apply(candidate: MISPEvent) -> None:
            holder = reach(candidate)
            setattr(holder, field, _mutated_value(holder, field))

        targets.append((where, field, apply))

    for field in MISPEvent.model_fields:
        if field not in _FINGERPRINT_EXCLUDED and field not in _CONTAINER_FIELDS:
            add("event", field, lambda candidate: candidate)
    for field in MISPAttribute.model_fields:
        if field not in _CONTAINER_FIELDS:
            add("event-attribute", field, lambda candidate: candidate.attributes[0])
            add("object-attribute", field, lambda candidate: candidate.objects[0].attributes[0])
    for field in MISPObject.model_fields:
        if field not in _CONTAINER_FIELDS:
            add("object", field, lambda candidate: candidate.objects[0])
    for field in ObjectReference.model_fields:
        add("reference", field, lambda candidate: candidate.objects[0].references[0])
    for field in Galaxy.model_fields:
        add("galaxy", field, lambda candidate: candidate.galaxies[0])
    return targets


def test_every_field_the_fingerprint_hashes_is_visible_to_the_diff() -> None:
    """The invariant, enumerated over every field rather than a chosen few.

    canonical_fingerprint dumps the whole model, so a field it hashes that the
    diff cannot surface makes `sync plan` re-propose the same copy forever
    while `event diff` calls the pair equivalent. Driving this from
    model_fields means a field added later is covered without anyone
    remembering to extend a list.
    """
    base = _invariant_event()
    targets = _mutation_targets()
    ok(len(targets) > 40)
    for where, field, apply in targets:
        other = _invariant_event()
        apply(other)
        diff = diff_events(UUID_A, "left", "right", base, other)
        same_fingerprint = base.canonical_fingerprint() == other.canonical_fingerprint()
        eq((f"{where}.{field}", diff.equivalent), (f"{where}.{field}", same_fingerprint))


def test_structural_mutations_also_keep_the_diff_and_fingerprint_agreed() -> None:
    """Single-field mutations cannot see list cardinality or ownership.

    The fingerprint hashes references and galaxies as lists, but the diff
    compared them as flattened sets, so a repeated reference, a galaxy listed
    twice, or clusters moved between two same-name galaxies read as equivalent
    while the fingerprints disagreed — sync re-proposing forever.
    """
    reference = ObjectReference(
        uuid="ref-1", object_uuid="obj-1", referenced_uuid="tgt-1", relationship_type="related-to"
    )

    def with_objects(references: list[ObjectReference]) -> MISPEvent:
        return event(objects=[MISPObject(uuid="obj-1", name="file", references=references)])

    def with_galaxies(galaxies: list[Galaxy]) -> MISPEvent:
        return event(galaxies=galaxies)

    galaxy = Galaxy(uuid="G1", name="g", clusters={"C1"})
    # Stock MISP ships two distinct galaxies both named "Techniques".
    first = Galaxy(uuid="G1", name="Techniques", clusters={"C1", "C2"})
    second = Galaxy(uuid="G2", name="Techniques", clusters=set())
    moved_first = Galaxy(uuid="G1", name="Techniques", clusters={"C1"})
    moved_second = Galaxy(uuid="G2", name="Techniques", clusters={"C2"})

    pairs = [
        (with_objects([reference]), with_objects([reference, reference.model_copy(deep=True)])),
        (with_galaxies([galaxy]), with_galaxies([galaxy, galaxy.model_copy(deep=True)])),
        (with_galaxies([first, second]), with_galaxies([moved_first, moved_second])),
        (
            with_galaxies([moved_first, moved_second]),
            with_galaxies(
                [
                    Galaxy(uuid="G1", name="Techniques", clusters={"C2"}),
                    Galaxy(uuid="G2", name="Techniques", clusters={"C1"}),
                ]
            ),
        ),
    ]
    for left, right in pairs:
        diff = diff_events(UUID_A, "left", "right", left, right)
        eq(diff.equivalent, left.canonical_fingerprint() == right.canonical_fingerprint())


def test_volatile_and_partial_sort_keys_do_not_pair_entities_crosswise() -> None:
    """The sort keys must canonicalize exactly as the fingerprint does.

    Including a per-attribute timestamp made two servers order the same
    objects differently and pair them crosswise, reporting four differences
    for events whose fingerprints agreed; omitting a payload left two
    attachments tied and handed the pairing back to storage order.
    """

    def timestamped(value: str, timestamp: str) -> MISPObject:
        return MISPObject(
            name="file",
            attributes=[MISPAttribute(type="ip-dst", value=value, timestamp=timestamp)],
        )

    attachment_a = MISPAttribute(type="attachment", value="report.pdf", data="AAAA")
    attachment_b = MISPAttribute(type="attachment", value="report.pdf", data="BBBB")
    pairs = [
        (
            event(objects=[timestamped("1.1.1.1", "100"), timestamped("2.2.2.2", "200")]),
            event(objects=[timestamped("1.1.1.1", "200"), timestamped("2.2.2.2", "100")]),
        ),
        (
            event(attributes=[attachment_a, attachment_b]),
            event(attributes=[attachment_b, attachment_a]),
        ),
    ]
    for left, right in pairs:
        diff = diff_events(UUID_A, "left", "right", left, right)
        eq(diff.equivalent, left.canonical_fingerprint() == right.canonical_fingerprint())


def test_an_absent_identifier_is_not_an_empty_one() -> None:
    """The fingerprint keeps None and "" apart; the diff keys used to conflate them."""
    reference = ObjectReference(
        object_uuid="obj-1", referenced_uuid="tgt-1", relationship_type="related-to"
    )
    pairs = [
        (
            event(galaxies=[Galaxy(uuid="", name="g", clusters={"C1"})]),
            event(galaxies=[Galaxy(uuid=None, name="g", clusters={"C1"})]),
        ),
        (
            event(objects=[MISPObject(uuid="", name="file")]),
            event(objects=[MISPObject(uuid=None, name="file")]),
        ),
        (
            event(objects=[MISPObject(uuid="o", name="file", references=[reference])]),
            event(
                objects=[
                    MISPObject(
                        uuid="o",
                        name="file",
                        references=[reference.model_copy(update={"uuid": ""})],
                    )
                ]
            ),
        ),
    ]
    for left, right in pairs:
        diff = diff_events(UUID_A, "left", "right", left, right)
        eq(diff.equivalent, left.canonical_fingerprint() == right.canonical_fingerprint())


def test_clusters_moved_between_two_entries_of_one_galaxy_are_visible() -> None:
    """The cluster set belongs to the entry, not to the identity."""

    def techniques(clusters: set[str]) -> Galaxy:
        return Galaxy(uuid="G1", name="Techniques", clusters=clusters)

    left = event(galaxies=[techniques({"a"}), techniques({"b"})])
    right = event(galaxies=[techniques({"a", "b"}), techniques(set())])
    diff = diff_events(UUID_A, "left", "right", left, right)
    eq(diff.equivalent, left.canonical_fingerprint() == right.canonical_fingerprint())


def _structural_base() -> MISPEvent:
    reference = ObjectReference(
        uuid="r1", object_uuid="o1", referenced_uuid="t1", relationship_type="related-to"
    )
    return event(
        attributes=[
            MISPAttribute(uuid="ea1", type="domain", value="e.example"),
            MISPAttribute(type="attachment", value="r.pdf", data="AAAA"),
        ],
        objects=[
            MISPObject(
                uuid="o1",
                name="file",
                template_uuid="tpl",
                attributes=[
                    MISPAttribute(uuid="oa1", type="md5", value="a" * 32, object_relation="md5")
                ],
                references=[reference],
            ),
            MISPObject(name="pe", attributes=[MISPAttribute(type="sha256", value="c" * 64)]),
        ],
        galaxies=[
            Galaxy(uuid="G1", name="Techniques", clusters={"C1"}),
            Galaxy(uuid="G2", name="Techniques", clusters={"C2"}),
        ],
    )


def _assign(
    reach: Callable[[MISPEvent], object], field: str, value: object
) -> Callable[[MISPEvent], None]:
    def mutate(candidate: MISPEvent) -> None:
        setattr(reach(candidate), field, value)

    return mutate


def _duplicate(reach: Callable[[MISPEvent], list[Any]]) -> Callable[[MISPEvent], None]:
    def mutate(candidate: MISPEvent) -> None:
        items = reach(candidate)
        items.append(items[0].model_copy(deep=True))

    return mutate


def _drop(reach: Callable[[MISPEvent], list[Any]], index: int = 0) -> Callable[[MISPEvent], None]:
    def mutate(candidate: MISPEvent) -> None:
        reach(candidate).pop(index)

    return mutate


def _reverse(reach: Callable[[MISPEvent], list[Any]]) -> Callable[[MISPEvent], None]:
    def mutate(candidate: MISPEvent) -> None:
        reach(candidate).reverse()

    return mutate


def _clear(reach: Callable[[MISPEvent], Any]) -> Callable[[MISPEvent], None]:
    def mutate(candidate: MISPEvent) -> None:
        reach(candidate).clear()

    return mutate


def _timestamped_twins(first: str, second: str) -> Callable[[MISPEvent], None]:
    """Two objects of one key whose only difference is a volatile timestamp.

    They have to group together — same name, no uuid — for the pairing order
    to matter at all.
    """

    def mutate(candidate: MISPEvent) -> None:
        candidate.objects = [
            MISPObject(
                name="file",
                attributes=[MISPAttribute(type="ip-dst", value="1.1.1.1", timestamp=first)],
            ),
            MISPObject(
                name="file",
                attributes=[MISPAttribute(type="ip-dst", value="2.2.2.2", timestamp=second)],
            ),
        ]

    return mutate


def _clusters_within_one_identity(*groups: set[str]) -> Callable[[MISPEvent], None]:
    """Several entries sharing one galaxy identity, clusters split between them."""

    def mutate(candidate: MISPEvent) -> None:
        candidate.galaxies = [
            Galaxy(uuid="G1", name="Techniques", clusters=set(group)) for group in groups
        ]

    return mutate


def _move_cluster(candidate: MISPEvent) -> None:
    candidate.galaxies[0].clusters.add("C2")
    candidate.galaxies[1].clusters.discard("C2")


def _share_galaxy_identity(candidate: MISPEvent) -> None:
    candidate.galaxies[1] = candidate.galaxies[1].model_copy(update={"uuid": "G1"})


def _swap_object_names(candidate: MISPEvent) -> None:
    candidate.objects[0].name, candidate.objects[1].name = (
        candidate.objects[1].name,
        candidate.objects[0].name,
    )


_STRUCTURAL_MUTATIONS: dict[str, Callable[[MISPEvent], None]] = {
    "duplicate attribute": _duplicate(lambda e: e.attributes),
    "drop attribute": _drop(lambda e: e.attributes),
    "reverse attributes": _reverse(lambda e: e.attributes),
    "duplicate object": _duplicate(lambda e: e.objects),
    "drop object": _drop(lambda e: e.objects),
    "reverse objects": _reverse(lambda e: e.objects),
    "duplicate reference": _duplicate(lambda e: e.objects[0].references),
    "drop reference": _drop(lambda e: e.objects[0].references),
    "duplicate object attribute": _duplicate(lambda e: e.objects[0].attributes),
    "duplicate galaxy": _duplicate(lambda e: e.galaxies),
    "drop galaxy": _drop(lambda e: e.galaxies, -1),
    "reverse galaxies": _reverse(lambda e: e.galaxies),
    "move cluster between galaxies": _move_cluster,
    "two galaxies of one identity": _share_galaxy_identity,
    "galaxy uuid absent": _assign(lambda e: e.galaxies[0], "uuid", None),
    "galaxy uuid empty": _assign(lambda e: e.galaxies[0], "uuid", ""),
    "object uuid absent": _assign(lambda e: e.objects[0], "uuid", None),
    "object uuid empty": _assign(lambda e: e.objects[0], "uuid", ""),
    "reference uuid absent": _assign(lambda e: e.objects[0].references[0], "uuid", None),
    "reference uuid empty": _assign(lambda e: e.objects[0].references[0], "uuid", ""),
    "attribute uuid absent": _assign(lambda e: e.attributes[0], "uuid", None),
    "empty attributes": _clear(lambda e: e.attributes),
    "empty objects": _clear(lambda e: e.objects),
    "empty galaxies": _clear(lambda e: e.galaxies),
    "empty tags": _clear(lambda e: e.tags),
    "attachment payload": _assign(lambda e: e.attributes[1], "data", "BBBB"),
    "attribute timestamp only": _assign(lambda e: e.attributes[0], "timestamp", "999"),
    "object attribute timestamp only": _assign(
        lambda e: e.objects[0].attributes[0], "timestamp", "999"
    ),
    "swap object names": _swap_object_names,
    "timestamped twins": _timestamped_twins("100", "200"),
    "timestamped twins, stamps swapped": _timestamped_twins("200", "100"),
    "one identity, clusters split": _clusters_within_one_identity({"a"}, {"b"}),
    "one identity, clusters pooled": _clusters_within_one_identity({"a", "b"}, set()),
}


def test_the_invariant_holds_across_every_structural_mutation_pair() -> None:
    """Cardinality, ordering, ownership and absent-versus-empty, enumerated.

    Single-field mutations cannot reach any of these, and each of the last
    three rounds broke the invariant on a shape the hand-written examples did
    not contain: a repeated reference, clusters moved between two entries of
    one galaxy, a volatile timestamp reaching a sort key.
    """
    for left_name, right_name in product([None, *_STRUCTURAL_MUTATIONS], repeat=2):
        left, right = _structural_base(), _structural_base()
        if left_name is not None:
            _STRUCTURAL_MUTATIONS[left_name](left)
        if right_name is not None:
            _STRUCTURAL_MUTATIONS[right_name](right)
        diff = diff_events(UUID_A, "left", "right", left, right)
        eq(
            (left_name, right_name, diff.equivalent),
            (
                left_name,
                right_name,
                left.canonical_fingerprint() == right.canonical_fingerprint(),
            ),
        )


def test_a_multiline_value_cannot_forge_a_patch_entry() -> None:
    """Paths embed attribute values verbatim, and MISP text values wrap lines."""
    left = event(attributes=[])
    right = event(
        attributes=[MISPAttribute(type="text", value="line1\nline2\n+ attributes[forged]")]
    )
    text = patch_from_diff(diff_events(UUID_A, "left", "right", left, right))
    entries = [line for line in text.splitlines() if line.startswith(("+ ", "- ", "~ ", "! "))]
    eq(len(entries), 1)
    not_contains(text, "\n+ attributes[forged]")


def test_composite_type_attributes_never_disagree_with_the_fingerprint() -> None:
    """Enumerate the attribute-key invariant, as the galaxy one does below.

    MISP composite types carry "|" in the type AND the value, so the diff's
    attribute key is composed and its alphabet must include the separator it
    composes on ("|"), the escape ("\\") and the other key separators, plus a
    type that is a prefix of another via "|" (``regkey`` vs ``regkey|value``).
    A plain join let ("regkey","value|x") and ("regkey|value","x") pair up, so
    the diff called two different attribute sets equivalent while the
    fingerprint disagreed.
    """
    types = ("regkey", "regkey|value", "filename|md5")
    values = ("x", "value|x", "a\\b", "x|", "|", "a=b")
    shapes = list(product(types, values))

    def build(chosen: tuple[tuple[str, str], ...]) -> MISPEvent:
        return event(
            attributes=[MISPAttribute(type=t, value=v) for t, v in chosen],
            objects=[],
            galaxies=[],
        )

    for left_shape, right_shape in product(shapes, repeat=2):
        one, two = build((left_shape,)), build((right_shape,))
        eq(
            diff_events(UUID_A, "left", "right", one, two).equivalent,
            one.canonical_fingerprint() == two.canonical_fingerprint(),
        )

    pairs = list(product(shapes[:6], repeat=2))
    for left_pair, right_pair in product(pairs[:30], repeat=2):
        one, two = build(left_pair), build(right_pair)
        eq(
            diff_events(UUID_A, "left", "right", one, two).equivalent,
            one.canonical_fingerprint() == two.canonical_fingerprint(),
        )


def test_galaxy_entries_never_disagree_with_the_fingerprint() -> None:
    """Enumerate the invariant instead of patching the examples.

    Four rounds of hand-written cases each left the next shape loose. The
    galaxy entry is a composed key, so the alphabet includes the separators it
    composes with — "|", "/", "=" — and names equal to its own literals.
    """
    shapes = [
        (name, uuid, clusters)
        for name in ("g", "set", "cluster")
        for uuid in (None, "", "u", "u/x", "u=x", "|")
        for clusters in (
            frozenset(),
            frozenset({"a"}),
            frozenset({"x/a"}),
            frozenset({"x=a"}),
            frozenset({"set"}),
            frozenset({"cluster"}),
            frozenset({"a", "b"}),
        )
    ]

    def build(chosen: tuple[tuple[str, str | None, frozenset[str]], ...]) -> MISPEvent:
        return event(
            attributes=[],
            objects=[],
            galaxies=[Galaxy(name=n, uuid=u, clusters=set(c)) for n, u, c in chosen],
        )

    for left_shape, right_shape in product(shapes, repeat=2):
        one, two = build((left_shape,)), build((right_shape,))
        eq(
            diff_events(UUID_A, "left", "right", one, two).equivalent,
            one.canonical_fingerprint() == two.canonical_fingerprint(),
        )

    pairs = list(product(shapes[:12], repeat=2))
    for left_pair, right_pair in product(pairs[:40], repeat=2):
        one, two = build(left_pair), build(right_pair)
        eq(
            diff_events(UUID_A, "left", "right", one, two).equivalent,
            one.canonical_fingerprint() == two.canonical_fingerprint(),
        )
