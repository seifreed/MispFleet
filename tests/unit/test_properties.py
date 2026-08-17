"""Property-based tests for query round trips, fingerprints and pagination."""

from __future__ import annotations

import json
from collections import Counter
from itertools import permutations, product

from hypothesis import given
from hypothesis import strategies as st

from mispfleet.client.pagination import paginate
from mispfleet.models.attribute import MISPAttribute, MISPObject, ObjectReference
from mispfleet.models.event import Galaxy, MISPEvent, Proposal, Sighting
from mispfleet.models.query import SearchQuery
from mispfleet.services.copy import merge_events
from mispfleet.settings import FleetDefaults, _merge
from tests.support import eq, ok

TYPES = st.sets(st.sampled_from(["domain", "sha256", "ip-dst", "url"]), max_size=4)
TAGS = st.sets(st.sampled_from(["tlp:green", "tlp:amber", "approved"]), max_size=3)
ORGS = st.sets(st.sampled_from(["CIRCL", "ACME", "Partner"]), max_size=3)


@given(
    value=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    attribute_types=TYPES,
    tags=TAGS,
    organisations=ORGS,
    published=st.one_of(st.none(), st.booleans()),
    metadata_only=st.booleans(),
)
def test_search_query_round_trips_through_json(
    value: str | None,
    attribute_types: set[str],
    tags: set[str],
    organisations: set[str],
    published: bool | None,
    metadata_only: bool,
) -> None:
    query = SearchQuery(
        value=value,
        attribute_types=attribute_types,
        tags=tags,
        organisations=organisations,
        published=published,
        metadata_only=metadata_only,
    )
    rebuilt = SearchQuery.model_validate_json(query.model_dump_json())
    eq(rebuilt, query)
    eq(rebuilt.fingerprint(), query.fingerprint())


def build_set(values: list[str]) -> set[str]:
    """Build a set by inserting values one at a time in the given order."""
    result: set[str] = set()
    for value in values:
        result.add(value)
    return result


@given(attribute_types=TYPES, tags=TAGS, organisations=ORGS)
def test_query_fingerprint_ignores_set_ordering(
    attribute_types: set[str], tags: set[str], organisations: set[str]
) -> None:
    left = SearchQuery(
        attribute_types=build_set(sorted(attribute_types)),
        tags=build_set(sorted(tags)),
        organisations=build_set(sorted(organisations)),
    )
    right = SearchQuery(
        attribute_types=build_set(sorted(attribute_types, reverse=True)),
        tags=build_set(sorted(tags, reverse=True)),
        organisations=build_set(sorted(organisations, reverse=True)),
    )
    eq(left.fingerprint(), right.fingerprint())
    eq(left.to_misp_payload(), right.to_misp_payload())


@given(
    values=st.lists(st.text(min_size=1, max_size=8), min_size=1, max_size=6, unique=True),
    tags=TAGS,
)
def test_event_fingerprint_is_stable_under_reordering(values: list[str], tags: set[str]) -> None:
    attributes = [MISPAttribute(type="domain", value=value, tags=tags) for value in values]
    left = MISPEvent(uuid="9c5c1c2e-0000-4000-8000-00000000000e", attributes=attributes)
    right = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        attributes=list(reversed(attributes)),
    )
    eq(left.canonical_fingerprint(), right.canonical_fingerprint())


@given(
    total=st.integers(min_value=0, max_value=250),
    page_size=st.integers(min_value=1, max_value=50),
)
async def test_pagination_always_terminates_and_yields_every_record(
    total: int, page_size: int
) -> None:
    async def fetch(page: int, limit: int) -> list[dict[str, object]]:
        start = (page - 1) * limit
        if start >= total:
            return []
        return [{"id": str(index)} for index in range(start, min(start + limit, total))]

    seen = [record async for record in paginate(fetch, page_size=page_size)]
    eq(len(seen), total)
    eq([record["id"] for record in seen], [str(index) for index in range(total)])


@given(
    base_timeout=st.floats(min_value=1.0, max_value=100.0),
    override_timeout=st.floats(min_value=1.0, max_value=100.0),
    concurrency=st.integers(min_value=1, max_value=20),
)
def test_configuration_merge_precedence_prefers_the_override(
    base_timeout: float, override_timeout: float, concurrency: int
) -> None:
    base = {"defaults": {"request_timeout": base_timeout, "concurrency": 1}}
    override = {"defaults": {"request_timeout": override_timeout, "concurrency": concurrency}}
    merged = _merge(base, override)
    defaults = FleetDefaults.model_validate(merged["defaults"])
    eq(defaults.request_timeout, override_timeout)
    eq(defaults.concurrency, concurrency)
    ok(_merge(base, {}) == base)


MERGE_DESTINATION_UUID = "dddddddd-0000-4000-8000-00000000000d"
OBJECT_A = "0b1ec700-0000-4000-8000-00000000000b"
OBJECT_B = "0b1ec700-0000-4000-8000-00000000000c"


def _file_object(uuid: str | None, *hashes: tuple[str, str]) -> MISPObject:
    return MISPObject(
        uuid=uuid,
        name="file",
        attributes=[MISPAttribute(type=t, value=v) for t, v in hashes],
    )


def _merge_pair() -> tuple[MISPEvent, MISPEvent]:
    destination = MISPEvent(
        uuid=MERGE_DESTINATION_UUID,
        info="Destination",
        tags={"kept"},
        attributes=[MISPAttribute(type="domain", value="d1.example")],
        objects=[
            _file_object(OBJECT_A, ("md5", "a" * 32)),
            _file_object(OBJECT_B, ("md5", "b" * 32)),
        ],
        galaxies=[Galaxy(name="g", clusters={"C1"})],
    )
    proposed = MISPEvent(
        uuid=MERGE_DESTINATION_UUID,
        info="Proposed",
        tags={"added"},
        attributes=[MISPAttribute(type="domain", value="d2.example")],
        objects=[
            _file_object(OBJECT_A, ("md5", "a" * 32), ("sha256", "c" * 64)),
            _file_object(OBJECT_B, ("md5", "b" * 32)),
        ],
        galaxies=[Galaxy(name="g", clusters={"C2"})],
    )
    return destination, proposed


def test_merge_is_order_independent_over_every_permutation() -> None:
    """Storage order must never change the merged event.

    Enumerating this beats patching examples: pairing same-key objects in
    stored order made the servers' order decide the result, so the same apply
    produced different events and event diff then reported drift it created.
    """
    destination, proposed = _merge_pair()
    fingerprints = set()
    for stored in permutations(destination.objects):
        for offered in permutations(proposed.objects):
            left = destination.model_copy(deep=True)
            left.objects = list(stored)
            right = proposed.model_copy(deep=True)
            right.objects = list(offered)
            fingerprints.add(merge_events(left, right).canonical_fingerprint())
    eq(len(fingerprints), 1)


def test_merge_is_idempotent_and_loses_nothing_from_either_side() -> None:
    """Merging the result again changes nothing, and both sides survive."""
    destination, proposed = _merge_pair()
    once = merge_events(destination, proposed)
    eq(
        merge_events(once, proposed).canonical_fingerprint(),
        once.canonical_fingerprint(),
    )

    merged_attributes = {(a.type, a.value) for a in once.attributes}
    merged_object_attributes = {(a.type, a.value) for o in once.objects for a in o.attributes}
    ok({(a.type, a.value) for a in destination.attributes} <= merged_attributes)
    ok({(a.type, a.value) for a in proposed.attributes} <= merged_attributes)
    ok({o.uuid for o in destination.objects} <= {o.uuid for o in once.objects})
    ok(
        {(a.type, a.value) for o in proposed.objects for a in o.attributes}
        <= merged_object_attributes
    )
    ok(destination.tags <= once.tags)
    ok(proposed.tags <= once.tags)
    eq(sorted(once.galaxies[0].clusters), ["C1", "C2"])


def test_merge_folds_case_only_tag_differences_to_the_destination() -> None:
    """MISP tags collate case-insensitively, so a case-only variant is one tag.

    A plain set union kept both ``TLP:RED`` and ``tlp:red``, and the merged
    event then fingerprinted with a duplicate tag no server can hold; the
    destination's spelling wins, as it does for every other field.
    """
    destination = MISPEvent(
        uuid="a" * 8 + "-0000-4000-8000-000000000001", info="x", tags={"TLP:RED"}
    )
    proposed = MISPEvent(uuid="a" * 8 + "-0000-4000-8000-000000000001", info="x", tags={"tlp:red"})
    merged = merge_events(destination, proposed)
    eq(merged.tags, {"TLP:RED"})
    eq([tag["name"] for tag in merged.to_misp()["Tag"]], ["TLP:RED"])


def test_merge_survives_the_shapes_the_first_property_tests_missed() -> None:
    """Counterexamples round 3 found to the invariants above.

    The first pass only generated UUID-carrying, uniquely-keyed objects, so it
    could not see any of these.
    """
    shared = "0b1ec700-0000-4000-8000-00000000000b"

    # Two proposed objects sharing a UUID: the loser used to be neither paired
    # nor appended, so its indicator vanished.
    destination = MISPEvent(uuid=MERGE_DESTINATION_UUID, info="D", objects=[_file_object(shared)])
    proposed = MISPEvent(
        uuid=MERGE_DESTINATION_UUID,
        info="P",
        objects=[
            _file_object(shared, ("md5", "a" * 32)),
            _file_object(shared, ("sha256", "c" * 64)),
        ],
    )
    kept = {a.type for o in merge_events(destination, proposed).objects for a in o.attributes}
    eq(kept, {"md5", "sha256"})

    # Proposed galaxies of one name: uniting them has to settle on one uuid
    # regardless of the order the server stored them in.
    def galaxy(uuid: str | None, cluster: str) -> Galaxy:
        return Galaxy(uuid=uuid, name="g", clusters={cluster})

    bare = MISPEvent(uuid=MERGE_DESTINATION_UUID, info="D")
    forward = MISPEvent(
        uuid=MERGE_DESTINATION_UUID, info="P", galaxies=[galaxy(None, "T1"), galaxy("U1", "T2")]
    )
    reverse = MISPEvent(
        uuid=MERGE_DESTINATION_UUID, info="P", galaxies=[galaxy("U1", "T2"), galaxy(None, "T1")]
    )
    eq(
        merge_events(bare, forward).canonical_fingerprint(),
        merge_events(bare, reverse).canonical_fingerprint(),
    )

    # A proposed object with no UUID used to be appended on every merge.
    anonymous = MISPEvent(
        uuid=MERGE_DESTINATION_UUID, info="P", objects=[_file_object(None, ("md5", "a" * 32))]
    )
    once = merge_events(bare, anonymous)
    eq(len(merge_events(once, anonymous).objects), len(once.objects))


_MD5 = ("md5", "a" * 32)
_SHA = ("sha256", "c" * 64)
_OBJECT_A = "0b1ec700-0000-4000-8000-000000000001"
_OBJECT_B = "0b1ec700-0000-4000-8000-000000000002"


def _shaped_object(
    uuid: str | None,
    *hashes: tuple[str, str],
    name: str = "file",
    referenced: str | None = None,
) -> MISPObject:
    references = (
        [
            ObjectReference(
                uuid="r1",
                object_uuid=uuid,
                referenced_uuid=referenced,
                relationship_type="related-to",
            )
        ]
        if referenced
        else []
    )
    return MISPObject(
        uuid=uuid,
        name=name,
        attributes=[MISPAttribute(type=t, value=v) for t, v in hashes],
        references=references,
    )


def _shaped_event(objects: list[MISPObject], galaxies: list[Galaxy], tag: str) -> MISPEvent:
    return MISPEvent(
        uuid=MERGE_DESTINATION_UUID,
        info="Shaped",
        tags={tag},
        attributes=[MISPAttribute(type="domain", value="x.example")],
        objects=list(objects),
        galaxies=list(galaxies),
    )


def _object_shapes() -> list[list[MISPObject]]:
    return [
        [],
        [_shaped_object(_OBJECT_A)],
        [_shaped_object(_OBJECT_A, _MD5)],
        [_shaped_object(None, _MD5)],
        [_shaped_object(_OBJECT_A, _MD5), _shaped_object(_OBJECT_B, _SHA)],
        # Duplicate UUIDs, same name and mixed names — both destabilised the
        # pairing in earlier rounds.
        [_shaped_object(_OBJECT_A, _MD5), _shaped_object(_OBJECT_A, _SHA)],
        [_shaped_object(_OBJECT_A, _MD5, name="pe")],
        [_shaped_object(_OBJECT_A, _MD5, name="pe"), _shaped_object(_OBJECT_A, _SHA)],
        [_shaped_object(None, _MD5), _shaped_object(None, _MD5)],
        [_shaped_object(_OBJECT_A, _MD5, referenced="t1")],
    ]


def _galaxy_shapes() -> list[list[Galaxy]]:
    return [
        [],
        [Galaxy(name="g", clusters={"T1"})],
        [Galaxy(uuid="G1", name="g", clusters={"T2"})],
        [Galaxy(name="g", clusters={"T1"}), Galaxy(uuid="G1", name="g", clusters={"T2"})],
    ]


def _content(event: MISPEvent) -> list[set[str]]:
    """Every indicator, cluster and tag the event carries, as comparable sets."""
    return [
        {f"{a.type}|{a.value}" for a in event.attributes},
        {f"{a.type}|{a.value}" for o in event.objects for a in o.attributes},
        {c for g in event.galaxies for c in g.clusters},
        set(event.tags),
    ]


def test_merge_invariants_hold_across_every_generated_shape() -> None:
    """Order independence, idempotence and no loss, enumerated.

    Four rounds of hand-written examples each missed the next shape: duplicate
    UUIDs, duplicate UUIDs under different names, UUID-less objects, galaxies
    that share a name but not a uuid. Enumerating the shapes and permuting
    both sides catches the class instead of the instance.
    """
    objects = _object_shapes()
    galaxies = _galaxy_shapes()
    checked = 0
    for stored_objects, offered_objects in product(objects, repeat=2):
        for stored_galaxies, offered_galaxies in product(galaxies, repeat=2):
            checked += 1
            destination = _shaped_event(stored_objects, stored_galaxies, "kept")
            proposed = _shaped_event(offered_objects, offered_galaxies, "added")
            merged = merge_events(destination, proposed)
            fingerprint = merged.canonical_fingerprint()

            for left in permutations(stored_objects):
                for right in permutations(offered_objects):
                    shuffled = merge_events(
                        _shaped_event(list(left), stored_galaxies, "kept"),
                        _shaped_event(list(right), offered_galaxies, "added"),
                    )
                    eq(shuffled.canonical_fingerprint(), fingerprint)
            for left_galaxies in permutations(stored_galaxies):
                for right_galaxies in permutations(offered_galaxies):
                    shuffled = merge_events(
                        _shaped_event(stored_objects, list(left_galaxies), "kept"),
                        _shaped_event(offered_objects, list(right_galaxies), "added"),
                    )
                    eq(shuffled.canonical_fingerprint(), fingerprint)

            eq(merge_events(merged, proposed).canonical_fingerprint(), fingerprint)

            merged_content = _content(merged)
            for side in (destination, proposed):
                for present, kept in zip(_content(side), merged_content, strict=True):
                    ok(present <= kept)
    ok(checked > 100)


def _observation_shapes() -> list[tuple[list[Sighting], list[Proposal]]]:
    return [
        ([], []),
        ([Sighting(uuid="s1", attribute_uuid="a1")], []),
        ([], [Proposal(uuid="p1", type="domain", value="x")]),
        # Duplicates: the diff compares both dimensions as multisets, so the
        # merge has to keep the cardinality rather than collapse it.
        ([Sighting(attribute_uuid="a1"), Sighting(attribute_uuid="a1")], []),
        ([], [Proposal(type="domain", value="x"), Proposal(type="domain", value="x")]),
        (
            [Sighting(uuid="s1", attribute_uuid="a1", organisation="ORG-A")],
            [Proposal(uuid="p1", type="domain", value="x", to_ids=True)],
        ),
    ]


def _observed(event: MISPEvent) -> tuple[list[str], list[str]]:
    """Sightings and proposals as sorted multisets of their whole content."""
    return (
        sorted(json.dumps(s.model_dump(), sort_keys=True) for s in event.sightings),
        sorted(json.dumps(p.model_dump(), sort_keys=True) for p in event.proposals),
    )


def test_merge_keeps_every_sighting_and_proposal_it_was_given() -> None:
    """The fingerprint excludes both dimensions, so the other enumeration is blind.

    Both were left out of the merge entirely at first, and the fix that added
    them then collapsed duplicates the diff had just been taught to count.
    """
    checked = 0
    for stored, offered in product(_observation_shapes(), repeat=2):
        destination = _shaped_event([], [], "kept").model_copy(
            update={"sightings": list(stored[0]), "proposals": list(stored[1])}
        )
        proposed = _shaped_event([], [], "added").model_copy(
            update={"sightings": list(offered[0]), "proposals": list(offered[1])}
        )
        merged = merge_events(destination, proposed)
        expected = _observed(merged)
        checked += 1

        for sightings in permutations(offered[0]):
            for proposals in permutations(offered[1]):
                shuffled = merge_events(
                    destination,
                    proposed.model_copy(
                        update={"sightings": list(sightings), "proposals": list(proposals)}
                    ),
                )
                eq(_observed(shuffled), expected)

        eq(_observed(merge_events(merged, proposed)), expected)

        # Nothing either side offered may go missing, cardinality included.
        merged_sightings, merged_proposals = (Counter(part) for part in _observed(merged))
        for side in (destination, proposed):
            side_sightings, side_proposals = (Counter(part) for part in _observed(side))
            for entry, count in side_sightings.items():
                ok(merged_sightings[entry] >= count)
            for entry, count in side_proposals.items():
                ok(merged_proposals[entry] >= count)
    ok(checked > 30)
