"""Unit and property tests for deterministic event similarity."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent
from mispfleet.services.similarity import (
    POSSIBLE_MATCH_THRESHOLD,
    event_similarity,
    indicator_set,
    similarity_from_parts,
)
from tests.support import eq, ok


def event(uuid_suffix: str, info: str, values: list[str], tags: set[str]) -> MISPEvent:
    return MISPEvent(
        uuid=f"9c5c1c2e-0000-4000-8000-00000000000{uuid_suffix}",
        info=info,
        tags=tags,
        attributes=[MISPAttribute(type="domain", value=value) for value in values],
    )


def test_identical_events_score_one() -> None:
    left = event("1", "Campaign X", ["a.example", "b.example"], {"tlp:green"})
    right = event("2", "Campaign X", ["a.example", "b.example"], {"tlp:green"})
    score = event_similarity(left, right)
    eq(score.score, 1.0)
    eq(score.shared_indicators, 2)
    ok(score.score >= POSSIBLE_MATCH_THRESHOLD)


def test_disjoint_events_score_low() -> None:
    left = event("1", "Campaign X", ["a.example"], {"tlp:green"})
    right = event("2", "Totally different", ["z.example"], {"tlp:red"})
    score = event_similarity(left, right)
    ok(score.score < POSSIBLE_MATCH_THRESHOLD)
    eq(score.shared_indicators, 0)


def test_object_attributes_count_as_indicators() -> None:
    holder = event("1", "Campaign X", [], set())
    holder.objects = [
        MISPObject(name="domain-ip", attributes=[MISPAttribute(type="ip-dst", value="10.0.0.1")])
    ]
    eq(indicator_set(holder), {"ip-dst|10.0.0.1"})


def test_composite_types_do_not_forge_a_shared_indicator() -> None:
    """A "|" in a composite type and value must not collide two indicators.

    ``("regkey", "value|x")`` and ``("regkey|value", "x")`` are different
    attributes; an unescaped ``type|value`` join folded both to
    ``regkey|value|x`` and scored two disjoint events as sharing an indicator.
    """
    left = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-000000000001",
        info="left",
        attributes=[MISPAttribute(type="regkey", value="value|x")],
    )
    right = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-000000000002",
        info="right",
        attributes=[MISPAttribute(type="regkey|value", value="x")],
    )
    eq(indicator_set(left) & indicator_set(right), set())
    eq(event_similarity(left, right).shared_indicators, 0)


def test_empty_sets_are_no_evidence_of_similarity() -> None:
    score = similarity_from_parts(set(), set(), set(), set(), "same", "same")
    eq(score.attribute_overlap, 0.0)
    eq(score.tag_overlap, 0.0)
    ok(score.score < POSSIBLE_MATCH_THRESHOLD)


def test_untagged_events_sharing_one_indicator_are_not_a_possible_match() -> None:
    """Two untagged events matching the same searched indicator are unrelated.

    Scoring empty-vs-empty tags as a perfect overlap put every such pair over
    the threshold on its own, so a federated search for one IOC reported every
    pair of results as a possible match.
    """
    score = similarity_from_parts(
        {"ip-dst|8.8.8.8"},
        {"ip-dst|8.8.8.8"},
        set(),
        set(),
        "Phishing wave",
        "Unrelated botnet report",
    )
    eq(score.shared_indicators, 1)
    ok(score.score < POSSIBLE_MATCH_THRESHOLD)


def test_tag_overlap_is_case_insensitive_like_misp() -> None:
    """MISP treats TLP:RED and tlp:red as one tag; scoring them as distinct

    undercounts the overlap between two identically-tagged events.
    """
    folded = similarity_from_parts(
        {"ip-dst|8.8.8.8"}, {"ip-dst|8.8.8.8"}, {"TLP:RED"}, {"tlp:red"}, "same", "same"
    )
    same_case = similarity_from_parts(
        {"ip-dst|8.8.8.8"}, {"ip-dst|8.8.8.8"}, {"tlp:red"}, {"tlp:red"}, "same", "same"
    )
    eq(folded.tag_overlap, 1.0)
    eq(folded.score, same_case.score)


@given(
    left_values=st.sets(st.sampled_from(["a", "b", "c", "d"]), max_size=4),
    right_values=st.sets(st.sampled_from(["a", "b", "c", "d"]), max_size=4),
    left_tags=st.sets(st.sampled_from(["t1", "t2", "t3"]), max_size=3),
    right_tags=st.sets(st.sampled_from(["t1", "t2", "t3"]), max_size=3),
    left_info=st.text(max_size=20),
    right_info=st.text(max_size=20),
)
def test_similarity_is_symmetric_and_bounded(
    left_values: set[str],
    right_values: set[str],
    left_tags: set[str],
    right_tags: set[str],
    left_info: str,
    right_info: str,
) -> None:
    forward = similarity_from_parts(
        left_values, right_values, left_tags, right_tags, left_info, right_info
    )
    backward = similarity_from_parts(
        right_values, left_values, right_tags, left_tags, right_info, left_info
    )
    eq(forward, backward)
    ok(0.0 <= forward.score <= 1.0)


def test_group_matches_skips_dissimilar_event_pairs() -> None:
    from uuid import UUID

    from mispfleet.models.result import FederatedMatch
    from mispfleet.services.search import group_matches

    left = FederatedMatch(
        server="alpha",
        event_uuid=UUID("11111111-0000-4000-8000-000000000001"),
        attribute_type="domain",
        value="one.example",
        event_info="Emotet wave",
        tags={"tlp:green"},
    )
    right = FederatedMatch(
        server="beta",
        event_uuid=UUID("22222222-0000-4000-8000-000000000002"),
        attribute_type="sha256",
        value="ff" * 32,
        event_info="Unrelated intrusion",
        tags={"tlp:red"},
    )
    groups = group_matches([left, right])
    eq(groups, [])


def test_group_matches_does_not_forge_a_duplicate_from_composite_types() -> None:
    """Composite ``type|value`` matches must not collide into one group.

    ``("regkey", "value|x")`` and ``("regkey|value", "x")`` are different
    indicators from different servers; an unescaped key folded both to
    ``regkey|value|x`` and reported them as one duplicated attribute.
    """
    from uuid import UUID

    from mispfleet.models.result import FederatedMatch
    from mispfleet.services.search import group_matches

    left = FederatedMatch(
        server="alpha",
        event_uuid=UUID("11111111-0000-4000-8000-000000000001"),
        attribute_type="regkey",
        value="value|x",
    )
    right = FederatedMatch(
        server="beta",
        event_uuid=UUID("22222222-0000-4000-8000-000000000002"),
        attribute_type="regkey|value",
        value="x",
    )
    eq(group_matches([left, right]), [])
