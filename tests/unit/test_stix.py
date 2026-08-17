"""Unit tests for the deterministic STIX 2.1 mapping."""

from __future__ import annotations

from typing import Any

from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent
from mispfleet.output.stix import SPEC_VERSION, event_to_stix_bundle
from tests.support import contains, eq, ne, not_contains, ok

EVENT_UUID = "9c5c1c2e-0000-4000-8000-00000000000e"


def event(**overrides: Any) -> MISPEvent:
    fields: dict[str, Any] = {
        "uuid": EVENT_UUID,
        "info": "Campaign X",
        "timestamp": "1700000000",
        "orgc": "CIRCL",
        "tags": {"tlp:green", "malware"},
        "attributes": [
            MISPAttribute(type="domain", value="evil.example", tags={"confidence:high"}),
            MISPAttribute(type="sha256", value="aa" * 32),
            MISPAttribute(type="ip-dst", value="203.0.113.7"),
        ],
    }
    fields.update(overrides)
    return MISPEvent.model_validate(fields)


def _by_type(bundle: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [obj for obj in bundle["objects"] if obj.get("type") == kind]


def test_bundle_contains_report_indicators_identity_and_marking() -> None:
    bundle, skipped = event_to_stix_bundle(event())
    eq(bundle["type"], "bundle")
    eq(skipped, [])
    reports = _by_type(bundle, "report")
    eq(len(reports), 1)
    eq(reports[0]["spec_version"], SPEC_VERSION)
    eq(reports[0]["name"], "Campaign X")
    eq(sorted(reports[0]["labels"]), ["malware", "tlp:green"])
    indicators = _by_type(bundle, "indicator")
    eq(len(indicators), 3)
    patterns = {indicator["pattern"] for indicator in indicators}
    contains(patterns, "[domain-name:value = 'evil.example']")
    contains(patterns, "[ipv4-addr:value = '203.0.113.7']")
    contains(patterns, f"[file:hashes.'SHA-256' = '{'aa' * 32}']")
    identities = _by_type(bundle, "identity")
    eq(identities[0]["name"], "CIRCL")
    markings = _by_type(bundle, "marking-definition")
    eq(markings[0]["definition"], {"tlp": "green"})
    eq(reports[0]["object_marking_refs"], markings[0]["id"] and [markings[0]["id"]])


def test_unmapped_attribute_types_are_reported_not_dropped_silently() -> None:
    bundle, skipped = event_to_stix_bundle(
        event(
            attributes=[
                MISPAttribute(type="domain", value="evil.example"),
                MISPAttribute(type="passport-number", value="X123"),
                MISPAttribute(type="btc", value="1abc"),
            ]
        )
    )
    eq(skipped, ["btc", "passport-number"])
    eq(len(_by_type(bundle, "indicator")), 1)


def test_object_attributes_are_included() -> None:
    bundle, _ = event_to_stix_bundle(
        event(
            attributes=[],
            objects=[
                MISPObject(
                    name="file",
                    attributes=[MISPAttribute(type="md5", value="bb" * 16)],
                )
            ],
        )
    )
    indicators = _by_type(bundle, "indicator")
    eq(len(indicators), 1)
    contains(indicators[0]["pattern"], "file:hashes.MD5")


def test_mapping_is_deterministic() -> None:
    first, _ = event_to_stix_bundle(event())
    second, _ = event_to_stix_bundle(event())
    eq(first, second)
    changed, _ = event_to_stix_bundle(event(info="Renamed"))
    ne(first["id"], changed["id"])


def test_pattern_values_are_escaped() -> None:
    bundle, _ = event_to_stix_bundle(
        event(attributes=[MISPAttribute(type="domain", value="o'brien\\evil")])
    )
    pattern = _by_type(bundle, "indicator")[0]["pattern"]
    contains(pattern, "\\'")
    contains(pattern, "\\\\")


def test_event_without_indicators_still_references_something() -> None:
    bundle, skipped = event_to_stix_bundle(
        event(attributes=[MISPAttribute(type="btc", value="1abc")], orgc="CIRCL")
    )
    eq(skipped, ["btc"])
    report = _by_type(bundle, "report")[0]
    ok(len(report["object_refs"]) == 1)


def test_missing_timestamp_and_org_use_safe_defaults() -> None:
    bundle, _ = event_to_stix_bundle(
        MISPEvent(uuid=EVENT_UUID, attributes=[MISPAttribute(type="domain", value="x.example")])
    )
    report = _by_type(bundle, "report")[0]
    contains(report["created"], "1970-01-01")
    eq(_by_type(bundle, "identity"), [])
    not_contains(report, "object_marking_refs")


def test_tlp_red_and_clear_map_to_markings() -> None:
    red, _ = event_to_stix_bundle(event(tags={"tlp:red"}))
    eq(_by_type(red, "marking-definition")[0]["definition"], {"tlp": "red"})
    clear, _ = event_to_stix_bundle(event(tags={"tlp:clear"}))
    eq(_by_type(clear, "marking-definition")[0]["definition"], {"tlp": "white"})


def test_report_never_references_an_absent_identity() -> None:
    bare = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        info="No mappable indicators",
        attributes=[MISPAttribute(type="comment", value="just a note")],
    )
    bundle, skipped = event_to_stix_bundle(bare)
    eq(skipped, ["comment"])
    present = {str(obj["id"]) for obj in bundle["objects"]}
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    for reference in report["object_refs"]:
        ok(reference in present)


def test_uuid_less_duplicate_attributes_produce_one_indicator() -> None:
    """The id seed falls back to type|value when an attribute has no uuid.

    Two such attributes hashed to the same STIX id, so the bundle carried two
    objects sharing one id and a duplicated entry in the report's object_refs.
    """
    duplicated = event(
        attributes=[MISPAttribute(type="domain", value="evil.example")],
        objects=[
            MISPObject(
                name="domain-ip",
                attributes=[MISPAttribute(type="domain", value="evil.example")],
            )
        ],
    )
    bundle, _ = event_to_stix_bundle(duplicated)
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    eq(len(indicators), 1)
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    eq(len(report["object_refs"]), len(set(report["object_refs"])))


def test_ipv6_indicators_use_the_ipv6_object_type() -> None:
    """ip-src/ip-dst carry v4 and v6 alike on MISP.

    Hard-coding ipv4-addr produced a well-formed pattern that can never match.
    """
    mixed = event(
        attributes=[
            MISPAttribute(type="ip-dst", value="2001:db8::1"),
            MISPAttribute(type="ip-src", value="203.0.113.7"),
        ]
    )
    bundle, _ = event_to_stix_bundle(mixed)
    patterns = {
        obj["name"]: obj["pattern"] for obj in bundle["objects"] if obj["type"] == "indicator"
    }
    contains(patterns["ip-dst: 2001:db8::1"], "ipv6-addr:value")
    contains(patterns["ip-src: 203.0.113.7"], "ipv4-addr:value")


def test_unparsable_address_keeps_the_ipv4_mapping() -> None:
    bundle, _ = event_to_stix_bundle(
        event(attributes=[MISPAttribute(type="ip-dst", value="not-an-address")])
    )
    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    contains(indicator["pattern"], "ipv4-addr:value")


def test_an_unrepresentable_event_timestamp_falls_back_to_the_epoch() -> None:
    """timestamp is server-supplied; isdigit accepts values no platform can map."""
    event = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        info="Overflowing",
        timestamp="99999999999999999999",
        attributes=[MISPAttribute(type="domain", value="evil.example")],
    )
    bundle, _ = event_to_stix_bundle(event)
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    eq(report["created"], "1970-01-01T00:00:00.000Z")


def indicators(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return [obj for obj in bundle["objects"] if obj["type"] == "indicator"]


def markings(bundle: dict[str, Any]) -> list[str]:
    return [obj["name"] for obj in bundle["objects"] if obj["type"] == "marking-definition"]


def test_an_attribute_keeps_its_own_tlp_marking() -> None:
    """Markings are the normative mechanism; labels are not.

    A tlp:red attribute inside a tlp:green event used to be published with the
    event's GREEN marking alone, so a consumer honoring markings could
    redistribute it.
    """
    event = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        tags={"tlp:green"},
        attributes=[MISPAttribute(uuid="a1", type="md5", value="d" * 32, tags={"tlp:red"})],
    )
    bundle, _ = event_to_stix_bundle(event)
    red = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    contains(indicators(bundle)[0]["object_marking_refs"], red)
    contains(markings(bundle), "TLP:RED")


def test_tlp_tags_are_matched_case_insensitively_and_cover_amber_strict() -> None:
    """An unmatched TLP tag exported as an unmarked, i.e. unrestricted, bundle."""
    for tag, expected in (
        ("TLP:RED", "TLP:RED"),
        ("tlp:amber+strict", "TLP:AMBER"),
        ("Tlp:Green", "TLP:GREEN"),
    ):
        event = MISPEvent(
            uuid="9c5c1c2e-0000-4000-8000-00000000000e",
            tags={tag},
            attributes=[MISPAttribute(uuid="a1", type="md5", value="d" * 32)],
        )
        bundle, _ = event_to_stix_bundle(event)
        eq(markings(bundle), [expected])
        ok(indicators(bundle)[0]["object_marking_refs"])


def test_collapsing_two_identical_attributes_keeps_both_sets_of_tags() -> None:
    """The dropped duplicate took its tags — and its TLP marking — with it."""
    bundles = []
    for reverse in (False, True):
        attributes = [
            MISPAttribute(type="md5", value="a" * 32),
            MISPAttribute(type="md5", value="a" * 32, tags={"tlp:red"}),
        ]
        if reverse:
            attributes.reverse()
        event = MISPEvent(
            uuid="9c5c1c2e-0000-4000-8000-00000000000e", tags=set(), attributes=attributes
        )
        bundle, _ = event_to_stix_bundle(event)
        eq(len(indicators(bundle)), 1)
        contains(indicators(bundle)[0]["labels"], "tlp:red")
        contains(markings(bundle), "TLP:RED")
        bundles.append(bundle)
    eq(bundles[0], bundles[1])
