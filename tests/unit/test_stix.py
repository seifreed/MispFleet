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
