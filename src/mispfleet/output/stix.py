"""Deterministic STIX 2.1 bundle generation from normalized MISP events.

Pure JSON construction: identifiers are UUIDv5 values derived from the event
content, so exporting the same event twice yields the identical bundle.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent

SPEC_VERSION = "2.1"

_NAMESPACE = uuid5(NAMESPACE_URL, "https://github.com/seifreed/MispFleet/stix")

_PATTERN_TEMPLATES = {
    "ip-src": "[ipv4-addr:value = '{value}']",
    "ip-dst": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "hostname": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "email-src": "[email-addr:value = '{value}']",
    "email-dst": "[email-addr:value = '{value}']",
    "filename": "[file:name = '{value}']",
}

_TLP_MARKINGS = {
    "tlp:white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp:clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp:green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "tlp:amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    # STIX 2.1 fixes four TLP definitions, so the TLP 2.0 "+strict" variant
    # maps onto plain AMBER: the alternative is exporting the most restricted
    # level as an unmarked, i.e. unrestricted, bundle.
    "tlp:amber+strict": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "tlp:red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_TLP_DEFINITIONS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}


def _pattern_template(attribute: MISPAttribute) -> str | None:
    """The STIX pattern for one attribute, chosen by type and by value.

    MISP's ip-src/ip-dst carry v4 and v6 alike, so the object type has to come
    from the address itself: an IPv6 value under ipv4-addr is a well-formed
    pattern that can never match.
    """
    if attribute.type in ("ip-src", "ip-dst"):
        try:
            version = ip_address(attribute.value).version
        except ValueError:
            version = 4
        return f"[ipv{version}-addr:value = '{{value}}']"
    return _PATTERN_TEMPLATES.get(attribute.type)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _markings(tags: Iterable[str]) -> set[str]:
    """Marking ids for the TLP tags in ``tags``.

    Matched case-insensitively because MISP accepts ``TLP:RED`` as readily as
    ``tlp:red``, and an unmatched TLP tag exports as no marking at all.
    """
    folded = (tag.casefold() for tag in tags)
    return {_TLP_MARKINGS[tag] for tag in folded if tag in _TLP_MARKINGS}


def _stix_id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid5(_NAMESPACE, f'{kind}:{seed}')}"


def _event_time(event: MISPEvent) -> str:
    """The event's instant, falling back to the epoch for anything unusable.

    ``timestamp`` is whatever the server sent, and ``isdigit`` happily accepts
    a number no platform can turn into a date; the resulting OverflowError
    aborted every STIX export of that event.
    """
    moment = datetime.fromtimestamp(0, tz=UTC)
    if event.timestamp is not None and event.timestamp.isdigit():
        try:
            moment = datetime.fromtimestamp(int(event.timestamp), tz=UTC)
        except OverflowError, OSError, ValueError:
            moment = datetime.fromtimestamp(0, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _indicator(
    attribute: MISPAttribute,
    identifier: str,
    pattern: str,
    created: str,
    marking_refs: list[str],
    tags: set[str],
) -> dict[str, Any]:
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": identifier,
        "created": created,
        "modified": created,
        "name": f"{attribute.type}: {attribute.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
    }
    if tags:
        indicator["labels"] = sorted(tags)
    if marking_refs:
        indicator["object_marking_refs"] = marking_refs
    return indicator


def event_to_stix_bundle(event: MISPEvent) -> tuple[dict[str, Any], list[str]]:
    """Convert a normalized event into a STIX 2.1 bundle.

    Returns the bundle and the sorted list of attribute types that have no
    STIX pattern mapping and were therefore omitted.
    """
    created = _event_time(event)
    marking_refs = sorted(_markings(event.tags))
    skipped: set[str] = set()
    attributes = list(event.attributes)
    for obj in event.objects:
        attributes.extend(obj.attributes)
    # Collapse attributes sharing a STIX id (two uuid-less ones of the same
    # type and value) rather than dropping the later one, which carried away
    # its tags and with them its TLP marking. uuid completes the sort key so
    # the survivor does not depend on insertion order.
    collapsed: dict[str, tuple[MISPAttribute, str, set[str]]] = {}
    for attribute in sorted(attributes, key=lambda item: (item.type, item.value, item.uuid or "")):
        template = _pattern_template(attribute)
        if template is None:
            skipped.add(attribute.type)
            continue
        seed = attribute.uuid or f"{attribute.type}|{attribute.value}"
        identifier = _stix_id("indicator", seed)
        existing = collapsed.get(identifier)
        if existing is None:
            collapsed[identifier] = (
                attribute,
                template.format(value=_escape(attribute.value)),
                set(attribute.tags),
            )
        else:
            existing[2].update(attribute.tags)
    # An attribute's own TLP has to reach its indicator: markings are the
    # normative mechanism, so a tlp:red attribute inside a tlp:green event used
    # to be published to consumers as GREEN.
    indicator_markings = {
        identifier: sorted(set(marking_refs) | _markings(tags))
        for identifier, (_, _, tags) in collapsed.items()
    }
    every_marking = sorted(set(marking_refs).union(*indicator_markings.values()))
    objects: list[dict[str, Any]] = []
    for marking_id in every_marking:
        objects.append(
            {
                "type": "marking-definition",
                "spec_version": SPEC_VERSION,
                "id": marking_id,
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": f"TLP:{_TLP_DEFINITIONS[marking_id].upper()}",
                "definition": {"tlp": _TLP_DEFINITIONS[marking_id]},
            }
        )
    identity_name = event.orgc if event.orgc is not None else "unknown"
    identity_id = _stix_id("identity", identity_name)
    if event.orgc is not None:
        objects.append(
            {
                "type": "identity",
                "spec_version": SPEC_VERSION,
                "id": identity_id,
                "created": created,
                "modified": created,
                "name": event.orgc,
                "identity_class": "organization",
            }
        )
    indicator_refs: list[str] = []
    for identifier, (attribute, pattern, tags) in collapsed.items():
        objects.append(
            _indicator(
                attribute, identifier, pattern, created, indicator_markings[identifier], tags
            )
        )
        indicator_refs.append(identifier)
    report: dict[str, Any] = {
        "type": "report",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("report", event.uuid),
        "created": created,
        "modified": created,
        "published": created,
        "name": event.info or f"MISP event {event.uuid}",
        "report_types": ["threat-report"],
        "object_refs": indicator_refs or [identity_id],
    }
    if not indicator_refs and event.orgc is None:
        # A report may not reference an object the bundle does not carry:
        # without indicators nor a creator organisation, publish a placeholder
        # identity so the bundle stays internally consistent.
        objects.insert(
            len(every_marking),
            {
                "type": "identity",
                "spec_version": SPEC_VERSION,
                "id": identity_id,
                "created": created,
                "modified": created,
                "name": identity_name,
                "identity_class": "organization",
            },
        )
    if event.tags:
        report["labels"] = sorted(event.tags)
    if marking_refs:
        report["object_marking_refs"] = marking_refs
    objects.append(report)
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", event.canonical_fingerprint()),
        "objects": objects,
    }
    return bundle, sorted(skipped)
