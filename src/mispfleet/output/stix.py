"""Deterministic STIX 2.1 bundle generation from normalized MISP events.

Pure JSON construction: identifiers are UUIDv5 values derived from the event
content, so exporting the same event twice yields the identical bundle.
"""

from __future__ import annotations

from datetime import UTC, datetime
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
    "tlp:red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_TLP_DEFINITIONS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid5(_NAMESPACE, f'{kind}:{seed}')}"


def _event_time(event: MISPEvent) -> str:
    if event.timestamp is not None and event.timestamp.isdigit():
        moment = datetime.fromtimestamp(int(event.timestamp), tz=UTC)
    else:
        moment = datetime.fromtimestamp(0, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _indicator(
    attribute: MISPAttribute,
    pattern: str,
    created: str,
    marking_refs: list[str],
) -> dict[str, Any]:
    seed = attribute.uuid or f"{attribute.type}|{attribute.value}"
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("indicator", seed),
        "created": created,
        "modified": created,
        "name": f"{attribute.type}: {attribute.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
    }
    if attribute.tags:
        indicator["labels"] = sorted(attribute.tags)
    if marking_refs:
        indicator["object_marking_refs"] = marking_refs
    return indicator


def event_to_stix_bundle(event: MISPEvent) -> tuple[dict[str, Any], list[str]]:
    """Convert a normalized event into a STIX 2.1 bundle.

    Returns the bundle and the sorted list of attribute types that have no
    STIX pattern mapping and were therefore omitted.
    """
    created = _event_time(event)
    marking_refs = sorted({_TLP_MARKINGS[tag] for tag in event.tags if tag in _TLP_MARKINGS})
    objects: list[dict[str, Any]] = []
    for marking_id in marking_refs:
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
    if event.orgc is not None:
        objects.append(
            {
                "type": "identity",
                "spec_version": SPEC_VERSION,
                "id": _stix_id("identity", event.orgc),
                "created": created,
                "modified": created,
                "name": event.orgc,
                "identity_class": "organization",
            }
        )
    skipped: set[str] = set()
    indicator_refs: list[str] = []
    attributes = list(event.attributes)
    for obj in event.objects:
        attributes.extend(obj.attributes)
    for attribute in sorted(attributes, key=lambda item: (item.type, item.value)):
        template = _PATTERN_TEMPLATES.get(attribute.type)
        if template is None:
            skipped.add(attribute.type)
            continue
        pattern = template.format(value=_escape(attribute.value))
        indicator = _indicator(attribute, pattern, created, marking_refs)
        objects.append(indicator)
        indicator_refs.append(str(indicator["id"]))
    report: dict[str, Any] = {
        "type": "report",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("report", event.uuid),
        "created": created,
        "modified": created,
        "published": created,
        "name": event.info or f"MISP event {event.uuid}",
        "report_types": ["threat-report"],
        "object_refs": indicator_refs or [_stix_id("identity", event.orgc or "unknown")],
    }
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
