"""Deterministic event comparison across two servers."""

from __future__ import annotations

from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.diff import Difference, DiffOperation, DiffSummary, EventDiff
from mispfleet.models.event import MISPEvent

_METADATA_FIELDS = (
    "info",
    "date",
    "published",
    "distribution",
    "threat_level",
    "analysis",
    "orgc",
)

_ATTRIBUTE_FIELDS = ("category", "to_ids", "comment", "deleted")


def _attribute_key(attribute: MISPAttribute) -> str:
    return f"{attribute.type}|{attribute.value}"


def _diff_attributes(
    path_prefix: str,
    left: list[MISPAttribute],
    right: list[MISPAttribute],
) -> list[Difference]:
    differences: list[Difference] = []
    left_by_key = {_attribute_key(item): item for item in left}
    right_by_key = {_attribute_key(item): item for item in right}
    for key in sorted(left_by_key.keys() | right_by_key.keys()):
        path = f"{path_prefix}[{key}]"
        left_item = left_by_key.get(key)
        right_item = right_by_key.get(key)
        if left_item is None:
            differences.append(Difference(operation=DiffOperation.ADD, path=path))
            continue
        if right_item is None:
            differences.append(Difference(operation=DiffOperation.REMOVE, path=path))
            continue
        for field in _ATTRIBUTE_FIELDS:
            left_value = getattr(left_item, field)
            right_value = getattr(right_item, field)
            if left_value != right_value:
                differences.append(
                    Difference(
                        operation=DiffOperation.CONFLICT,
                        path=f"{path}.{field}",
                        left=left_value,
                        right=right_value,
                    )
                )
        if left_item.tags != right_item.tags:
            differences.append(
                Difference(
                    operation=DiffOperation.CONFLICT,
                    path=f"{path}.tags",
                    left=sorted(left_item.tags),
                    right=sorted(right_item.tags),
                )
            )
    return differences


def diff_events(
    identifier: str,
    left_server: str,
    right_server: str,
    left: MISPEvent,
    right: MISPEvent,
) -> EventDiff:
    """Compare two normalized event versions dimension by dimension."""
    differences: list[Difference] = []
    for field in _METADATA_FIELDS:
        left_value = getattr(left, field)
        right_value = getattr(right, field)
        if left_value != right_value:
            differences.append(
                Difference(
                    operation=DiffOperation.CHANGE,
                    path=field,
                    left=left_value,
                    right=right_value,
                )
            )
    for tag in sorted(right.tags - left.tags):
        differences.append(Difference(operation=DiffOperation.ADD, path=f"tags[{tag}]"))
    for tag in sorted(left.tags - right.tags):
        differences.append(Difference(operation=DiffOperation.REMOVE, path=f"tags[{tag}]"))
    differences.extend(_diff_attributes("attributes", left.attributes, right.attributes))
    left_objects = {obj.name: obj for obj in left.objects}
    right_objects = {obj.name: obj for obj in right.objects}
    for name in sorted(left_objects.keys() | right_objects.keys()):
        left_obj = left_objects.get(name)
        right_obj = right_objects.get(name)
        if left_obj is None:
            differences.append(Difference(operation=DiffOperation.ADD, path=f"objects[{name}]"))
            continue
        if right_obj is None:
            differences.append(Difference(operation=DiffOperation.REMOVE, path=f"objects[{name}]"))
            continue
        differences.extend(
            _diff_attributes(
                f"objects[{name}].attributes",
                left_obj.attributes,
                right_obj.attributes,
            )
        )
    summary = DiffSummary(
        added=sum(1 for d in differences if d.operation is DiffOperation.ADD),
        removed=sum(1 for d in differences if d.operation is DiffOperation.REMOVE),
        changed=sum(1 for d in differences if d.operation is DiffOperation.CHANGE),
        conflicts=sum(1 for d in differences if d.operation is DiffOperation.CONFLICT),
    )
    return EventDiff(
        event_identifier=identifier,
        left_server=left_server,
        right_server=right_server,
        equivalent=not differences,
        differences=differences,
        summary=summary,
    )
