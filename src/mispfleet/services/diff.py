"""Deterministic event comparison across two servers."""

from __future__ import annotations

from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.diff import Difference, DiffOperation, DiffSummary, EventDiff
from mispfleet.models.event import MISPEvent

_METADATA_FIELDS = (
    "info",
    "date",
    "published",
    "distribution",
    "sharing_group_id",
    "threat_level",
    "analysis",
    "orgc",
    "orgc_uuid",
)

_ATTRIBUTE_FIELDS = ("category", "to_ids", "comment", "deleted")


def _attribute_key(attribute: MISPAttribute) -> str:
    return f"{attribute.type}|{attribute.value}"


def _object_key(obj: MISPObject) -> str:
    return obj.uuid or obj.name


def _galaxy_entries(event: MISPEvent) -> set[str]:
    entries: set[str] = set()
    for galaxy in event.galaxies:
        entries.add(galaxy.name)
        entries.update(f"{galaxy.name}/{cluster}" for cluster in galaxy.clusters)
    return entries


def _sighting_entries(event: MISPEvent) -> set[str]:
    return {
        f"{item.attribute_uuid or ''}|{item.type}|{item.date_sighting or ''}"
        for item in event.sightings
    }


def _proposal_entries(event: MISPEvent) -> set[str]:
    return {f"{item.type}|{item.value}" for item in event.proposals}


def _reference_entries(obj: MISPObject) -> set[str]:
    return {f"{ref.referenced_uuid}|{ref.relationship_type}" for ref in obj.references}


def _diff_entry_sets(path_prefix: str, left: set[str], right: set[str]) -> list[Difference]:
    differences: list[Difference] = []
    for entry in sorted(right - left):
        differences.append(Difference(operation=DiffOperation.ADD, path=f"{path_prefix}[{entry}]"))
    for entry in sorted(left - right):
        differences.append(
            Difference(operation=DiffOperation.REMOVE, path=f"{path_prefix}[{entry}]")
        )
    return differences


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


def _diff_objects(left: list[MISPObject], right: list[MISPObject]) -> list[Difference]:
    differences: list[Difference] = []
    left_objects = {_object_key(obj): obj for obj in left}
    right_objects = {_object_key(obj): obj for obj in right}
    for key in sorted(left_objects.keys() | right_objects.keys()):
        left_obj = left_objects.get(key)
        right_obj = right_objects.get(key)
        if left_obj is None:
            differences.append(Difference(operation=DiffOperation.ADD, path=f"objects[{key}]"))
            continue
        if right_obj is None:
            differences.append(Difference(operation=DiffOperation.REMOVE, path=f"objects[{key}]"))
            continue
        differences.extend(
            _diff_attributes(
                f"objects[{key}].attributes",
                left_obj.attributes,
                right_obj.attributes,
            )
        )
        differences.extend(
            _diff_entry_sets(
                f"objects[{key}].references",
                _reference_entries(left_obj),
                _reference_entries(right_obj),
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
    differences.extend(_diff_entry_sets("tags", left.tags, right.tags))
    differences.extend(_diff_attributes("attributes", left.attributes, right.attributes))
    differences.extend(_diff_objects(left.objects, right.objects))
    differences.extend(_diff_entry_sets("galaxies", _galaxy_entries(left), _galaxy_entries(right)))
    differences.extend(
        _diff_entry_sets("sightings", _sighting_entries(left), _sighting_entries(right))
    )
    differences.extend(
        _diff_entry_sets("proposals", _proposal_entries(left), _proposal_entries(right))
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
