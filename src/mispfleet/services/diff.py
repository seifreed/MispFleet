"""Deterministic event comparison across two servers."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from typing import Any

from mispfleet.models.attribute import OBJECT_METADATA_FIELDS, MISPAttribute, MISPObject
from mispfleet.models.diff import Difference, DiffOperation, DiffSummary, EventDiff
from mispfleet.models.event import (
    MISPEvent,
    Proposal,
    Sighting,
    canonicalize_attribute,
    composite_key,
    fold_tags,
)
from mispfleet.services.similarity import event_similarity

_METADATA_FIELDS = (
    "uuid",
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

# Everything canonical_fingerprint hashes must be visible here: sync decides
# "in sync" by that fingerprint, so a field it counts but the diff ignores made
# `event diff` print "equivalent" for a pair `sync plan` re-proposed forever.
_ATTRIBUTE_FIELDS = (
    "uuid",
    "category",
    "to_ids",
    "comment",
    "deleted",
    "distribution",
    "sharing_group_id",
    "object_relation",
    "first_seen",
    "last_seen",
    "disable_correlation",
)

# The diff compares an object's identity (``name``) on top of the scalar
# metadata the merge adopts.
_OBJECT_FIELDS = ("name", *OBJECT_METADATA_FIELDS)


def _attribute_key(attribute: MISPAttribute) -> str:
    return composite_key(attribute.type, attribute.value)


def _index_attributes(attributes: list[MISPAttribute]) -> dict[str, list[MISPAttribute]]:
    """Group attributes by key, keeping duplicates so counts stay comparable.

    MISP allows several attributes with the same type and value; indexing them
    into a plain dict would silently hide every copy but the last.
    """
    index: dict[str, list[MISPAttribute]] = {}
    for attribute in attributes:
        index.setdefault(_attribute_key(attribute), []).append(attribute)
    return index


def attribute_sort_key(attribute: MISPAttribute) -> str:
    """Total order over an attribute, canonicalized as the fingerprint is.

    A partial key left two attachments of one ``type|value`` tied on their
    payloads, and including the volatile timestamp would make two servers sort
    the same attributes differently — either way the stable sort hands the
    pairing back to storage order.
    """
    payload = attribute.model_dump(mode="json")
    canonicalize_attribute(payload)
    return _canonical_json(payload)


def _object_key(obj: MISPObject) -> str:
    return identity(obj.uuid) or obj.name


def _index_objects(objects: list[MISPObject]) -> dict[str, list[MISPObject]]:
    """Group objects by key, keeping duplicates so counts stay comparable.

    Uuid-less objects fall back to their name, and two objects of the same
    template per event is normal: a plain dict hid every copy but the last.
    """
    index: dict[str, list[MISPObject]] = {}
    for obj in objects:
        index.setdefault(_object_key(obj), []).append(obj)
    return index


def _galaxy_entries(event: MISPEvent) -> list[str]:
    """Galaxy and cluster entries, keeping ownership and cardinality.

    Flattening every galaxy into one event-wide set lost which galaxy owned a
    cluster and how many galaxies there were, so redistributing clusters
    between two same-name galaxies, or listing one twice, diffed as equivalent
    while the fingerprint — which hashes them as a list — disagreed.
    """
    entries: list[str] = []
    for galaxy in event.galaxies:
        owner = (galaxy.name, identity(galaxy.uuid))
        # The cluster set belongs to the entry, not to the identity: two
        # entries sharing one identity could otherwise swap clusters unseen.
        # Composed through composite_key rather than "=" and "/" separators, which the
        # data contains: a uuid of "u/x" and a cluster of "x/a" produced the
        # same entry, so the diff called two different galaxy sets equivalent
        # while the fingerprint disagreed.
        entries.append(composite_key(*owner, "set", *sorted(galaxy.clusters)))
        entries.extend(
            composite_key(*owner, "cluster", cluster) for cluster in sorted(galaxy.clusters)
        )
    return entries


def sighting_key(item: Sighting) -> tuple[str, ...]:
    """The fields that identify a sighting, shared by the merge and the diff.

    identity(), not "or": an absent value stays distinct from an empty one, so
    the merge and the diff agree on what counts as the same sighting. When they
    did not, the merge dropped an entry the diff reported as a difference
    immediately after a successful merge.
    """
    return (
        identity(item.uuid),
        identity(item.attribute_uuid),
        item.type,
        identity(item.date_sighting),
        identity(item.organisation),
    )


def proposal_key(item: Proposal) -> tuple[str, ...]:
    """The fields that identify a proposal, shared by the merge and the diff."""
    return (
        identity(item.uuid),
        item.type,
        item.value,
        identity(item.category),
        str(item.to_ids),
    )


def _sighting_entries(event: MISPEvent) -> list[str]:
    """Sightings as a multiset over every field they carry.

    A set over three of the five fields hid a changed organisation or uuid,
    and collapsed two identical sightings into one.
    """
    return [composite_key(*sighting_key(item)) for item in event.sightings]


def _proposal_entries(event: MISPEvent) -> list[str]:
    """Proposals as a multiset over every field they carry."""
    return [composite_key(*proposal_key(item)) for item in event.proposals]


def _reference_entries(obj: MISPObject) -> list[str]:
    """Reference entries as a multiset: the fingerprint keeps duplicates."""
    return [
        composite_key(
            identity(ref.uuid),
            identity(ref.object_uuid),
            ref.referenced_uuid,
            ref.relationship_type,
        )
        for ref in obj.references
    ]


def _diff_entry_sets(
    path_prefix: str, left: Iterable[str], right: Iterable[str]
) -> list[Difference]:
    """Compare entries as multisets so a repeated entry is a real difference."""
    stored, offered = Counter(left), Counter(right)
    differences: list[Difference] = []
    for entry in sorted((offered - stored).elements()):
        differences.append(Difference(operation=DiffOperation.ADD, path=f"{path_prefix}[{entry}]"))
    for entry in sorted((stored - offered).elements()):
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
    left_by_key = _index_attributes(left)
    right_by_key = _index_attributes(right)
    for key in sorted(left_by_key.keys() | right_by_key.keys()):
        path = f"{path_prefix}[{key}]"
        left_items = sorted(left_by_key.get(key, []), key=attribute_sort_key)
        right_items = sorted(right_by_key.get(key, []), key=attribute_sort_key)
        if left_items and right_items and len(left_items) != len(right_items):
            differences.append(
                Difference(
                    operation=DiffOperation.CONFLICT,
                    path=f"{path}.count",
                    left=len(left_items),
                    right=len(right_items),
                )
            )
        if not left_items:
            differences.append(Difference(operation=DiffOperation.ADD, path=path))
            continue
        if not right_items:
            differences.append(Difference(operation=DiffOperation.REMOVE, path=path))
            continue
        # MISP allows several attributes under one type|value: comparing only
        # the first copy reported two diverging events as equivalent.
        paired = list(zip(left_items, right_items, strict=False))
        for position, (left_item, right_item) in enumerate(paired):
            item_path = path if len(paired) == 1 else f"{path}#{position}"
            differences.extend(_diff_attribute_pair(item_path, left_item, right_item))
    return differences


def _diff_attribute_pair(
    path: str, left_item: MISPAttribute, right_item: MISPAttribute
) -> list[Difference]:
    """Field-by-field comparison of two attributes sharing one key."""
    differences: list[Difference] = []
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
    left_tags, right_tags = fold_tags(left_item.tags), fold_tags(right_item.tags)
    if left_tags != right_tags:
        differences.append(
            Difference(
                operation=DiffOperation.CONFLICT,
                path=f"{path}.tags",
                left=left_tags,
                right=right_tags,
            )
        )
    if left_item.data != right_item.data:
        # Reported by size: an inline base64 attachment would swamp the diff.
        differences.append(
            Difference(
                operation=DiffOperation.CONFLICT,
                path=f"{path}.data",
                left=len(left_item.data or ""),
                right=len(right_item.data or ""),
            )
        )
    return differences


def object_sort_key(obj: MISPObject) -> str:
    """Total order over an object's whole content.

    Both the diff and the merge pair same-key duplicates in this order, so it
    has to be total: keying on ``(type, value)`` alone left two objects whose
    attributes differ only in ``to_ids`` or a comment tied, and a stable sort
    then handed the decision back to each server's storage order.
    """
    canonical = obj.model_dump(mode="json")
    for attribute in canonical["attributes"]:
        # The volatile fields the fingerprint strips must not reach the sort
        # key either: they differ per server, so leaving them in made the two
        # sides order the same objects differently and pair them crosswise.
        canonicalize_attribute(attribute)
    canonical["attributes"].sort(key=_canonical_json)
    canonical["references"].sort(key=_canonical_json)
    return _canonical_json(canonical)


def _canonical_json(item: Any) -> str:
    return json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)


def identity(value: str | None) -> str:
    """Keep an absent value distinct from an empty one, as the fingerprint does."""
    return "" if value is None else (value or "''")


def _diff_objects(left: list[MISPObject], right: list[MISPObject]) -> list[Difference]:
    differences: list[Difference] = []
    left_objects = _index_objects(left)
    right_objects = _index_objects(right)
    for key in sorted(left_objects.keys() | right_objects.keys()):
        left_group = left_objects.get(key, [])
        right_group = right_objects.get(key, [])
        if left_group and right_group and len(left_group) != len(right_group):
            differences.append(
                Difference(
                    operation=DiffOperation.CONFLICT,
                    path=f"objects[{key}].count",
                    left=len(left_group),
                    right=len(right_group),
                )
            )
        if not left_group:
            differences.append(Difference(operation=DiffOperation.ADD, path=f"objects[{key}]"))
            continue
        if not right_group:
            differences.append(Difference(operation=DiffOperation.REMOVE, path=f"objects[{key}]"))
            continue
        # Sorted before pairing, like duplicate attributes: comparing the two
        # groups in stored order reported the same content as different when
        # the servers happened to hold it in a different sequence, and hid a
        # real difference in any copy past the first.
        paired = list(
            zip(
                sorted(left_group, key=object_sort_key),
                sorted(right_group, key=object_sort_key),
                strict=False,
            )
        )
        for position, (left_obj, right_obj) in enumerate(paired):
            path = f"objects[{key}]" if len(paired) == 1 else f"objects[{key}]#{position}"
            differences.extend(_diff_object_pair(path, left_obj, right_obj))
    return differences


def _diff_object_pair(path: str, left_obj: MISPObject, right_obj: MISPObject) -> list[Difference]:
    """Field-by-field comparison of two objects sharing one key."""
    differences: list[Difference] = []
    for field in _OBJECT_FIELDS:
        left_value = getattr(left_obj, field)
        right_value = getattr(right_obj, field)
        if left_value != right_value:
            differences.append(
                Difference(
                    operation=DiffOperation.CONFLICT,
                    path=f"{path}.{field}",
                    left=left_value,
                    right=right_value,
                )
            )
    differences.extend(
        _diff_attributes(
            f"{path}.attributes",
            left_obj.attributes,
            right_obj.attributes,
        )
    )
    differences.extend(
        _diff_entry_sets(
            f"{path}.references",
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
    differences.extend(_diff_entry_sets("tags", fold_tags(left.tags), fold_tags(right.tags)))
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
        similarity=event_similarity(left, right).score,
        differences=differences,
        summary=summary,
    )
