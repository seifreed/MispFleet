"""Configuration-driven policy implementation."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import Transformation
from mispfleet.policies.base import (
    PolicyContext,
    PolicyResult,
    PolicySpec,
    PolicyViolation,
    PolicyWarning,
)
from mispfleet.redaction import REDACTED

DISTRIBUTION_LEVELS = {
    "organisation": 0,
    "community": 1,
    "connected-communities": 2,
    "all-communities": 3,
}

# Only levels 0-3 form MISP's widening scale. Level 4 shares with a named
# sharing group and level 5 inherits the event's level: neither sits on that
# scale, so comparing them numerically would widen the audience, not restrict it.
DISTRIBUTION_SHARING_GROUP = 4
DISTRIBUTION_INHERIT_EVENT = 5


def _all_attributes(event: MISPEvent) -> Iterator[MISPAttribute]:
    """Yield event-level attributes followed by every object attribute."""
    yield from event.attributes
    for obj in event.objects:
        yield from obj.attributes


def _attachment_size(data: str) -> int:
    """Approximate decoded size of a base64 attachment without decoding it."""
    return (len(data) * 3) // 4


def _distribution_level(value: str | None) -> int | None:
    """Numeric distribution level, or ``None`` when absent or non-numeric."""
    if value is None or not value.strip().isdigit():
        return None
    return int(value)


def _clamp_distribution(
    holder: MISPEvent | MISPAttribute | MISPObject,
    label: str,
    maximum: int,
    transformations: list[Transformation],
    warnings: list[PolicyWarning],
) -> None:
    """Lower one holder's distribution to ``maximum`` when it exceeds it.

    Levels outside the 0-3 scale are never rewritten: level 5 already inherits
    the event's clamped level, and any other level is narrower than or
    incomparable to the scale, so rewriting it would broaden the audience.
    """
    current = _distribution_level(holder.distribution)
    if current is None or current == DISTRIBUTION_INHERIT_EVENT:
        return
    if current > DISTRIBUTION_INHERIT_EVENT or current == DISTRIBUTION_SHARING_GROUP:
        warnings.append(
            PolicyWarning(
                message=(
                    f"{label} uses distribution {current} which is not on the "
                    "0-3 scale; maximum_distribution left it untouched"
                )
            )
        )
        return
    if current > maximum:
        holder.distribution = str(maximum)
        transformations.append(
            Transformation(
                action="restrict-distribution",
                target=label,
                detail=f"{current} -> {maximum}",
            )
        )


def folded_tags(names: Iterable[str]) -> set[str]:
    """Case-insensitive view of a tag collection.

    MISP stores tag names under a case-insensitive collation and captures them
    case-insensitively, so ``TLP:RED`` and ``tlp:red`` are the same tag there.
    Matching them exactly would let a policy gate pass a marking it must catch.
    """
    return {name.casefold() for name in names}


def _govern_tags(
    spec: PolicySpec, tags: set[str], target_prefix: str, transformations: list[Transformation]
) -> None:
    """Apply ``remove_tags`` and ``rename_tags`` to one tag holder, in place."""
    removed = folded_tags(spec.remove_tags)
    for tag in sorted(tag for tag in tags if tag.casefold() in removed):
        tags.discard(tag)
        transformations.append(
            Transformation(
                action="remove-tag", target=f"{target_prefix}{tag}", detail="policy remove_tags"
            )
        )
    # Resolved against a snapshot: renaming in place let a tag produced by one
    # rule be matched again by a later one, so {amber: green, green: clear}
    # turned tlp:amber into tlp:clear — two levels wider than the map says.
    # The holder keeps its own spelling, so the snapshot maps the tag as stored.
    renames: dict[str, str] = {}
    for old, new in sorted(spec.rename_tags.items()):
        for present in sorted(tags):
            if present.casefold() == old.casefold():
                renames.setdefault(present, new)
    for old_name in renames:
        tags.discard(old_name)
    for old_name, new_name in sorted(renames.items()):
        if new_name.casefold() in removed:
            # Renaming onto a removed tag would hand the partner back exactly
            # the marking remove_tags is there to strip.
            transformations.append(
                Transformation(
                    action="remove-tag",
                    target=f"{target_prefix}{old_name}",
                    detail=f"renamed to {new_name}, which remove_tags strips",
                )
            )
            continue
        if new_name.casefold() in folded_tags(tags):
            # The holder already carries this tag in another spelling; adding
            # it again would put two rows MISP considers one tag on the event.
            # The old tag still went away, so the plan has to say so: skipping
            # silently changed the marking with nothing to review.
            transformations.append(
                Transformation(
                    action="remove-tag",
                    target=f"{target_prefix}{old_name}",
                    detail=f"renamed to {new_name}, already present",
                )
            )
            continue
        tags.add(new_name)
        transformations.append(
            Transformation(
                action="rename-tag", target=f"{target_prefix}{old_name}", detail=new_name
            )
        )


def _carried_tags(event: MISPEvent) -> set[str]:
    """Every tag the event shares, event-level and attribute-level alike."""
    return event.tags | {tag for attribute in _all_attributes(event) for tag in attribute.tags}


def _apply_organisation_map(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    mapped = spec.organisation_map.get(event.orgc or "")
    if mapped is not None and event.orgc != mapped:
        transformations.append(
            Transformation(action="map-organisation", target=str(event.orgc), detail=mapped)
        )
        event.orgc = mapped
        event.orgc_uuid = None


def _apply_sharing_group_map(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    holders: list[tuple[str, MISPEvent | MISPAttribute | MISPObject]] = [("event", event)]
    holders.extend((f"attribute:{a.type}", a) for a in _all_attributes(event))
    holders.extend((f"object:{obj.name}", obj) for obj in event.objects)
    for label, holder in holders:
        mapped = spec.sharing_group_map.get(holder.sharing_group_id or "")
        if mapped is not None and holder.sharing_group_id != mapped:
            holder.sharing_group_id = mapped
            transformations.append(
                Transformation(action="map-sharing-group", target=label, detail=mapped)
            )


def _apply_set_to_ids(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    if spec.set_to_ids is None:
        return
    changed = [a for a in _all_attributes(event) if a.to_ids != spec.set_to_ids]
    for attribute in changed:
        attribute.to_ids = spec.set_to_ids
    if changed:
        transformations.append(
            Transformation(
                action="set-to-ids",
                target=f"{len(changed)} attribute(s)",
                detail=str(spec.set_to_ids),
            )
        )


def _apply_redactions(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    patterns = [re.compile(pattern) for pattern in spec.redact_values]
    if not patterns:
        return

    def matches(text: str) -> bool:
        return text != REDACTED and bool(text) and any(p.search(text) for p in patterns)

    for attribute in _all_attributes(event):
        hit = False
        if matches(attribute.value):
            attribute.value = REDACTED
            hit = True
            transformations.append(
                Transformation(
                    action="redact-value",
                    target=attribute.type,
                    detail="policy redact_values",
                )
            )
        if matches(attribute.comment):
            attribute.comment = REDACTED
            hit = True
            transformations.append(
                Transformation(
                    action="redact-comment",
                    target=attribute.type,
                    detail="policy redact_values",
                )
            )
        if hit:
            # For attachment types the value is only the filename: leaving the
            # base64 body behind ships the very content being redacted, and it
            # is just as secret when the pattern matched only the comment.
            attribute.data = None
    for obj in event.objects:
        if matches(obj.comment):
            obj.comment = REDACTED
            transformations.append(
                Transformation(
                    action="redact-comment",
                    target=f"object:{obj.name}",
                    detail="policy redact_values",
                )
            )
    if matches(event.info):
        event.info = REDACTED
        transformations.append(
            Transformation(action="redact-info", target="info", detail="policy redact_values")
        )


def _drop_attribute_types(event: MISPEvent, types: set[str]) -> int:
    """Remove every attribute of the given types, objects included."""
    kept = [attribute for attribute in event.attributes if attribute.type not in types]
    removed = len(event.attributes) - len(kept)
    event.attributes = kept
    for obj in event.objects:
        kept_in_object = [attribute for attribute in obj.attributes if attribute.type not in types]
        removed += len(obj.attributes) - len(kept_in_object)
        obj.attributes = kept_in_object
    return removed


def _apply_attribute_rejections(
    spec: PolicySpec,
    event: MISPEvent,
    transformations: list[Transformation],
    warnings: list[PolicyWarning],
) -> None:
    if not spec.reject_attribute_types:
        return
    rejected = _drop_attribute_types(event, spec.reject_attribute_types)
    if rejected:
        transformations.append(
            Transformation(
                action="reject-attributes",
                target=",".join(sorted(spec.reject_attribute_types)),
                detail=f"rejected {rejected} attribute(s)",
            )
        )
        warnings.append(PolicyWarning(message=f"{rejected} attribute(s) rejected by type"))


def _apply_attachment_limits(
    spec: PolicySpec,
    event: MISPEvent,
    transformations: list[Transformation],
    warnings: list[PolicyWarning],
) -> None:
    if spec.max_attachment_bytes is None:
        return
    for attribute in _all_attributes(event):
        if attribute.data is None:
            continue
        size = _attachment_size(attribute.data)
        if size > spec.max_attachment_bytes:
            attribute.data = None
            transformations.append(
                Transformation(
                    action="limit-attachment",
                    target=attribute.type,
                    detail=f"{size} bytes exceeds {spec.max_attachment_bytes}",
                )
            )
            warnings.append(
                PolicyWarning(
                    message=f"attachment on {attribute.type} attribute exceeded size limit"
                )
            )


def _apply_add_tags(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    """Add each ``add_tags`` entry the event does not already carry."""
    # Adding a tag the holder already carries in another spelling would put
    # two rows MISP considers the same tag on one event.
    present = folded_tags(event.tags)
    for tag in sorted(spec.add_tags):
        if tag.casefold() in present:
            continue
        event.tags.add(tag)
        present.add(tag.casefold())
        transformations.append(
            Transformation(action="add-tag", target=tag, detail="policy add_tags")
        )


def _collect_violations(
    spec: PolicySpec, event: MISPEvent, incoming_tags: set[str]
) -> list[PolicyViolation]:
    """Every reason the spec rejects this event, gathered before any transform."""
    violations: list[PolicyViolation] = []
    # reject_if judges what arrived and what leaves: a rename must never
    # launder a rejected marking past the gate.
    carried = folded_tags(incoming_tags | _carried_tags(event))
    for tag in sorted(tag for tag in spec.reject_if.tags if tag.casefold() in carried):
        violations.append(
            PolicyViolation(rule="reject_if.tags", message=f"event carries tag {tag!r}")
        )
    rejecting_types = sorted(
        spec.reject_if.attribute_types & {a.type for a in _all_attributes(event)}
    )
    for attribute_type in rejecting_types:
        violations.append(
            PolicyViolation(
                rule="reject_if.attribute_types",
                message=f"event contains attribute type {attribute_type!r}",
            )
        )
    final_tags = folded_tags(event.tags)
    for tag in sorted(tag for tag in spec.required_tags if tag.casefold() not in final_tags):
        violations.append(
            PolicyViolation(rule="required_tags", message=f"missing required tag {tag!r}")
        )
    if spec.allowed_object_names:
        object_names = {obj.name for obj in event.objects}
        for name in sorted(object_names - spec.allowed_object_names):
            violations.append(
                PolicyViolation(
                    rule="allowed_object_names",
                    message=f"event contains unsupported object {name!r}",
                )
            )
    return violations


def _apply_remove_attribute_types(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    """Drop attributes whose type the spec forbids."""
    if not spec.remove_attribute_types:
        return
    removed_count = _drop_attribute_types(event, spec.remove_attribute_types)
    if removed_count:
        transformations.append(
            Transformation(
                action="remove-attributes",
                target=",".join(sorted(spec.remove_attribute_types)),
                detail=f"removed {removed_count} attribute(s)",
            )
        )


def _apply_remove_comments(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    """Blank the comment on every attribute and object."""
    if not spec.remove_comments:
        return
    for attribute in _all_attributes(event):
        if attribute.comment:
            attribute.comment = ""
            transformations.append(
                Transformation(
                    action="remove-comment",
                    target=f"{attribute.type}|{attribute.value}",
                    detail="policy remove_comments",
                )
            )
    for obj in event.objects:
        if obj.comment:
            obj.comment = ""
            transformations.append(
                Transformation(
                    action="remove-comment",
                    target=f"object:{obj.name}",
                    detail="policy remove_comments",
                )
            )


def _apply_set_published(
    spec: PolicySpec, event: MISPEvent, transformations: list[Transformation]
) -> None:
    """Force the published flag when the spec pins it."""
    if spec.set_published is not None and event.published != spec.set_published:
        event.published = spec.set_published
        transformations.append(
            Transformation(
                action="set-published",
                target="published",
                detail=str(spec.set_published),
            )
        )


def _apply_distribution_clamp(
    spec: PolicySpec,
    event: MISPEvent,
    transformations: list[Transformation],
    warnings: list[PolicyWarning],
) -> None:
    """Clamp the event and its attributes and objects to the maximum distribution."""
    if spec.maximum_distribution is None:
        return
    maximum = DISTRIBUTION_LEVELS[spec.maximum_distribution]
    if _distribution_level(event.distribution) is None:
        warnings.append(PolicyWarning(message="event has no distribution; maximum not enforced"))
    _clamp_distribution(event, "distribution", maximum, transformations, warnings)
    # Attributes and objects carry their own level: an attribute left at
    # a wider distribution would out-share the clamped event.
    for attribute in _all_attributes(event):
        _clamp_distribution(
            attribute, f"attribute:{attribute.type}", maximum, transformations, warnings
        )
    for obj in event.objects:
        _clamp_distribution(obj, f"object:{obj.name}", maximum, transformations, warnings)


class ConfigPolicy:
    """Deterministic policy built from a declarative :class:`PolicySpec`."""

    def __init__(self, name: str, spec: PolicySpec) -> None:
        self.name = name
        self.spec = spec

    async def evaluate(self, context: PolicyContext, event: MISPEvent) -> PolicyResult:
        """Apply the spec to a deep copy of the event; the input is untouched."""
        spec = self.spec
        transformed = event.model_copy(deep=True)
        transformations: list[Transformation] = []
        warnings: list[PolicyWarning] = []

        # Tag governance runs before the gates: required_tags used to pass on a
        # tag a later rename removed, so an accepted event could ship without
        # the marking the policy declares mandatory.
        incoming_tags = _carried_tags(transformed)
        _govern_tags(spec, transformed.tags, "", transformations)
        # An attribute keeps its own tags: leaving them alone would ship the very
        # markings the policy strips from the event.
        for attribute in _all_attributes(transformed):
            _govern_tags(spec, attribute.tags, f"attribute:{attribute.type}|", transformations)
        _apply_add_tags(spec, transformed, transformations)

        violations = _collect_violations(spec, transformed, incoming_tags)
        if violations:
            return PolicyResult(accepted=False, violations=violations, warnings=warnings)

        _apply_remove_attribute_types(spec, transformed, transformations)
        _apply_remove_comments(spec, transformed, transformations)
        _apply_set_published(spec, transformed, transformations)
        _apply_distribution_clamp(spec, transformed, transformations, warnings)
        _apply_organisation_map(spec, transformed, transformations)
        _apply_sharing_group_map(spec, transformed, transformations)
        _apply_set_to_ids(spec, transformed, transformations)
        _apply_redactions(spec, transformed, transformations)
        _apply_attribute_rejections(spec, transformed, transformations, warnings)
        _apply_attachment_limits(spec, transformed, transformations, warnings)
        return PolicyResult(
            accepted=True,
            transformed_event=transformed,
            transformations=transformations,
            warnings=warnings,
        )
