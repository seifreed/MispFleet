"""Configuration-driven policy implementation."""

from __future__ import annotations

import re
from collections.abc import Iterator

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


def _all_attributes(event: MISPEvent) -> Iterator[MISPAttribute]:
    """Yield event-level attributes followed by every object attribute."""
    yield from event.attributes
    for obj in event.objects:
        yield from obj.attributes


def _attachment_size(data: str) -> int:
    """Approximate decoded size of a base64 attachment without decoding it."""
    return (len(data) * 3) // 4


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
    for attribute in _all_attributes(event):
        if attribute.value != REDACTED and any(p.search(attribute.value) for p in patterns):
            attribute.value = REDACTED
            transformations.append(
                Transformation(
                    action="redact-value",
                    target=attribute.type,
                    detail="policy redact_values",
                )
            )


def _apply_attribute_rejections(
    spec: PolicySpec,
    event: MISPEvent,
    transformations: list[Transformation],
    warnings: list[PolicyWarning],
) -> None:
    if not spec.reject_attribute_types:
        return
    kept = [a for a in event.attributes if a.type not in spec.reject_attribute_types]
    rejected = len(event.attributes) - len(kept)
    if rejected:
        event.attributes = kept
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
        violations: list[PolicyViolation] = []

        rejecting_tags = sorted(spec.reject_if.tags & transformed.tags)
        for tag in rejecting_tags:
            violations.append(
                PolicyViolation(rule="reject_if.tags", message=f"event carries tag {tag!r}")
            )
        rejecting_types = sorted(
            spec.reject_if.attribute_types & {a.type for a in transformed.attributes}
        )
        for attribute_type in rejecting_types:
            violations.append(
                PolicyViolation(
                    rule="reject_if.attribute_types",
                    message=f"event contains attribute type {attribute_type!r}",
                )
            )
        missing_tags = sorted(spec.required_tags - transformed.tags)
        for tag in missing_tags:
            violations.append(
                PolicyViolation(rule="required_tags", message=f"missing required tag {tag!r}")
            )
        if spec.allowed_object_names:
            object_names = {obj.name for obj in transformed.objects}
            for name in sorted(object_names - spec.allowed_object_names):
                violations.append(
                    PolicyViolation(
                        rule="allowed_object_names",
                        message=f"event contains unsupported object {name!r}",
                    )
                )
        if violations:
            return PolicyResult(accepted=False, violations=violations, warnings=warnings)

        for tag in sorted(spec.remove_tags & transformed.tags):
            transformed.tags.discard(tag)
            transformations.append(
                Transformation(action="remove-tag", target=tag, detail="policy remove_tags")
            )
        for old_name, new_name in sorted(spec.rename_tags.items()):
            if old_name in transformed.tags:
                transformed.tags.discard(old_name)
                transformed.tags.add(new_name)
                transformations.append(
                    Transformation(action="rename-tag", target=old_name, detail=new_name)
                )
        for tag in sorted(spec.add_tags - transformed.tags):
            transformed.tags.add(tag)
            transformations.append(
                Transformation(action="add-tag", target=tag, detail="policy add_tags")
            )
        if spec.remove_attribute_types:
            kept = [
                attribute
                for attribute in transformed.attributes
                if attribute.type not in spec.remove_attribute_types
            ]
            removed_count = len(transformed.attributes) - len(kept)
            if removed_count:
                transformed.attributes = kept
                transformations.append(
                    Transformation(
                        action="remove-attributes",
                        target=",".join(sorted(spec.remove_attribute_types)),
                        detail=f"removed {removed_count} attribute(s)",
                    )
                )
        if spec.remove_comments:
            for attribute in transformed.attributes:
                if attribute.comment:
                    attribute.comment = ""
                    transformations.append(
                        Transformation(
                            action="remove-comment",
                            target=f"{attribute.type}|{attribute.value}",
                            detail="policy remove_comments",
                        )
                    )
        if spec.set_published is not None and transformed.published != spec.set_published:
            transformed.published = spec.set_published
            transformations.append(
                Transformation(
                    action="set-published",
                    target="published",
                    detail=str(spec.set_published),
                )
            )
        if spec.maximum_distribution is not None:
            maximum = DISTRIBUTION_LEVELS[spec.maximum_distribution]
            current = int(transformed.distribution) if transformed.distribution else None
            if current is not None and current > maximum:
                transformed.distribution = str(maximum)
                transformations.append(
                    Transformation(
                        action="restrict-distribution",
                        target="distribution",
                        detail=f"{current} -> {maximum}",
                    )
                )
            elif current is None:
                warnings.append(
                    PolicyWarning(message="event has no distribution; maximum not enforced")
                )
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
