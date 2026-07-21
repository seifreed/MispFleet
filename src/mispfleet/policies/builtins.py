"""Configuration-driven policy implementation."""

from __future__ import annotations

from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import Transformation
from mispfleet.policies.base import (
    PolicyContext,
    PolicyResult,
    PolicySpec,
    PolicyViolation,
    PolicyWarning,
)

DISTRIBUTION_LEVELS = {
    "organisation": 0,
    "community": 1,
    "connected-communities": 2,
    "all-communities": 3,
}


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
        return PolicyResult(
            accepted=True,
            transformed_event=transformed,
            transformations=transformations,
            warnings=warnings,
        )
