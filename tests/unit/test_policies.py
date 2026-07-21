"""Unit tests for the policy engine and configuration-driven policies."""

from __future__ import annotations

import pytest

from mispfleet.exceptions import PolicyConfigurationError
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent
from mispfleet.policies.base import PolicyContext, PolicySpec, RejectRules
from mispfleet.policies.engine import PolicyEngine
from tests.support import contains, eq, not_contains, ok

CONTEXT = PolicyContext(policy_name="p", source_server="research", destination_server="production")


def event(**overrides: object) -> MISPEvent:
    fields: dict[str, object] = {
        "uuid": "9c5c1c2e-0000-4000-8000-00000000000e",
        "info": "Campaign",
        "distribution": "3",
        "published": True,
        "tags": {"internal-only", "tlp:green"},
        "attributes": [
            MISPAttribute(type="domain", value="evil.example", comment="internal note"),
            MISPAttribute(type="passport-number", value="X123"),
        ],
    }
    fields.update(overrides)
    return MISPEvent.model_validate(fields)


def engine(**specs: PolicySpec) -> PolicyEngine:
    return PolicyEngine(dict(specs))


async def test_policy_transforms_tags_attributes_and_distribution() -> None:
    spec = PolicySpec(
        remove_tags={"internal-only"},
        add_tags={"imported-by:mispfleet"},
        rename_tags={"tlp:green": "tlp:clear"},
        remove_attribute_types={"passport-number"},
        remove_comments=True,
        set_published=False,
        maximum_distribution="community",
    )
    result = await engine(p=spec).apply("p", CONTEXT, event())
    ok(result.accepted)
    transformed = result.transformed_event
    ok(transformed is not None)
    if transformed is None:
        return
    eq(transformed.tags, {"imported-by:mispfleet", "tlp:clear"})
    eq([a.type for a in transformed.attributes], ["domain"])
    eq(transformed.attributes[0].comment, "")
    eq(transformed.published, False)
    eq(transformed.distribution, "1")
    actions = {t.action for t in result.transformations}
    eq(
        actions,
        {
            "remove-tag",
            "add-tag",
            "rename-tag",
            "remove-attributes",
            "remove-comment",
            "set-published",
            "restrict-distribution",
        },
    )


async def test_policy_evaluation_never_mutates_the_input_event() -> None:
    original = event()
    spec = PolicySpec(remove_tags={"internal-only"}, set_published=False)
    await engine(p=spec).apply("p", CONTEXT, original)
    contains(original.tags, "internal-only")
    ok(original.published)


async def test_policy_rejects_by_tag_type_and_missing_required_tag() -> None:
    spec = PolicySpec(
        reject_if=RejectRules(tags={"tlp:green"}, attribute_types={"passport-number"}),
        required_tags={"approved"},
    )
    result = await engine(p=spec).apply("p", CONTEXT, event())
    ok(not result.accepted)
    eq(result.transformed_event, None)
    rules = [violation.rule for violation in result.violations]
    contains(rules, "reject_if.tags")
    contains(rules, "reject_if.attribute_types")
    contains(rules, "required_tags")


async def test_policy_warns_when_distribution_is_absent() -> None:
    spec = PolicySpec(maximum_distribution="community")
    result = await engine(p=spec).apply("p", CONTEXT, event(distribution=None))
    ok(result.accepted)
    contains(result.warnings[0].message, "no distribution")
    low = await engine(p=spec).apply("p", CONTEXT, event(distribution="0"))
    if low.transformed_event is not None:
        eq(low.transformed_event.distribution, "0")


async def test_engine_accepts_untouched_copy_without_policy() -> None:
    original = event()
    result = await engine().apply(None, CONTEXT, original)
    ok(result.accepted)
    ok(result.transformed_event is not None)
    ok(result.transformed_event is not original)
    eq(result.transformations, [])


def test_engine_rejects_unknown_policy_and_bad_distribution() -> None:
    with pytest.raises(PolicyConfigurationError) as missing:
        engine().get("ghost")
    contains(str(missing.value), "ghost")
    bad = PolicySpec.model_construct(maximum_distribution="everywhere")
    with pytest.raises(PolicyConfigurationError) as invalid:
        engine(bad=bad).get("bad")
    contains(str(invalid.value), "everywhere")
    eq(engine(a=PolicySpec(), b=PolicySpec()).names(), ["a", "b"])


async def test_deterministic_policy_results_are_stable() -> None:
    spec = PolicySpec(add_tags={"x", "y"}, remove_tags={"internal-only"})
    first = await engine(p=spec).apply("p", CONTEXT, event())
    second = await engine(p=spec).apply("p", CONTEXT, event())
    first_event = first.transformed_event
    second_event = second.transformed_event
    ok(first_event is not None and second_event is not None)
    if first_event is None or second_event is None:
        return
    eq(first_event.canonical_fingerprint(), second_event.canonical_fingerprint())
    eq(
        [t.model_dump() for t in first.transformations],
        [t.model_dump() for t in second.transformations],
    )
    not_contains([t.action for t in first.transformations], "restrict-distribution")


async def test_policy_noop_branches_leave_event_untouched() -> None:
    spec = PolicySpec(
        rename_tags={"absent-tag": "renamed"},
        remove_attribute_types={"never-present-type"},
    )
    result = await engine(p=spec).apply("p", CONTEXT, event())
    ok(result.accepted)
    eq(result.transformations, [])
