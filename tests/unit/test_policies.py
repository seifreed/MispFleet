"""Unit tests for the policy engine and configuration-driven policies."""

from __future__ import annotations

import pytest

from mispfleet.exceptions import PolicyConfigurationError
from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent
from mispfleet.policies.base import PolicyContext, PolicySpec, RejectRules
from mispfleet.policies.engine import PolicyEngine
from mispfleet.redaction import REDACTED
from tests.support import contains, eq, not_contains, not_none, ok

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


async def test_policy_maps_redacts_rejects_and_limits() -> None:
    spec = PolicySpec(
        organisation_map={"CIRCL": "Partner"},
        sharing_group_map={"1": "9"},
        set_to_ids=True,
        redact_values=[r"^198\.51\."],
        reject_attribute_types={"passport-number"},
        max_attachment_bytes=4,
    )
    base = event(
        orgc="CIRCL",
        orgc_uuid="org-uuid",
        sharing_group_id="1",
        attributes=[
            MISPAttribute(type="domain", value="evil.example"),
            MISPAttribute(type="ip-src", value="198.51.100.7"),
            MISPAttribute(type="passport-number", value="X1"),
            MISPAttribute(
                type="attachment", value="a.bin", data="QUJDREVGR0g=", sharing_group_id="1"
            ),
        ],
        objects=[
            MISPObject(
                name="file",
                sharing_group_id="1",
                attributes=[MISPAttribute(type="malware-sample", value="s", data="QUJD")],
            )
        ],
    )
    result = await engine(p=spec).apply("p", CONTEXT, base)
    ok(result.accepted)
    transformed = result.transformed_event
    ok(transformed is not None)
    if transformed is None:
        return
    eq(transformed.orgc, "Partner")
    eq(transformed.orgc_uuid, None)
    eq(transformed.sharing_group_id, "9")
    eq(transformed.objects[0].sharing_group_id, "9")
    by_type = {a.type: a for a in transformed.attributes}
    not_contains(by_type, "passport-number")
    eq(by_type["attachment"].sharing_group_id, "9")
    eq(by_type["ip-src"].value, REDACTED)
    ok(all(a.to_ids for a in transformed.attributes))
    eq(by_type["attachment"].data, None)
    eq(transformed.objects[0].attributes[0].data, "QUJD")
    actions = {t.action for t in result.transformations}
    eq(
        actions,
        {
            "map-organisation",
            "map-sharing-group",
            "set-to-ids",
            "redact-value",
            "reject-attributes",
            "limit-attachment",
        },
    )
    messages = [w.message for w in result.warnings]
    ok(any("rejected by type" in m for m in messages))
    ok(any("size limit" in m for m in messages))


async def test_policy_new_operations_no_change_branches() -> None:
    spec = PolicySpec(
        organisation_map={"CIRCL": "CIRCL"},
        sharing_group_map={"1": "1"},
        set_to_ids=False,
        redact_values=[r".*"],
        reject_attribute_types={"never-present"},
        max_attachment_bytes=100,
    )
    base = event(
        orgc="CIRCL",
        sharing_group_id="1",
        # Empty info: the ".*" pattern matches any non-empty string, and the
        # event's own info is scanned too.
        info="",
        attributes=[
            MISPAttribute(type="domain", value=REDACTED),
            MISPAttribute(type="attachment", value=REDACTED, data="QUJD"),
        ],
        tags=set(),
    )
    result = await engine(p=spec).apply("p", CONTEXT, base)
    ok(result.accepted)
    eq(result.transformations, [])
    eq(result.warnings, [])


async def test_policy_rejects_unsupported_objects() -> None:
    spec = PolicySpec(allowed_object_names={"file"})
    base = event(objects=[MISPObject(name="file"), MISPObject(name="custom-widget")])
    result = await engine(p=spec).apply("p", CONTEXT, base)
    ok(not result.accepted)
    eq(result.violations[0].rule, "allowed_object_names")
    contains(result.violations[0].message, "custom-widget")
    allowed = await engine(p=spec).apply("p", CONTEXT, event(objects=[MISPObject(name="file")]))
    ok(allowed.accepted)


def test_engine_rejects_invalid_redact_pattern() -> None:
    bad = PolicySpec(redact_values=["["])
    with pytest.raises(PolicyConfigurationError) as invalid:
        engine(bad=bad).get("bad")
    contains(str(invalid.value), "redact_values")


def event_with_object() -> MISPEvent:
    """An event whose sensitive content lives inside a MISP object."""
    return event(
        attributes=[MISPAttribute(type="domain", value="evil.example")],
        objects=[
            MISPObject(
                name="credential",
                comment="internal object note",
                distribution="3",
                attributes=[
                    MISPAttribute(
                        type="passport-number",
                        value="X123",
                        comment="internal note",
                        distribution="3",
                    )
                ],
            )
        ],
    )


async def test_object_attributes_are_subject_to_type_rules() -> None:
    rejecting = PolicySpec(reject_if=RejectRules(attribute_types={"passport-number"}))
    result = await engine(p=rejecting).apply("p", CONTEXT, event_with_object())
    ok(not result.accepted)
    contains(result.violations[0].message, "passport-number")

    removing = PolicySpec(remove_attribute_types={"passport-number"})
    removed = await engine(p=removing).apply("p", CONTEXT, event_with_object())
    ok(removed.accepted)
    transformed = not_none(removed.transformed_event)
    eq(transformed.objects[0].attributes, [])

    dropping = PolicySpec(reject_attribute_types={"passport-number"})
    dropped = await engine(p=dropping).apply("p", CONTEXT, event_with_object())
    transformed = not_none(dropped.transformed_event)
    eq(transformed.objects[0].attributes, [])


async def test_remove_comments_reaches_objects_and_their_attributes() -> None:
    spec = PolicySpec(remove_comments=True)
    source = event_with_object()
    source.objects.append(MISPObject(name="file"))
    result = await engine(p=spec).apply("p", CONTEXT, source)
    transformed = not_none(result.transformed_event)
    obj = transformed.objects[0]
    eq(obj.comment, "")
    eq(obj.attributes[0].comment, "")
    eq(transformed.objects[1].comment, "")


async def test_maximum_distribution_clamps_attributes_and_objects() -> None:
    spec = PolicySpec(maximum_distribution="community")
    result = await engine(p=spec).apply("p", CONTEXT, event_with_object())
    transformed = not_none(result.transformed_event)
    eq(transformed.distribution, "1")
    eq(transformed.objects[0].distribution, "1")
    eq(transformed.objects[0].attributes[0].distribution, "1")


async def test_maximum_distribution_never_widens_a_sharing_group_level() -> None:
    """Distribution 4 shares with a named group, so it is not on the 0-3 scale.

    Clamping it numerically rewrote sharing-group-only data to the whole
    community: a broader audience than the policy asked for.
    """
    spec = PolicySpec(maximum_distribution="community")
    result = await engine(p=spec).apply("p", CONTEXT, event(distribution="4"))
    ok(result.accepted)
    transformed = not_none(result.transformed_event)
    eq(transformed.distribution, "4")
    contains(result.warnings[0].message, "not on the")


async def test_maximum_distribution_leaves_inherited_attribute_levels_alone() -> None:
    """Distribution 5 inherits the event's already-clamped level."""
    spec = PolicySpec(maximum_distribution="all-communities")
    source = event(
        distribution="0",
        attributes=[MISPAttribute(type="domain", value="evil.example", distribution="5")],
    )
    result = await engine(p=spec).apply("p", CONTEXT, source)
    ok(result.accepted)
    transformed = not_none(result.transformed_event)
    eq(transformed.distribution, "0")
    eq(transformed.attributes[0].distribution, "5")


async def test_maximum_distribution_warns_on_levels_off_the_scale() -> None:
    spec = PolicySpec(maximum_distribution="community")
    result = await engine(p=spec).apply("p", CONTEXT, event(distribution="9"))
    ok(result.accepted)
    transformed = not_none(result.transformed_event)
    eq(transformed.distribution, "9")
    contains(result.warnings[0].message, "not on the")


async def test_reject_if_tags_sees_attribute_level_markings() -> None:
    """An attribute can carry the very tag the policy refuses to share."""
    spec = PolicySpec(reject_if=RejectRules(tags={"tlp:red"}))
    source = event(
        tags={"tlp:green"},
        attributes=[MISPAttribute(type="domain", value="evil.example", tags={"tlp:red"})],
    )
    result = await engine(p=spec).apply("p", CONTEXT, source)
    ok(not result.accepted)
    contains(result.violations[0].message, "tlp:red")


async def test_remove_and_rename_tags_reach_attribute_tags() -> None:
    spec = PolicySpec(remove_tags={"internal-only"}, rename_tags={"old": "new"})
    source = event(
        tags={"tlp:green"},
        attributes=[
            MISPAttribute(
                type="domain", value="evil.example", tags={"internal-only", "old", "keep"}
            )
        ],
        objects=[
            MISPObject(
                name="file",
                attributes=[
                    MISPAttribute(type="sha256", value="a" * 64, tags={"internal-only"}),
                ],
            )
        ],
    )
    result = await engine(p=spec).apply("p", CONTEXT, source)
    ok(result.accepted)
    transformed = not_none(result.transformed_event)
    eq(transformed.attributes[0].tags, {"new", "keep"})
    eq(transformed.objects[0].attributes[0].tags, set())


async def test_maximum_distribution_ignores_non_numeric_levels() -> None:
    spec = PolicySpec(maximum_distribution="community")
    result = await engine(p=spec).apply("p", CONTEXT, event(distribution="inherit"))
    ok(result.accepted)
    transformed = not_none(result.transformed_event)
    eq(transformed.distribution, "inherit")
    contains(result.warnings[0].message, "no distribution")


async def test_rename_tags_substitutes_once_and_never_chains() -> None:
    """Renaming in place let one rule's output feed the next.

    {amber: green, green: clear} turned a tlp:amber event into tlp:clear —
    two levels wider than the map itself allows.
    """
    spec = PolicySpec(rename_tags={"tlp:amber": "tlp:green", "tlp:green": "tlp:clear"})
    source = event(
        tags={"tlp:amber"},
        attributes=[MISPAttribute(type="domain", value="evil.example", tags={"tlp:amber"})],
    )
    result = await engine(p=spec).apply("p", CONTEXT, source)
    transformed = not_none(result.transformed_event)
    eq(transformed.tags, {"tlp:green"})
    eq(transformed.attributes[0].tags, {"tlp:green"})


async def test_rename_tags_still_swaps_a_pair() -> None:
    spec = PolicySpec(rename_tags={"a": "b", "b": "a"})
    result = await engine(p=spec).apply("p", CONTEXT, event(tags={"a"}))
    eq(not_none(result.transformed_event).tags, {"b"})


async def test_a_rename_can_never_resurrect_a_removed_tag() -> None:
    """remove_tags wins over rename_tags.

    A normalize-case rule such as {"TLP:RED": "tlp:red"} used to hand the
    partner back the exact marking remove_tags exists to strip, because
    removals ran before renames and rename targets were never re-checked.
    """
    spec = PolicySpec(remove_tags={"tlp:red"}, rename_tags={"TLP:RED": "tlp:red"})
    result = await engine(p=spec).apply("p", CONTEXT, event(tags={"TLP:RED"}))
    ok(result.accepted)
    transformed = not_none(result.transformed_event)
    not_contains(transformed.tags, "tlp:red")
    not_contains(transformed.tags, "TLP:RED")


async def test_required_tags_are_judged_after_the_renames_run() -> None:
    """An accepted event must actually carry every tag the policy requires."""
    losing = PolicySpec(
        required_tags={"tlp:amber"},
        rename_tags={"tlp:amber": "tlp:amber+strict"},
    )
    rejected = await engine(p=losing).apply("p", CONTEXT, event(tags={"tlp:amber"}))
    ok(not rejected.accepted)

    # The mirror case: the rename produces the required tag, so it must pass.
    gaining = PolicySpec(
        required_tags={"tlp:clear"},
        rename_tags={"tlp:white": "tlp:clear"},
    )
    accepted = await engine(p=gaining).apply("p", CONTEXT, event(tags={"tlp:white"}))
    ok(accepted.accepted)
    contains(not_none(accepted.transformed_event).tags, "tlp:clear")


async def test_a_rename_cannot_launder_a_rejected_marking() -> None:
    """reject_if judges what arrived as well as what leaves."""
    spec = PolicySpec(
        reject_if=RejectRules(tags={"tlp:red"}),
        rename_tags={"tlp:red": "tlp:green"},
    )
    result = await engine(p=spec).apply("p", CONTEXT, event(tags={"tlp:red"}))
    ok(not result.accepted)

    # And a tag the policy itself introduces is judged too.
    introduced = PolicySpec(
        reject_if=RejectRules(tags={"tlp:red"}),
        rename_tags={"tlp:green": "tlp:red"},
    )
    ok(not (await engine(p=introduced).apply("p", CONTEXT, event(tags={"tlp:green"}))).accepted)


async def test_tag_gates_match_case_insensitively_like_misp() -> None:
    """MISP stores tag names case-insensitively, so the gates must too.

    Matching them exactly let ``reject_if`` fail *open*: an event tagged
    ``TLP:RED`` sailed past a policy configured to block ``tlp:red``.
    """
    blocking = PolicySpec(reject_if=RejectRules(tags={"tlp:red"}))
    for spelling in ("tlp:red", "TLP:RED", "TLP:Red"):
        ok(not (await engine(p=blocking).apply("p", CONTEXT, event(tags={spelling}))).accepted)

    stripping = PolicySpec(remove_tags={"tlp:red"})
    stripped = await engine(p=stripping).apply("p", CONTEXT, event(tags={"TLP:RED"}))
    ok(stripped.accepted)
    not_contains(not_none(stripped.transformed_event).tags, "TLP:RED")

    renaming = PolicySpec(rename_tags={"tlp:red": "tlp:amber"})
    renamed = await engine(p=renaming).apply("p", CONTEXT, event(tags={"TLP:RED"}))
    eq(not_none(renamed.transformed_event).tags, {"tlp:amber"})

    requiring = PolicySpec(required_tags={"tlp:green"})
    ok((await engine(p=requiring).apply("p", CONTEXT, event(tags={"TLP:GREEN"}))).accepted)


async def test_add_tags_does_not_duplicate_a_tag_spelled_differently() -> None:
    """MISP cannot hold TLP:GREEN and tlp:green as two tags on one event."""
    spec = PolicySpec(add_tags={"tlp:green"})
    result = await engine(p=spec).apply("p", CONTEXT, event(tags={"TLP:GREEN"}))
    eq(not_none(result.transformed_event).tags, {"TLP:GREEN"})
    eq(result.transformations, [])


async def test_renaming_onto_a_removed_tag_matches_case_insensitively() -> None:
    spec = PolicySpec(remove_tags={"tlp:red"}, rename_tags={"internal-only": "TLP:RED"})
    result = await engine(p=spec).apply("p", CONTEXT, event(tags={"internal-only"}))
    eq(not_none(result.transformed_event).tags, set())


async def test_redaction_drops_the_attachment_body_and_the_comment() -> None:
    """Blanking only ``value`` shipped the payload the redaction hides.

    For attachment types ``value`` is just the filename; the base64 body lives
    in ``data`` and used to travel to the destination untouched.
    """
    spec = PolicySpec(redact_values=[r"acme-internal"])
    base = event(
        tags=set(),
        attributes=[
            MISPAttribute(
                type="attachment",
                value="acme-internal-report.pdf",
                data="QUJDRA==",
                comment="acme-internal case notes",
            )
        ],
    )
    result = await engine(p=spec).apply("p", CONTEXT, base)
    ok(result.accepted)
    attribute = not_none(result.transformed_event).attributes[0]
    eq(attribute.value, REDACTED)
    eq(attribute.data, None)
    eq(attribute.comment, REDACTED)


async def test_redaction_reaches_the_object_comment_and_the_event_info() -> None:
    """The patterns describe what must not leave, wherever it sits.

    Scanning only attribute values and comments shipped the same string in the
    event's info and in an object's comment, with the audit trail claiming the
    policy had redacted it.
    """
    spec = PolicySpec(redact_values=[r"acme-internal"])
    base = event(
        info="acme-internal incident report",
        tags=set(),
        attributes=[],
        objects=[
            MISPObject(name="file", comment="acme-internal source", attributes=[]),
        ],
    )
    result = await engine(p=spec).apply("p", CONTEXT, base)
    transformed = not_none(result.transformed_event)
    eq(transformed.info, REDACTED)
    eq(transformed.objects[0].comment, REDACTED)
    eq({t.action for t in result.transformations}, {"redact-info", "redact-comment"})


async def test_redaction_drops_the_body_when_only_the_comment_matched() -> None:
    """For an attachment the value is the filename; the body is the secret.

    Clearing `data` only when the *value* matched shipped the payload whenever
    the pattern happened to hit the comment instead.
    """
    spec = PolicySpec(redact_values=[r"acme-internal"])
    base = event(
        info="",
        tags=set(),
        attributes=[
            MISPAttribute(
                type="attachment",
                value="q3-earnings.pdf",
                data="QUNNRS1JTlRFUk5BTA==",
                comment="acme-internal source document",
            )
        ],
    )
    result = await engine(p=spec).apply("p", CONTEXT, base)
    attribute = not_none(result.transformed_event).attributes[0]
    eq(attribute.comment, REDACTED)
    eq(attribute.data, None)
    eq(attribute.value, "q3-earnings.pdf")


async def test_a_rename_does_not_add_a_tag_already_held_in_another_case() -> None:
    """MISP cannot hold TLP:AMBER and tlp:amber as two tags on one event.

    add_tags was fixed for this; the rename path still produced the pair.
    """
    spec = PolicySpec(rename_tags={"tlp:red": "tlp:amber"})
    result = await engine(p=spec).apply("p", CONTEXT, event(tags={"TLP:AMBER", "tlp:red"}))
    eq(not_none(result.transformed_event).tags, {"TLP:AMBER"})
