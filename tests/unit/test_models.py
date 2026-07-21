"""Unit tests for domain models."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import AnyHttpUrl
from pydantic import ValidationError as PydanticValidationError

from mispfleet.models import (
    ApplyResult,
    ConflictAction,
    CopyPlan,
    CredentialReference,
    Difference,
    DiffOperation,
    DiffSummary,
    EventDiff,
    ExecutionOptions,
    FailurePolicy,
    FederatedMatch,
    FederatedSearchResult,
    MatchGroup,
    MatchLevel,
    MISPAttribute,
    MISPEvent,
    MISPObject,
    MultiServerResult,
    OperationWarning,
    SearchQuery,
    ServerConfig,
    ServerError,
    ServerHealth,
    ServerRole,
)
from mispfleet.models.attribute import tag_names
from tests.support import contains, eq, ne, not_contains, ok

RAW_ATTRIBUTE = {
    "uuid": "1f2b8a1e-0000-4000-8000-000000000001",
    "event_id": "7",
    "type": "domain",
    "category": "Network activity",
    "value": "evil.example",
    "to_ids": True,
    "comment": "seen in campaign",
    "deleted": False,
    "timestamp": "1700000000",
    "Tag": [{"name": "tlp:green"}, {"colour": "#ffffff"}],
}

RAW_EVENT: dict[str, Any] = {
    "Event": {
        "uuid": "9c5c1c2e-0000-4000-8000-00000000000e",
        "info": "Campaign X",
        "date": "2026-01-01",
        "published": True,
        "distribution": "1",
        "threat_level_id": "2",
        "analysis": "1",
        "timestamp": "1700000001",
        "Orgc": {"name": "CIRCL"},
        "Tag": [{"name": "tlp:green"}],
        "Attribute": [RAW_ATTRIBUTE],
        "Object": [
            {
                "uuid": "3a5c1c2e-0000-4000-8000-00000000000f",
                "name": "file",
                "template_uuid": "t-1",
                "comment": "",
                "Attribute": [
                    {
                        "type": "sha256",
                        "value": "aa" * 32,
                        "event_id": "7",
                        "timestamp": "1700000002",
                    }
                ],
            }
        ],
    }
}


def make_server(name: str = "production") -> ServerConfig:
    return ServerConfig(
        name=name,
        url=AnyHttpUrl("https://misp.example"),
        credential=CredentialReference(provider="env", key="MISPFLEET_KEY"),
    )


def test_server_config_defaults() -> None:
    config = make_server()
    eq(config.enabled, True)
    eq(config.read_only, False)
    eq(config.verify_tls, True)
    eq(config.role, ServerRole.GENERAL)
    eq(config.retry.max_attempts, 4)
    eq(config.concurrency, 5)


def test_server_config_rejects_invalid_url() -> None:
    with pytest.raises(PydanticValidationError):
        ServerConfig.model_validate(
            {
                "name": "bad",
                "url": "not-a-url",
                "credential": {"provider": "env", "key": "X"},
            }
        )


def test_tag_names_skips_malformed_tags() -> None:
    eq(tag_names(RAW_ATTRIBUTE), {"tlp:green"})
    eq(tag_names({}), set())


def test_attribute_from_misp_full_and_minimal() -> None:
    attribute = MISPAttribute.from_misp(RAW_ATTRIBUTE)
    eq(attribute.type, "domain")
    eq(attribute.value, "evil.example")
    eq(attribute.event_id, "7")
    ok(attribute.to_ids)
    minimal = MISPAttribute.from_misp({"type": "ip-dst", "value": "203.0.113.7"})
    eq(minimal.uuid, None)
    eq(minimal.event_id, None)
    eq(minimal.timestamp, None)
    eq(minimal.tags, set())


def test_object_from_misp() -> None:
    obj = MISPObject.from_misp(
        {"name": "file", "Attribute": [{"type": "sha256", "value": "bb" * 32}]}
    )
    eq(obj.name, "file")
    eq(len(obj.attributes), 1)
    eq(MISPObject.from_misp({"name": "empty"}).attributes, [])


def test_event_from_misp_wrapped_and_plain() -> None:
    event = MISPEvent.from_misp(RAW_EVENT)
    eq(event.uuid, "9c5c1c2e-0000-4000-8000-00000000000e")
    eq(event.info, "Campaign X")
    eq(event.orgc, "CIRCL")
    eq(event.tags, {"tlp:green"})
    eq(len(event.attributes), 1)
    eq(len(event.objects), 1)
    plain = MISPEvent.from_misp({"uuid": "aa5c1c2e-0000-4000-8000-00000000000e"})
    eq(plain.info, "")
    eq(plain.date, None)
    eq(plain.orgc, None)


def test_canonical_fingerprint_ignores_volatile_fields_and_order() -> None:
    left = MISPEvent.from_misp(RAW_EVENT)
    shuffled = MISPEvent.from_misp(RAW_EVENT)
    shuffled.timestamp = "9999999999"
    shuffled.attributes = list(reversed(shuffled.attributes))
    shuffled.objects = list(reversed(shuffled.objects))
    eq(left.canonical_fingerprint(), shuffled.canonical_fingerprint())
    changed = MISPEvent.from_misp(RAW_EVENT)
    changed.info = "renamed"
    ne(left.canonical_fingerprint(), changed.canonical_fingerprint())


def test_search_query_payload_includes_all_requested_criteria() -> None:
    query = SearchQuery(
        value="evil.example",
        event_info="campaign",
        event_uuid=uuid4(),
        attribute_uuid=uuid4(),
        attribute_types={"domain", "ip-dst"},
        categories={"Network activity"},
        tags={"tlp:green"},
        excluded_tags={"tlp:red"},
        published=True,
        date_from=date(2026, 1, 1),
        date_to=datetime(2026, 2, 1, tzinfo=UTC),
        metadata_only=True,
        include_deleted=True,
        enforce_warninglists=True,
        limit_per_server=100,
    )
    payload = query.to_misp_payload()
    eq(payload["returnFormat"], "json")
    eq(payload["value"], "evil.example")
    eq(payload["eventinfo"], "campaign")
    eq(payload["type"], ["domain", "ip-dst"])
    eq(payload["category"], ["Network activity"])
    eq(payload["tags"], ["tlp:green", "!tlp:red"])
    eq(payload["published"], True)
    eq(payload["from"], "2026-01-01")
    contains(payload["to"], "2026-02-01")
    eq(payload["metadata"], True)
    eq(payload["deleted"], True)
    eq(payload["enforceWarninglist"], True)


def test_search_query_empty_payload_is_minimal() -> None:
    eq(SearchQuery().to_misp_payload(), {"returnFormat": "json"})


def test_search_query_fingerprint_is_deterministic() -> None:
    left = SearchQuery(value="a", tags={"x", "y"})
    right = SearchQuery(value="a", tags={"y", "x"})
    eq(left.fingerprint(), right.fingerprint())
    ne(left.fingerprint(), SearchQuery(value="b").fingerprint())


def _result(failed: list[str]) -> MultiServerResult[str]:
    now = datetime.now(tz=UTC)
    return MultiServerResult[str](
        operation_id=uuid4(),
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        requested_servers=["a", "b"],
        successful_servers=[s for s in ["a", "b"] if s not in failed],
        failed_servers=failed,
        results={},
    )


def test_multi_server_result_complete_and_partial() -> None:
    ok(_result([]).complete)
    ok(not _result([]).partial)
    ok(_result(["b"]).partial)
    ok(not _result(["b"]).complete)


def test_federated_search_result_defaults() -> None:
    now = datetime.now(tz=UTC)
    result = FederatedSearchResult(
        operation_id=uuid4(),
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        requested_servers=[],
        successful_servers=[],
        failed_servers=[],
        results={},
    )
    eq(result.matches, [])
    eq(result.total_matches, 0)


def test_match_group_and_health_models() -> None:
    match = FederatedMatch(server="production", value="evil.example", attribute_type="domain")
    group = MatchGroup(
        level=MatchLevel.SAME_VALUE_AND_TYPE, key="domain|evil.example", matches=[match]
    )
    eq(group.matches[0].server, "production")
    health = ServerHealth(server="production", reachable=True, authenticated=True)
    eq(health.error, None)
    error = ServerError(server="x", kind="timeout", message="deadline exceeded", retryable=True)
    ok(error.retryable)
    warning = OperationWarning(message="dataset changed during traversal")
    eq(warning.server, None)


def test_execution_options_and_failure_policy() -> None:
    options = ExecutionOptions()
    eq(options.max_concurrency, 10)
    eq(options.failure_policy, FailurePolicy.CONTINUE)
    eq(FailurePolicy("fail-fast"), FailurePolicy.FAIL_FAST)


def test_diff_models() -> None:
    diff = EventDiff(
        event_identifier="uuid-1",
        left_server="a",
        right_server="b",
        equivalent=False,
        differences=[Difference(operation=DiffOperation.ADD, path="attributes[domain|x]")],
        summary=DiffSummary(added=1),
    )
    eq(diff.summary.added, 1)
    eq(diff.differences[0].operation, DiffOperation.ADD)


def test_copy_plan_and_apply_result() -> None:
    event = MISPEvent.from_misp(RAW_EVENT)
    plan = CopyPlan(
        plan_id=uuid4(),
        source_server="research",
        destination_server="production",
        source_event_uuid=UUID(event.uuid),
        source_fingerprint=event.canonical_fingerprint(),
        generated_at=datetime.now(tz=UTC),
        proposed_event=event,
    )
    eq(plan.kind, "copy")
    eq(plan.on_conflict, ConflictAction.ABORT)
    eq(plan.blocking_errors, [])
    outcome = ApplyResult(
        operation_id=uuid4(),
        plan_id=plan.plan_id,
        applied=True,
        destination_server="production",
    )
    ok(outcome.applied)


def test_attribute_and_object_to_misp_round_trip() -> None:
    full = MISPAttribute.from_misp(RAW_ATTRIBUTE)
    payload = full.to_misp()
    eq(payload["uuid"], full.uuid)
    eq(payload["category"], "Network activity")
    eq(payload["Tag"], [{"name": "tlp:green"}])
    minimal = MISPAttribute(type="domain", value="x.example")
    minimal_payload = minimal.to_misp()
    not_contains(minimal_payload, "uuid")
    not_contains(minimal_payload, "category")
    obj = MISPObject.from_misp(RAW_EVENT["Event"]["Object"][0])
    obj_payload = obj.to_misp()
    eq(obj_payload["name"], "file")
    eq(obj_payload["template_uuid"], "t-1")
    eq(len(obj_payload["Attribute"]), 1)
    bare_object = MISPObject(name="bare").to_misp()
    not_contains(bare_object, "uuid")
    not_contains(bare_object, "template_uuid")


def test_event_to_misp_round_trip_preserves_fingerprint() -> None:
    event = MISPEvent.from_misp(RAW_EVENT)
    rebuilt = MISPEvent.from_misp({"Event": event.to_misp()})
    eq(event.canonical_fingerprint(), rebuilt.canonical_fingerprint())
    minimal = MISPEvent(uuid="ab5c1c2e-0000-4000-8000-00000000000e")
    payload = minimal.to_misp()
    not_contains(payload, "date")
    not_contains(payload, "distribution")
    not_contains(payload, "threat_level_id")
    not_contains(payload, "analysis")


def test_server_config_rejects_plain_http_by_default() -> None:
    with pytest.raises(PydanticValidationError) as excinfo:
        ServerConfig(
            name="insecure",
            url=AnyHttpUrl("http://misp.example"),
            credential=CredentialReference(provider="env", key="X"),
        )
    contains(str(excinfo.value), "allow_insecure_http")
    permitted = ServerConfig(
        name="lab",
        url=AnyHttpUrl("http://127.0.0.1:8080"),
        credential=CredentialReference(provider="env", key="X"),
        allow_insecure_http=True,
    )
    eq(permitted.allow_insecure_http, True)
