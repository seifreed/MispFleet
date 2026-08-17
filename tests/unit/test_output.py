"""Unit tests for serializers and rich renderers."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from io import StringIO
from uuid import uuid4

from pydantic import AnyHttpUrl
from rich.console import Console

from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.common import OperationWarning, ServerError
from mispfleet.models.diff import Difference, DiffOperation, DiffSummary, EventDiff
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import ApplyResult, CopyPlan, PlanIssue, Transformation, ValidationResult
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import (
    FederatedMatch,
    FederatedSearchResult,
    FleetHealthResult,
    MatchGroup,
    MatchLevel,
    ServerHealth,
)
from mispfleet.models.server import CredentialReference, ServerConfig
from mispfleet.output.renderers import (
    render_apply_result,
    render_diff,
    render_health,
    render_plan,
    render_search_result,
    render_servers,
)
from mispfleet.output.serializers import SCHEMA_VERSION, document, jsonable, serialize
from tests.support import contains, eq, not_contains, ok

NOW = datetime.now(tz=UTC)


def console_output(render: Callable[..., None], *args: object) -> str:
    stream = StringIO()
    console = Console(file=stream, no_color=True, width=200)
    render(console, *args)
    return stream.getvalue()


def match(server: str = "production") -> FederatedMatch:
    return FederatedMatch(
        server=server,
        value="evil.example",
        attribute_type="domain",
        event_id="7",
        tags={"tlp:green"},
    )


def search_result(matches: list[FederatedMatch], failed: list[str]) -> FederatedSearchResult:
    servers = sorted({m.server for m in matches} | set(failed))
    return FederatedSearchResult(
        operation_id=uuid4(),
        started_at=NOW,
        completed_at=NOW,
        duration_ms=1.5,
        requested_servers=servers,
        successful_servers=[s for s in servers if s not in failed],
        failed_servers=failed,
        results={},
        matches=matches,
        groups=(
            [
                MatchGroup(
                    level=MatchLevel.SAME_VALUE_AND_TYPE, key="domain|evil.example", matches=matches
                )
            ]
            if len(matches) > 1
            else []
        ),
        total_matches=len(matches),
        unique_values=1,
    )


def test_jsonable_handles_models_containers_and_scalars() -> None:
    eq(jsonable({"set": {"b", "a"}}), {"set": ["a", "b"]})
    eq(jsonable([1, (2, 3)]), [1, [2, 3]])
    eq(jsonable("plain"), "plain")
    query = jsonable(SearchQuery(value="x"))
    eq(query["value"], "x")


def test_document_wraps_payloads_and_extras() -> None:
    envelope = document("op", {"key": "value"}, partial=True)
    eq(envelope["schema_version"], SCHEMA_VERSION)
    eq(envelope["operation"], "op")
    eq(envelope["partial"], True)
    eq(envelope["key"], "value")
    scalar = document("op", [1, 2])
    eq(scalar["data"], [1, 2])


def test_serialize_json_jsonl_and_yaml() -> None:
    payload = {"b": 2, "a": 1}
    as_json = serialize(payload, "json")
    eq(json.loads(as_json), payload)
    ok(as_json.index('"a"') < as_json.index('"b"'))
    lines = serialize([{"n": 1}, {"n": 2}], "jsonl").splitlines()
    eq([json.loads(line)["n"] for line in lines], [1, 2])
    single = serialize({"n": 3}, "jsonl").splitlines()
    eq(json.loads(single[0])["n"], 3)
    as_yaml = serialize({"a": [1, 2]}, "yaml")
    contains(as_yaml, "a:")


def test_render_servers_table() -> None:
    server = ServerConfig(
        name="production",
        url=AnyHttpUrl("https://misp.example"),
        credential=CredentialReference(provider="env", key="K"),
        groups={"internal"},
        read_only=True,
    )
    output = console_output(render_servers, [server])
    contains(output, "production")
    contains(output, "internal")


def test_render_search_result_with_groups_and_failures() -> None:
    result = search_result([match("production"), match("research")], failed=["partner"])
    output = console_output(render_search_result, result)
    contains(output, "evil.example")
    contains(output, "ok production")
    contains(output, "failed partner")
    contains(output, "1 duplicate group(s) detected")
    single = console_output(render_search_result, search_result([match()], failed=[]))
    not_contains(single, "duplicate group")


def test_render_health_covers_success_warning_error_and_missing() -> None:
    healthy = ServerHealth(
        server="production",
        reachable=True,
        authenticated=True,
        latency_ms=12.0,
        misp_version="2.4.190",
        capabilities={"sync"},
        warnings=["TLS verification is disabled for this server"],
    )
    broken = ServerHealth(
        server="down",
        reachable=False,
        authenticated=False,
        error=ServerError(server="down", kind="ConnectionFailedError", message="unreachable"),
    )
    result = FleetHealthResult(
        operation_id=uuid4(),
        started_at=NOW,
        completed_at=NOW,
        duration_ms=1.0,
        requested_servers=["production", "down", "crashed"],
        successful_servers=["production", "down"],
        failed_servers=["crashed"],
        results={"production": healthy, "down": broken},
        errors={
            "crashed": ServerError(
                server="crashed", kind="CredentialResolutionError", message="no key"
            )
        },
    )
    output = console_output(render_health, result)
    contains(output, "2.4.190")
    contains(output, "warning production")
    contains(output, "error down: unreachable")
    contains(output, "no key")


def test_render_diff_equivalent_and_differences() -> None:
    equivalent = EventDiff(
        event_identifier="uuid-1", left_server="a", right_server="b", equivalent=True
    )
    contains(console_output(render_diff, equivalent), "equivalent")
    differing = EventDiff(
        event_identifier="uuid-1",
        left_server="a",
        right_server="b",
        equivalent=False,
        differences=[
            Difference(operation=DiffOperation.CHANGE, path="info", left="x", right="y"),
            Difference(operation=DiffOperation.ADD, path="tags[new]"),
        ],
        summary=DiffSummary(added=1, changed=1),
    )
    output = console_output(render_diff, differing)
    contains(output, "change")
    contains(output, "added=1")


def test_render_plan_and_apply_result() -> None:
    event = MISPEvent(
        uuid=str(uuid4()), attributes=[MISPAttribute(type="domain", value="evil.example")]
    )
    plan = CopyPlan(
        plan_id=uuid4(),
        source_server="research",
        destination_server="production",
        source_event_uuid=uuid4(),
        source_fingerprint="fp",
        generated_at=NOW,
        transformations=[Transformation(action="add-tag", target="x")],
        validations=[
            ValidationResult(name="destination-writable", passed=True),
            ValidationResult(name="destination-conflict", passed=False, message="exists"),
        ],
        warnings=[OperationWarning(message="heads up")],
        blocking_errors=[PlanIssue(code="destination-conflict", message="already there")],
        proposed_event=event,
    )
    output = console_output(render_plan, plan)
    contains(output, "add-tag")
    contains(output, "pass")
    contains(output, "fail")
    contains(output, "heads up")
    contains(output, "blocking")
    applied = ApplyResult(
        operation_id=uuid4(),
        plan_id=plan.plan_id,
        applied=True,
        destination_server="production",
        messages=["event created on destination"],
    )
    output = console_output(render_apply_result, applied)
    contains(output, "applied")
    contains(output, "event created")
    skipped = ApplyResult(
        operation_id=uuid4(),
        plan_id=plan.plan_id,
        applied=False,
        destination_server="production",
    )
    contains(console_output(render_apply_result, skipped), "not applied")


def test_sync_result_renderer_lists_every_failed_copy() -> None:
    from mispfleet.cli.commands.sync import render_sync_result
    from mispfleet.models.sync import SyncResult

    result = SyncResult(
        plan_id=uuid4(),
        failures={
            "9c5c1c2e-0000-4000-8000-00000000000e": "destination unreachable",
            "9c5c1c2e-0000-4000-8000-00000000000f": "event changed after planning",
        },
    )
    output = console_output(render_sync_result, result)
    contains(output, "0 change(s) applied")
    contains(output, "destination unreachable")
    contains(output, "event changed after planning")


def test_non_finite_floats_serialize_as_valid_json() -> None:
    """json.dumps emits bare NaN/Infinity, which no RFC 8259 parser accepts."""
    text = serialize({"similarity": float("nan"), "latency_ms": float("inf")}, "json")
    not_contains(text, "NaN")
    not_contains(text, "Infinity")
    reloaded = json.loads(text)
    eq(reloaded["similarity"], None)
    eq(reloaded["latency_ms"], None)


def test_colliding_stringified_keys_are_refused_not_dropped() -> None:
    """{str(key): ...} merged 1 and "1", silently losing one record."""
    try:
        jsonable({1: "a", "1": "b"})
    except ValueError as error:
        contains(str(error), "collide")
        return
    raise AssertionError("colliding keys were accepted")


def test_audit_flag_reads_string_booleans_as_misp_sends_them() -> None:
    """bool("0") is True, so a disabled entry read as enabled.

    Builds in the supported range answer with "0"/"1" as well as booleans;
    two servers that agreed were then reported as drifting.
    """
    from mispfleet.services.audit import _flag

    eq(_flag("0"), "off")
    eq(_flag("false"), "off")
    eq(_flag(False), "off")
    eq(_flag("1"), "on")
    eq(_flag("true"), "on")
    eq(_flag(True), "on")


def test_server_data_is_never_parsed_as_rich_markup() -> None:
    """Square brackets from a MISP instance must render, not style or crash.

    An indicator value of "[/red]" aborted the whole command with MarkupError,
    and "[bold red]" silently restyled the terminal from attacker-chosen data.
    """
    hostile = FederatedMatch(
        server="production",
        value="[/red]",
        attribute_type="[bold red]domain",
        event_id="7",
        tags={"[blink]tlp:green"},
    )
    output = console_output(render_search_result, search_result([hostile], failed=[]))
    contains(output, "[/red]")
    contains(output, "[bold red]domain")
    contains(output, "[blink]tlp:green")
