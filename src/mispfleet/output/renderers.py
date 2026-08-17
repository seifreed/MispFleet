"""Human-oriented terminal rendering built on rich."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mispfleet.models.audit import FleetAuditResult
from mispfleet.models.diff import DiffOperation, EventDiff
from mispfleet.models.plan import ApplyResult, CopyPlan
from mispfleet.models.result import (
    FederatedSearchResult,
    FederatedSightingsResult,
    FleetHealthResult,
)
from mispfleet.models.server import ServerConfig


def plain_text(value: object) -> str:
    """Render server-controlled text literally.

    Rich reads square brackets as markup, so an indicator value of ``[/red]``
    aborted the whole command with ``MarkupError`` and ``[bold red]`` silently
    restyled the terminal. Everything that reaches us from a MISP instance has
    to go through here before it is interpolated next to a style tag.
    """
    return escape("" if value is None else str(value))


def _status_table(title: str, columns: list[str]) -> Table:
    table = Table(title=title, show_lines=False)
    for column in columns:
        table.add_column(column)
    return table


def render_servers(console: Console, servers: list[ServerConfig]) -> None:
    """Render the configured server list."""
    table = _status_table("Servers", ["name", "url", "role", "groups", "enabled", "read-only"])
    for server in servers:
        table.add_row(
            plain_text(server.name),
            plain_text(server.url),
            server.role.value,
            plain_text(",".join(sorted(server.groups))),
            "yes" if server.enabled else "no",
            "yes" if server.read_only else "no",
        )
    console.print(table)


def render_search_result(console: Console, result: FederatedSearchResult) -> None:
    """Render federated matches with per-server statuses."""
    table = _status_table(
        f"Matches ({result.total_matches})",
        ["server", "type", "value", "event", "tags"],
    )
    for match in result.matches:
        table.add_row(
            plain_text(match.server),
            plain_text(match.attribute_type or ""),
            plain_text(match.value or ""),
            plain_text(match.event_uuid or match.event_id or ""),
            plain_text(",".join(sorted(match.tags))),
        )
    console.print(table)
    _render_server_statuses(console, result.successful_servers, result.failed_servers)
    if result.groups:
        console.print(f"{len(result.groups)} duplicate group(s) detected")


def _render_server_statuses(console: Console, successful: list[str], failed: list[str]) -> None:
    for server in successful:
        console.print(f"[green]ok[/green] {plain_text(server)}")
    for server in failed:
        console.print(f"[red]failed[/red] {plain_text(server)}")


def render_sightings(console: Console, result: FederatedSightingsResult) -> None:
    """Render fleet-wide sightings of one indicator."""
    table = _status_table(
        f"Sightings ({result.total_sightings})",
        ["server", "event", "attribute", "type", "date", "organisation"],
    )
    for record in result.sightings:
        table.add_row(
            plain_text(record.server),
            plain_text(record.event_id or "-"),
            plain_text(record.attribute_uuid or "-"),
            plain_text(record.type),
            plain_text(record.date_sighting or "-"),
            plain_text(record.organisation or "-"),
        )
    console.print(table)
    for name in result.failed_servers:
        error = result.errors.get(name)
        detail = plain_text(error.message if error else "unreachable")
        console.print(f"[red]failed[/red] {plain_text(name)}: {detail}")


def render_audit(console: Console, result: FleetAuditResult) -> None:
    """Render fleet configuration drift, one row per divergent key."""
    if result.consistent:
        console.print(
            f"fleet configuration consistent across {len(result.successful_servers)} server(s)"
        )
    else:
        table = _status_table("Fleet configuration drift", ["dimension", "key", "kind", "servers"])
        for finding in result.findings:
            described = ", ".join(
                f"{server}={value if value is not None else 'absent'}"
                for server, value in sorted(finding.values.items())
            )
            table.add_row(
                plain_text(finding.dimension),
                plain_text(finding.key),
                finding.kind.value,
                plain_text(described),
            )
        console.print(table)
    for name in result.failed_servers:
        error = result.errors.get(name)
        detail = plain_text(error.message if error else "unreachable")
        console.print(f"[red]failed[/red] {plain_text(name)}: {detail}")


def render_health(console: Console, result: FleetHealthResult) -> None:
    """Render fleet health with warnings separated from failures."""
    table = _status_table(
        "Fleet health",
        ["server", "reachable", "authenticated", "latency", "version", "capabilities"],
    )
    for name in result.requested_servers:
        health = result.results.get(name)
        if health is None:
            error = result.errors.get(name)
            table.add_row(
                plain_text(name), "no", "-", "-", "-", plain_text(error.message if error else "")
            )
            continue
        table.add_row(
            plain_text(health.server),
            "yes" if health.reachable else "no",
            "yes" if health.authenticated else "no",
            f"{health.latency_ms:.0f} ms" if health.latency_ms is not None else "-",
            plain_text(health.misp_version or "-"),
            plain_text(",".join(sorted(health.capabilities))),
        )
    console.print(table)
    for name in result.requested_servers:
        health = result.results.get(name)
        if health is not None:
            for warning in health.warnings:
                console.print(f"[yellow]warning[/yellow] {plain_text(name)}: {plain_text(warning)}")
            if health.error is not None:
                console.print(
                    f"[red]error[/red] {plain_text(name)}: {plain_text(health.error.message)}"
                )


def render_diff(console: Console, diff: EventDiff) -> None:
    """Render an event diff."""
    if diff.equivalent:
        console.print(
            f"event {plain_text(diff.event_identifier)} is equivalent on "
            f"{plain_text(diff.left_server)} and {plain_text(diff.right_server)}"
        )
        return
    table = _status_table(
        f"Diff {plain_text(diff.left_server)} vs {plain_text(diff.right_server)}",
        ["operation", "path", "left", "right"],
    )
    for difference in diff.differences:
        table.add_row(
            difference.operation.value,
            plain_text(difference.path),
            "" if difference.left is None else plain_text(difference.left),
            "" if difference.right is None else plain_text(difference.right),
        )
    console.print(table)
    summary = diff.summary
    console.print(
        f"added={summary.added} removed={summary.removed} "
        f"changed={summary.changed} conflicts={summary.conflicts}"
    )


_PATCH_SYMBOLS = {
    DiffOperation.ADD: "+",
    DiffOperation.REMOVE: "-",
    DiffOperation.CHANGE: "~",
    DiffOperation.CONFLICT: "!",
}


def _one_line(text: str) -> str:
    """Keep server data from breaking out of its patch line.

    Paths embed attribute values, tag names and cluster names verbatim, and a
    multi-line ``text`` attribute is routine in MISP: one difference became two
    lines, and a crafted value could forge an entry the diff never reported.
    """
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")


def patch_from_diff(diff: EventDiff) -> str:
    """Render an event diff as a deterministic patch-style text document."""
    lines = [
        f"--- {_one_line(diff.left_server)}/{_one_line(str(diff.event_identifier))}",
        f"+++ {_one_line(diff.right_server)}/{_one_line(str(diff.event_identifier))}",
    ]
    for difference in diff.differences:
        line = f"{_PATCH_SYMBOLS[difference.operation]} {_one_line(difference.path)}"
        if difference.left is not None or difference.right is not None:
            line += f": {difference.left!r} -> {difference.right!r}"
        lines.append(line)
    summary = diff.summary
    lines.append(
        f"@@ added={summary.added} removed={summary.removed} "
        f"changed={summary.changed} conflicts={summary.conflicts}"
    )
    return "\n".join(lines) + "\n"


def render_plan(console: Console, plan: CopyPlan) -> None:
    """Render a copy plan review."""
    console.print(
        f"Plan {plan.plan_id}: copy {plain_text(plan.source_event_uuid)} "
        f"from {plain_text(plan.source_server)} to {plain_text(plan.destination_server)}"
    )
    for transformation in plan.transformations:
        console.print(
            f"  transform: {plain_text(transformation.action)} {plain_text(transformation.target)}"
        )
    for validation in plan.validations:
        status = "[green]pass[/green]" if validation.passed else "[red]fail[/red]"
        console.print(
            f"  validate: {plain_text(validation.name)} {status} {plain_text(validation.message)}"
        )
    for warning in plan.warnings:
        console.print(f"  [yellow]warning[/yellow]: {plain_text(warning.message)}")
    for issue in plan.blocking_errors:
        console.print(
            f"  [red]blocking[/red]: {plain_text(issue.code)}: {plain_text(issue.message)}"
        )


def render_apply_result(console: Console, result: ApplyResult) -> None:
    """Render the outcome of applying a plan."""
    status = "applied" if result.applied else "not applied"
    console.print(f"Plan {result.plan_id}: {status} on {plain_text(result.destination_server)}")
    for message in result.messages:
        console.print(f"  {plain_text(message)}")
