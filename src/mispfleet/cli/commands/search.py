"""Federated search commands."""

from __future__ import annotations

from typing import Annotated

import typer

from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    CLIState,
    run,
    since_to_datetime,
    state_of,
)
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import FederatedSearchResult
from mispfleet.output.renderers import render_search_result, render_sightings

app = typer.Typer(help="Search across the fleet, preserving provenance.")


async def _search(state: CLIState, query: SearchQuery, operation: str) -> int:
    async with state.build_fleet() as fleet:
        result = await fleet.search(query, selector=state.selector())
    _emit(state, operation, result)
    if result.partial:
        return EXIT_PARTIAL
    if result.total_matches == 0:
        return EXIT_NO_MATCHES
    return EXIT_SUCCESS


def _emit(state: CLIState, operation: str, result: FederatedSearchResult) -> None:
    state.emit(
        operation,
        result,
        render=lambda console: render_search_result(console, result),
        jsonl_records=[match.model_dump(mode="json", exclude={"raw"}) for match in result.matches],
        partial=result.partial,
    )


@app.command()
def value(
    ctx: typer.Context,
    indicator: Annotated[str, typer.Argument(help="Indicator value to search for.")],
    limit: Annotated[int | None, typer.Option(min=1, help="Maximum records per server.")] = None,
) -> None:
    """Search one indicator value across the fleet."""
    state = state_of(ctx)
    query = SearchQuery(value=indicator, limit_per_server=limit)
    run(state, _search(state, query, "federated-search"))


@app.command()
def sightings(
    ctx: typer.Context,
    indicator: Annotated[str, typer.Argument(help="Indicator value to look up.")],
) -> None:
    """Report who has sighted an indicator across the fleet."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.sightings(indicator, selector=state.selector())
        state.emit(
            "federated-sightings",
            result,
            render=lambda console: render_sightings(console, result),
            jsonl_records=[record.model_dump(mode="json") for record in result.sightings],
            partial=result.partial,
        )
        if result.partial:
            return EXIT_PARTIAL
        if result.total_sightings == 0:
            return EXIT_NO_MATCHES
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def events(
    ctx: typer.Context,
    info: Annotated[str | None, typer.Option(help="Event info substring.")] = None,
    since: Annotated[str | None, typer.Option(help="Relative window, e.g. 30d.")] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Require this event tag.")] = None,
    org: Annotated[list[str] | None, typer.Option(help="Creator organisation filter.")] = None,
    threat_level: Annotated[str | None, typer.Option(help="Threat level filter.")] = None,
    analysis: Annotated[str | None, typer.Option(help="Analysis level filter.")] = None,
    distribution: Annotated[str | None, typer.Option(help="Distribution level filter.")] = None,
) -> None:
    """Search events by metadata across the fleet."""
    state = state_of(ctx)
    query = SearchQuery(
        event_info=info,
        tags=set(tag or []),
        organisations=set(org or []),
        threat_level=threat_level,
        analysis=analysis,
        distribution=distribution,
        date_from=since_to_datetime(since) if since else None,
        metadata_only=True,
    )
    run(state, _search(state, query, "federated-event-search"))


@app.command()
def attributes(
    ctx: typer.Context,
    attribute_type: Annotated[
        list[str] | None, typer.Option("--type", help="Attribute type filter.")
    ] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Require this tag.")] = None,
    since: Annotated[str | None, typer.Option(help="Relative window, e.g. 7d.")] = None,
    limit: Annotated[int | None, typer.Option(min=1, help="Maximum records per server.")] = None,
    org: Annotated[list[str] | None, typer.Option(help="Creator organisation filter.")] = None,
    object_name: Annotated[str | None, typer.Option(help="MISP object name filter.")] = None,
    distribution: Annotated[str | None, typer.Option(help="Distribution level filter.")] = None,
    timestamp_since: Annotated[
        str | None, typer.Option(help="Modified within this relative window, e.g. 7d.")
    ] = None,
    timestamp_until: Annotated[
        str | None, typer.Option(help="Modified before this relative window, e.g. 1d.")
    ] = None,
) -> None:
    """Search attributes by type, tag and date across the fleet."""
    state = state_of(ctx)
    query = SearchQuery(
        attribute_types=set(attribute_type or []),
        tags=set(tag or []),
        organisations=set(org or []),
        object_name=object_name,
        distribution=distribution,
        date_from=since_to_datetime(since) if since else None,
        timestamp_from=since_to_datetime(timestamp_since) if timestamp_since else None,
        timestamp_to=since_to_datetime(timestamp_until) if timestamp_until else None,
        limit_per_server=limit,
    )
    run(state, _search(state, query, "federated-attribute-search"))
