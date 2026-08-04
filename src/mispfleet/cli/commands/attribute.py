"""Attribute commands: single fetch and streaming federated search."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from mispfleet.attachments import write_attachment
from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_SUCCESS,
    CLIState,
    run,
    since_to_datetime,
    state_of,
)
from mispfleet.models.query import SearchQuery

app = typer.Typer(help="Work with attributes across the fleet.")


def _single_server(state: CLIState) -> str:
    if len(state.servers) == 1:
        return state.servers[0]
    raise typer.BadParameter("specify exactly one server with --server NAME")


@app.command()
def get(
    ctx: typer.Context,
    attribute_id: Annotated[str, typer.Argument(help="Attribute UUID or numeric id.")],
    download: Annotated[
        Path | None,
        typer.Option("--download", help="Save the attachment payload into this directory."),
    ] = None,
) -> None:
    """Fetch one attribute from one server (--server NAME)."""
    state = state_of(ctx)
    server = _single_server(state)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            attribute = await fleet.client(server).attributes.get(attribute_id)
        payload: dict[str, object] = {"server": server, "attribute": attribute}
        if download is not None:
            if attribute.data is None:
                state.emit("attribute-get", payload | {"saved_to": None})
                return EXIT_NO_MATCHES
            filename = attribute.value.split("|", 1)[0]
            saved = write_attachment(attribute.data, download, filename)
            payload["saved_to"] = str(saved)
        state.emit(
            "attribute-get",
            payload,
            render=lambda console: console.print_json(data=attribute.model_dump(mode="json")),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def search(
    ctx: typer.Context,
    attribute_type: Annotated[
        list[str] | None, typer.Option("--type", help="Attribute type filter.")
    ] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Require this tag.")] = None,
    since: Annotated[str | None, typer.Option(help="Relative window, e.g. 7d.")] = None,
    limit: Annotated[int | None, typer.Option(help="Maximum records per server.")] = None,
    page_size: Annotated[int, typer.Option(help="Records fetched per page.")] = 1000,
) -> None:
    """Stream matching attributes as JSON lines without buffering the dataset."""
    state = state_of(ctx)
    query = SearchQuery(
        attribute_types=set(attribute_type or []),
        tags=set(tag or []),
        date_from=since_to_datetime(since) if since else None,
        limit_per_server=limit,
    )

    async def inner() -> int:
        count = 0
        stream = state.output_path.open("w", encoding="utf-8") if state.output_path else sys.stdout
        try:
            async with state.build_fleet() as fleet:
                async for match in fleet.iter_search(
                    query, selector=state.selector(), page_size=page_size
                ):
                    record = match.model_dump(mode="json", exclude={"raw"})
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
                    count += 1
        finally:
            if state.output_path is not None:
                stream.close()
        return EXIT_SUCCESS if count else EXIT_NO_MATCHES

    run(state, inner())
