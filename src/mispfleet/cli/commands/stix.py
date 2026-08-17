"""STIX export and TAXII push commands."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from mispfleet.cli.context import EXIT_GENERIC, EXIT_SUCCESS, CLIState, run, state_of
from mispfleet.credentials.base import default_resolver
from mispfleet.models.server import CredentialReference
from mispfleet.output.renderers import plain_text
from mispfleet.output.serializers import serialize
from mispfleet.output.stix import event_to_stix_bundle
from mispfleet.services.taxii import TaxiiClient

app = typer.Typer(help="Export events as STIX 2.1 and push them over TAXII 2.1.")


def _resolve_credential(state: CLIState, key: str) -> str:
    resolver = default_resolver(interactive=not state.non_interactive)
    return resolver.resolve(CredentialReference(provider="env", key=key))


@app.command()
def export(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
) -> None:
    """Convert one event into a STIX 2.1 bundle (--server NAME)."""
    state = state_of(ctx)
    server = state.single_server()

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            event = await fleet.client(server).events.get(event_id)
        bundle, skipped = event_to_stix_bundle(event)

        def render(console: Console) -> None:
            # JSON is full of square brackets; rich would read them as markup
            # and abort the export on the first unbalanced one.
            console.print(serialize(bundle, "json"), end="", markup=False, highlight=False)
            for attribute_type in skipped:
                console.print(
                    f"[yellow]skipped[/yellow] unmapped type: {plain_text(attribute_type)}"
                )

        state.emit(
            "stix-export",
            {"bundle": bundle, "skipped": skipped},
            render=render,
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def push(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
    taxii_url: Annotated[str, typer.Option("--taxii-url", help="TAXII 2.1 base URL.")],
    collection: Annotated[str, typer.Option(help="Target collection id.")],
    credential_key: Annotated[
        str, typer.Option(help="Environment variable holding the TAXII bearer token.")
    ],
    api_root: Annotated[str, typer.Option(help="TAXII API root.")] = "api1",
) -> None:
    """Export one event to STIX and push it to a TAXII collection (--server NAME)."""
    state = state_of(ctx)
    server = state.single_server()

    async def inner() -> int:
        # Resolved inside the coroutine so a missing credential exits 3
        # through run() instead of escaping click as a traceback.
        token = _resolve_credential(state, credential_key)
        async with state.build_fleet() as fleet:
            event = await fleet.client(server).events.get(event_id)
        bundle, skipped = event_to_stix_bundle(event)
        async with TaxiiClient(taxii_url, token=token) as taxii:
            status = await taxii.push(api_root, collection, bundle["objects"])
        # The TAXII status resource is the outcome, not a receipt: a server
        # that rejected every object still answers 202, so reporting success
        # from the HTTP code alone called a total failure a success.
        failures = int(status.get("failure_count", 0) or 0)
        succeeded = int(status.get("success_count", len(bundle["objects"])) or 0)
        state.emit(
            "taxii-push",
            {
                "status": status,
                "skipped": skipped,
                "pushed": succeeded,
                "failed": failures,
            },
            render=lambda console: console.print(
                f"pushed {succeeded} object(s) to {plain_text(collection)}: "
                f"{plain_text(str(status.get('status', 'unknown')))}"
                + (f" ({failures} rejected)" if failures else "")
            ),
        )
        return EXIT_GENERIC if failures else EXIT_SUCCESS

    run(state, inner())
