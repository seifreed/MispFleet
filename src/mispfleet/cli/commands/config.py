"""Configuration commands."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from rich.console import Console
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from mispfleet.cli.context import (
    EXIT_CONFIGURATION,
    EXIT_SUCCESS,
    EXIT_USAGE,
    CLIState,
    guard,
    state_of,
)
from mispfleet.credentials.keyring import KeyringCredentialProvider
from mispfleet.exceptions import CredentialResolutionError, InvalidConfigurationError
from mispfleet.models.common import ServerRole
from mispfleet.models.server import ServerConfig
from mispfleet.output.renderers import plain_text
from mispfleet.output.serializers import jsonable
from mispfleet.redaction import redact_mapping
from mispfleet.settings import default_config_path

app = typer.Typer(help="Manage the fleet configuration file.")

CONFIG_TEMPLATE = """version: 1
defaults:
  verify_tls: true
  request_timeout: 60
  connect_timeout: 10
  concurrency: 5
servers: {}
policies: {}
"""


@app.command()
def init(
    ctx: typer.Context,
    force: Annotated[bool, typer.Option(help="Overwrite an existing file.")] = False,
) -> None:
    """Create a configuration file with restrictive permissions."""
    state = state_of(ctx)
    path = state.config_path or default_config_path()
    if path.exists() and not force:
        typer.echo(f"configuration already exists at {path}; use --force to overwrite", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    # An unwritable --config target (parent is a file, no permission) is
    # operator error: report it as the one-line usage error every other CLI
    # write path uses, not as a raw OSError traceback with exit 1.
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        path.chmod(0o600)
    except OSError as error:
        raise typer.BadParameter(f"cannot write {path}: {error}") from error
    typer.echo(f"created {path}")


@app.command()
def show(ctx: typer.Context) -> None:
    """Show the validated configuration with credentials redacted."""
    state = state_of(ctx)
    guard(state, lambda: _show(state))


def _show(state: CLIState) -> None:
    config = state.load_config()
    payload = redact_mapping(jsonable(config.model_dump(mode="json")))
    state.emit(
        "config-show",
        {"config": payload},
        render=lambda console: console.print_json(data=payload),
    )


@app.command()
def validate(ctx: typer.Context) -> None:
    """Validate the configuration and check credential references."""
    state = state_of(ctx)
    try:
        config = state.load_config()
    except InvalidConfigurationError as error:
        typer.echo(f"invalid configuration: {error.message}", err=True)
        raise typer.Exit(EXIT_CONFIGURATION) from error
    warnings: list[str] = []
    for name, server in config.servers.items():
        reference = server.credential
        if reference.provider == "env" and not os.environ.get(reference.key):
            warnings.append(f"server {name}: environment variable {reference.key} is not set")
        elif reference.provider == "keyring":
            try:
                KeyringCredentialProvider().resolve(reference.key)
            except CredentialResolutionError:
                warnings.append(f"server {name}: no keyring entry for {reference.key}")

    def render(console: Console) -> None:
        console.print(f"configuration valid: {len(config.servers)} server(s)")
        for warning in warnings:
            console.print(f"[yellow]warning[/yellow] {plain_text(warning)}")

    state.emit(
        "config-validate",
        {"valid": True, "servers": sorted(config.servers), "warnings": warnings},
        render=render,
    )


@app.command()
def path(ctx: typer.Context) -> None:
    """Print the effective configuration path."""
    state = state_of(ctx)
    typer.echo(str(state.config_path or default_config_path()))


def _load_document(config_path: Path) -> Any:
    """Parse the raw YAML document, mapping a syntax error to exit 3.

    add-server and remove-server edit the file textually rather than through
    the validated model, so a malformed file surfaced as a raw ruamel
    traceback where every other command reports a configuration error.
    """
    try:
        document = YAML().load(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, YAMLError) as error:
        typer.echo(f"error: invalid YAML in {config_path}: {error}", err=True)
        raise typer.Exit(EXIT_CONFIGURATION) from error
    if document is not None and not isinstance(document, Mapping):
        # A list or scalar parses fine and then fails on .get/.setdefault, which
        # surfaced as a traceback where the model-based commands report exit 3.
        typer.echo(
            f"error: {config_path} must contain a mapping, not " f"{type(document).__name__}",
            err=True,
        )
        raise typer.Exit(EXIT_CONFIGURATION)
    return document


def _dump_config(config_path: Path, yaml: YAML, data: Any) -> None:
    """Write the YAML config owner-only, typing an unwritable target.

    add-server/remove-server edit the file textually; an unwritable target
    (parent is a regular file, no permission) is operator error and must
    surface as the one-line usage error every other CLI write path reports,
    not as a raw OSError traceback with exit 1.
    """
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with config_path.open("w", encoding="utf-8") as handle:
            yaml.dump(data, handle)
        config_path.chmod(0o600)
    except OSError as error:
        raise typer.BadParameter(f"cannot write {config_path}: {error}") from error


@app.command("add-server")
def add_server(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Local server name.")],
    url: Annotated[str, typer.Option(help="Base URL of the MISP server.")],
    credential_key: Annotated[str, typer.Option(help="Credential key (e.g. env var name).")],
    credential_provider: Annotated[
        str, typer.Option(help="Credential provider: env, keyring, prompt or memory.")
    ] = "env",
    groups: Annotated[list[str] | None, typer.Option("--groups", help="Group membership.")] = None,
    role: Annotated[ServerRole, typer.Option(help="Server role.")] = ServerRole.GENERAL,
    read_only: Annotated[bool, typer.Option(help="Mark the server read-only.")] = False,
) -> None:
    """Append a server to the configuration file."""
    state = state_of(ctx)
    config_path = state.config_path or default_config_path()
    yaml = YAML()
    data = _load_document(config_path) if config_path.exists() else None
    if data is None:
        data = {"version": 1, "servers": {}}
    servers = data.setdefault("servers", {}) or {}
    if name in servers:
        typer.echo(f"server {name!r} already exists", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    entry: dict[str, object] = {
        "url": url,
        "credential": {"provider": credential_provider, "key": credential_key},
        # ruamel serializes plain scalars only, never the StrEnum member.
        "role": role.value,
    }
    if groups:
        entry["groups"] = list(groups)
    if read_only:
        entry["read_only"] = True
    # Writing an entry the loader will reject leaves the file unusable, and the
    # rejection surfaces later against a file the user did not just edit.
    try:
        ServerConfig.model_validate({"name": name, **entry})
    except ValidationError as error:
        typer.echo(f"invalid server {name!r}: {error}", err=True)
        raise typer.Exit(EXIT_USAGE) from error
    servers[name] = entry
    data["servers"] = servers
    _dump_config(config_path, yaml, data)
    typer.echo(f"added server {name!r} to {config_path}")


@app.command("remove-server")
def remove_server(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Local server name.")],
) -> None:
    """Remove a server from the configuration file."""
    state = state_of(ctx)
    config_path = state.config_path or default_config_path()
    if not config_path.exists():
        typer.echo(f"configuration file not found: {config_path}", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    yaml = YAML()
    data = _load_document(config_path) or {}
    servers = data.get("servers") or {}
    if name not in servers:
        typer.echo(f"server {name!r} is not configured", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    del servers[name]
    _dump_config(config_path, yaml, data)
    typer.echo(f"removed server {name!r}")
    raise typer.Exit(EXIT_SUCCESS)
