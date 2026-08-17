"""Configuration loading: YAML file, profiles, defaults and standard paths."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import platformdirs
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic import ValidationError as PydanticValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.models.server import ServerConfig
from mispfleet.models.sync import SyncJobSpec
from mispfleet.policies.base import PolicySpec
from mispfleet.state.base import StateBackend
from mispfleet.state.mariadb import MariaDBStateBackend
from mispfleet.state.sqlite import SqliteStateBackend

APP_NAME = "mispfleet"
SUPPORTED_CONFIG_VERSION = 1

ENV_CONFIG = "MISPFLEET_CONFIG"
ENV_STATE = "MISPFLEET_STATE_PATH"
ENV_PROFILE = "MISPFLEET_PROFILE"
ENV_ACTOR = "MISPFLEET_ACTOR"


class FleetDefaults(BaseModel):
    """Fleet-wide defaults applied to servers that do not override them."""

    model_config = ConfigDict(extra="forbid")

    verify_tls: bool = True
    request_timeout: float = Field(default=60.0, gt=0.0)
    connect_timeout: float = Field(default=10.0, gt=0.0)
    concurrency: int = Field(default=5, ge=1)
    http2: bool = False
    max_keepalive_connections: int | None = Field(default=None, ge=1)
    keepalive_expiry: float | None = Field(default=None, gt=0.0)
    max_response_bytes: int = Field(default=50_000_000, ge=1)


class SecuritySettings(BaseModel):
    """Fleet-wide security constraints."""

    model_config = ConfigDict(extra="forbid")

    forbid_insecure_tls: bool = False


class StateSettings(BaseModel):
    """Selection and location of the local state backend."""

    model_config = ConfigDict(extra="forbid")

    backend: Literal["sqlite", "mariadb"] = "sqlite"
    path: Path | None = None
    dsn: str | None = None
    password_env: str | None = None
    capability_ttl_seconds: float = Field(default=3600.0, gt=0.0)

    @model_validator(mode="after")
    def _require_dsn_for_mariadb(self) -> StateSettings:
        if self.path is not None:
            self.path = self.path.expanduser()
        if self.backend == "mariadb" and not self.dsn:
            raise ValueError("state backend 'mariadb' requires a dsn (mysql://user@host/db)")
        return self


def build_state_backend(settings: StateSettings) -> StateBackend:
    """Instantiate the configured state backend (not yet initialized)."""
    if settings.backend == "mariadb":
        password = os.environ.get(settings.password_env) if settings.password_env else None
        return MariaDBStateBackend(settings.dsn or "", password=password)
    # The environment outranks the configuration file (docs/configuration.md),
    # so the override cannot be left to default_state_path's fallback alone.
    override = os.environ.get(ENV_STATE)
    if override:
        return SqliteStateBackend(Path(override))
    return SqliteStateBackend(settings.path or default_state_path())


class FleetConfig(BaseModel):
    """Validated fleet configuration: servers, defaults, policies and state."""

    version: int = SUPPORTED_CONFIG_VERSION
    defaults: FleetDefaults = Field(default_factory=FleetDefaults)
    servers: dict[str, ServerConfig] = Field(default_factory=dict)
    policies: dict[str, PolicySpec] = Field(default_factory=dict)
    sync_jobs: dict[str, SyncJobSpec] = Field(default_factory=dict)
    state: StateSettings = Field(default_factory=StateSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)


def default_config_path() -> Path:
    """Resolve the platform config path, honoring ``MISPFLEET_CONFIG``."""
    override = os.environ.get(ENV_CONFIG)
    if override:
        # No shell expands a variable set in a systemd unit or a .env file, so
        # "~/fleet.yml" created a directory literally named "~".
        return Path(override).expanduser()
    return platformdirs.user_config_path(APP_NAME) / "config.yml"


def default_state_path() -> Path:
    """Resolve the platform state path, honoring ``MISPFLEET_STATE_PATH``."""
    override = os.environ.get(ENV_STATE)
    if override:
        return Path(override).expanduser()
    return platformdirs.user_state_path(APP_NAME) / "state.db"


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` on top of ``base``."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InvalidConfigurationError(f"configuration file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        # A binary or non-UTF-8 file is a bad configuration, not a crash.
        raise InvalidConfigurationError(f"cannot read {path}: {error}") from error
    try:
        data = YAML(typ="safe").load(text)
    except YAMLError as error:
        raise InvalidConfigurationError(f"invalid YAML in {path}: {error}") from error
    except RecursionError as error:
        # A deeply nested document is a bad configuration, not a crash.
        raise InvalidConfigurationError(f"configuration in {path} is nested too deeply") from error
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise InvalidConfigurationError(f"configuration root must be a mapping: {path}")
    return dict(data)


def _apply_profile(data: dict[str, Any], profile: str | None) -> dict[str, Any]:
    profiles = data.pop("profiles", {}) or {}
    if profile is None:
        return data
    # A list or scalar here would make the lookup and the merge raise TypeError.
    if not isinstance(profiles, dict):
        raise InvalidConfigurationError(
            f"configuration section 'profiles' must be a mapping, got {type(profiles).__name__}"
        )
    if profile not in profiles:
        raise InvalidConfigurationError(f"unknown configuration profile {profile!r}")
    selected = profiles[profile]
    if not isinstance(selected, dict):
        raise InvalidConfigurationError(
            f"configuration profile {profile!r} must be a mapping, "
            f"got {type(selected).__name__}"
        )
    return _merge(data, dict(selected))


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    """Read one configuration section, rejecting non-mapping shapes.

    A YAML list where a mapping belongs must fail as a configuration error,
    not as an AttributeError escaping from the loader.
    """
    section = data.get(name) or {}
    if not isinstance(section, dict):
        raise InvalidConfigurationError(
            f"configuration section {name!r} must be a mapping, got {type(section).__name__}"
        )
    return dict(section)


def _build_servers(
    raw_servers: dict[str, Any],
    defaults: FleetDefaults,
) -> dict[str, ServerConfig]:
    servers: dict[str, ServerConfig] = {}
    seen_lower: set[str] = set()
    for name, entry in raw_servers.items():
        lowered = str(name).lower()
        if lowered in seen_lower:
            raise InvalidConfigurationError(f"duplicate server name {name!r}")
        seen_lower.add(lowered)
        if not isinstance(entry, dict):
            raise InvalidConfigurationError(f"server {name!r} must be a mapping")
        merged = {**defaults.model_dump(), **entry, "name": str(name)}
        try:
            servers[str(name)] = ServerConfig.model_validate(merged)
        except PydanticValidationError as error:
            raise InvalidConfigurationError(f"invalid server {name!r}: {error}") from error
    return servers


def load_fleet_config(path: Path | None = None, profile: str | None = None) -> FleetConfig:
    """Load and validate the fleet configuration file.

    Precedence: explicit arguments > environment > profile > file > defaults.
    """
    config_path = path or default_config_path()
    profile = profile or os.environ.get(ENV_PROFILE) or None
    data = _apply_profile(_read_yaml(config_path), profile)
    version = data.get("version", SUPPORTED_CONFIG_VERSION)
    if version != SUPPORTED_CONFIG_VERSION:
        raise InvalidConfigurationError(f"unsupported configuration version {version!r}")
    try:
        defaults = FleetDefaults.model_validate(data.get("defaults") or {})
        policies = {
            str(name): PolicySpec.model_validate(spec or {})
            for name, spec in _section(data, "policies").items()
        }
        state = StateSettings.model_validate(data.get("state") or {})
        security = SecuritySettings.model_validate(data.get("security") or {})
        sync_jobs = {
            str(name): SyncJobSpec.model_validate(spec or {})
            for name, spec in _section(data, "sync_jobs").items()
        }
    except PydanticValidationError as error:
        raise InvalidConfigurationError(str(error)) from error
    servers = _build_servers(_section(data, "servers"), defaults)
    if security.forbid_insecure_tls:
        insecure = sorted(name for name, server in servers.items() if not server.verify_tls)
        if insecure:
            raise InvalidConfigurationError(
                f"TLS verification is disabled for {insecure} but the configuration "
                "forbids insecure TLS (security.forbid_insecure_tls)"
            )
    return FleetConfig(
        version=version,
        defaults=defaults,
        servers=servers,
        policies=policies,
        sync_jobs=sync_jobs,
        state=state,
        security=security,
    )
