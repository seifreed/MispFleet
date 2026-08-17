"""Unit tests for configuration loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.settings import (
    ENV_CONFIG,
    ENV_STATE,
    FleetDefaults,
    StateSettings,
    default_config_path,
    default_state_path,
    load_fleet_config,
)
from tests.support import contains, eq, ok

VALID_CONFIG = """
version: 1
defaults:
  verify_tls: true
  request_timeout: 42
servers:
  production:
    url: https://misp.example
    credential:
      provider: env
      key: MISPFLEET_PRODUCTION_API_KEY
    role: primary
    groups: [internal, all]
  partner-cert:
    url: https://misp.partner.example
    credential:
      provider: env
      key: MISPFLEET_PARTNER_API_KEY
    read_only: true
    groups: [partners, all]
policies:
  production-import:
    remove_tags: [internal-only]
    add_tags: ["imported-by:mispfleet"]
    reject_if:
      tags: ["tlp:red"]
profiles:
  lab:
    defaults:
      request_timeout: 5
"""


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "config.yml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_valid_config_applies_defaults(tmp_path: Path) -> None:
    config = load_fleet_config(write_config(tmp_path, VALID_CONFIG))
    eq(sorted(config.servers), ["partner-cert", "production"])
    production = config.servers["production"]
    eq(production.request_timeout, 42.0)
    eq(production.concurrency, 5)
    ok(config.servers["partner-cert"].read_only)
    eq(config.policies["production-import"].reject_if.tags, {"tlp:red"})


def test_load_config_with_profile_overrides_defaults(tmp_path: Path) -> None:
    path = write_config(tmp_path, VALID_CONFIG)
    config = load_fleet_config(path, profile="lab")
    eq(config.servers["production"].request_timeout, 5.0)


def test_profile_can_come_from_environment(tmp_path: Path) -> None:
    path = write_config(tmp_path, VALID_CONFIG)
    os.environ["MISPFLEET_PROFILE"] = "lab"
    try:
        config = load_fleet_config(path)
        eq(config.servers["production"].request_timeout, 5.0)
    finally:
        del os.environ["MISPFLEET_PROFILE"]


def test_unknown_profile_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, VALID_CONFIG)
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path, profile="missing")
    contains(str(excinfo.value), "missing")


def test_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(tmp_path / "absent.yml")
    contains(str(excinfo.value), "not found")


def test_invalid_yaml_is_reported(tmp_path: Path) -> None:
    path = write_config(tmp_path, "servers: [unclosed")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "invalid YAML")


def test_non_mapping_root_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "mapping")


def test_empty_file_yields_empty_config(tmp_path: Path) -> None:
    config = load_fleet_config(write_config(tmp_path, ""))
    eq(config.servers, {})
    eq(config.defaults, FleetDefaults())


def test_unsupported_version_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "version: 99\n")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "99")


def test_case_insensitive_duplicate_server_names_are_rejected(tmp_path: Path) -> None:
    content = """
servers:
  production:
    url: https://a.example
    credential: {provider: env, key: A}
  PRODUCTION:
    url: https://b.example
    credential: {provider: env, key: B}
"""
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(write_config(tmp_path, content))
    contains(str(excinfo.value), "duplicate")


def test_invalid_server_entry_is_reported_with_name(tmp_path: Path) -> None:
    content = """
servers:
  broken:
    url: not-a-url
    credential: {provider: env, key: A}
"""
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(write_config(tmp_path, content))
    contains(str(excinfo.value), "broken")


def test_non_mapping_server_entry_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(write_config(tmp_path, "servers:\n  broken: 42\n"))
    contains(str(excinfo.value), "must be a mapping")


def test_invalid_defaults_are_reported(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigurationError):
        load_fleet_config(write_config(tmp_path, "defaults:\n  unexpected: true\n"))


def test_default_paths_honor_environment_overrides(tmp_path: Path) -> None:
    os.environ[ENV_CONFIG] = str(tmp_path / "override.yml")
    os.environ[ENV_STATE] = str(tmp_path / "override.db")
    try:
        eq(default_config_path(), tmp_path / "override.yml")
        eq(default_state_path(), tmp_path / "override.db")
    finally:
        del os.environ[ENV_CONFIG]
        del os.environ[ENV_STATE]
    contains(str(default_config_path()), "mispfleet")
    contains(str(default_state_path()), "mispfleet")


def test_config_written_with_a_utf8_bom_loads(tmp_path: Path) -> None:
    """PowerShell and Notepad write UTF-8 with a BOM by default on Windows."""
    path = tmp_path / "bom.yml"
    path.write_text(VALID_CONFIG, encoding="utf-8-sig")
    eq(sorted(load_fleet_config(path).servers), ["partner-cert", "production"])


def test_state_path_environment_override_outranks_the_configuration_file(
    tmp_path: Path,
) -> None:
    """Documented precedence puts the environment above the file.

    The file's ``state.path`` used to win outright, so the override was
    silently ignored and the configured database was opened instead.
    """
    from mispfleet.settings import StateSettings, build_state_backend

    from_file = tmp_path / "from-file.db"
    from_env = tmp_path / "from-env.db"
    settings = StateSettings(path=from_file)
    eq(build_state_backend(settings).location, str(from_file))
    os.environ[ENV_STATE] = str(from_env)
    try:
        eq(build_state_backend(settings).location, str(from_env))
    finally:
        del os.environ[ENV_STATE]


def test_non_mapping_sections_are_configuration_errors(tmp_path: Path) -> None:
    """A YAML list where a mapping belongs must exit 3, not crash the loader."""
    for section in ("servers", "policies", "sync_jobs"):
        path = tmp_path / f"{section}.yml"
        path.write_text(f"version: 1\n{section}: [oops]\n", encoding="utf-8")
        with pytest.raises(InvalidConfigurationError) as raised:
            load_fleet_config(path)
        contains(str(raised.value), f"{section!r} must be a mapping")


def test_binary_configuration_file_is_a_configuration_error(tmp_path: Path) -> None:
    """A non-UTF-8 file raised UnicodeDecodeError as a traceback with exit 1."""
    path = tmp_path / "binary.yml"
    path.write_bytes(b"\xff\xfe\x00binary garbage")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "cannot read")


def test_non_mapping_profiles_are_configuration_errors(tmp_path: Path) -> None:
    """profiles[name] raised TypeError on a list or a scalar."""
    listed = tmp_path / "listed.yml"
    listed.write_text("version: 1\nprofiles:\n  - prod\n", encoding="utf-8")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(listed, "prod")
    contains(str(excinfo.value), "'profiles' must be a mapping")
    scalar = tmp_path / "scalar.yml"
    scalar.write_text("version: 1\nprofiles:\n  prod: 3\n", encoding="utf-8")
    with pytest.raises(InvalidConfigurationError) as raised:
        load_fleet_config(scalar, "prod")
    contains(str(raised.value), "must be a mapping")


def test_deeply_nested_configuration_is_a_configuration_error(tmp_path: Path) -> None:
    """A pathological document escaped as RecursionError."""
    path = tmp_path / "deep.yml"
    depth = 6000
    path.write_text("version: 1\ndeep: " + "[" * depth + "]" * depth + "\n", encoding="utf-8")
    with pytest.raises(InvalidConfigurationError):
        load_fleet_config(path)


def test_home_relative_paths_are_expanded(tmp_path: Path) -> None:
    """Nothing expands "~" in a systemd unit or a .env file.

    An unexpanded override created a directory literally named "~" beside the
    working directory and put the database inside it.
    """
    previous = {key: os.environ.get(key) for key in ("MISPFLEET_CONFIG", "MISPFLEET_STATE_PATH")}
    os.environ["MISPFLEET_CONFIG"] = "~/fleet.yml"
    os.environ["MISPFLEET_STATE_PATH"] = "~/fleet.db"
    try:
        eq(default_config_path(), Path.home() / "fleet.yml")
        eq(default_state_path(), Path.home() / "fleet.db")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    eq(StateSettings(path=Path("~/state.db")).path, Path.home() / "state.db")
    eq(StateSettings().path, None)
