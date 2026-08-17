"""End-to-end CLI tests: every command runs against real local servers."""

from __future__ import annotations

import contextlib
import json
import os

# subprocess launches the built mispfleet CLI directly (no shell, argv as a
# list) to exercise real piped-stdout behaviour.
import subprocess  # nosec B404
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from mispfleet.cli.app import app
from tests.fake_misp import API_KEY, FakeMisp
from tests.fake_opencti import TOKEN as OPENCTI_TOKEN
from tests.fake_opencti import VERSION as OPENCTI_VERSION
from tests.fake_opencti import FakeOpenCTI
from tests.fake_taxii import COLLECTION_ID as TAXII_COLLECTION
from tests.fake_taxii import TOKEN as TAXII_TOKEN
from tests.fake_taxii import FakeTaxii
from tests.support import contains, eq, ne, not_contains, not_none, ok

EVENT_UUID = "9c5c1c2e-0000-4000-8000-00000000000e"
ENV_KEY = "MISPFLEET_CLI_TEST_KEY"

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        ENV_KEY: API_KEY,
        "MISPFLEET_STATE_PATH": str(tmp_path / "state" / "state.db"),
        "MISPFLEET_NO_COLOR": "1",
    }


@pytest.fixture
def cli_servers(tmp_path: Path) -> Iterator[tuple[Path, FakeMisp, FakeMisp]]:
    research = FakeMisp()
    production = FakeMisp()
    research.start()
    production.start()
    config = tmp_path / "config.yml"
    config.write_text(
        f"""
version: 1
servers:
  research:
    url: {research.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
    groups: [all, internal]
    role: research
  production:
    url: {production.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
    groups: [all]
    role: primary
policies:
  production-import:
    remove_tags: [internal-only]
    add_tags: ["imported-by:mispfleet"]
  strict:
    reject_if:
      tags: ["tlp:green"]
  clamp:
    maximum_distribution: community
""",
        encoding="utf-8",
    )
    yield config, research, production
    research.stop()
    production.stop()


def seed(server: FakeMisp, info: str = "Campaign X") -> None:
    server.add_event(
        {
            "id": "7",
            "uuid": EVENT_UUID,
            "info": info,
            "published": True,
            "Tag": [{"name": "internal-only"}, {"name": "tlp:green"}],
            "Attribute": [{"type": "domain", "value": "evil.example"}],
        }
    )
    server.attributes = [
        {
            "id": "1",
            "type": "domain",
            "value": "evil.example",
            "event_id": "7",
            "Event": {"uuid": EVENT_UUID, "info": info},
        }
    ]


def invoke(args: list[str], env: dict[str, str], config: Path | None = None) -> tuple[int, str]:
    full = ["--config", str(config), *args] if config is not None else args
    result = runner.invoke(app, full, env=env)
    return result.exit_code, result.stdout


def test_version_command_and_flag(env: dict[str, str]) -> None:
    code, output = invoke(["version"], env)
    eq(code, 0)
    contains(output, "0.1.0")
    code, output = invoke(["--version"], env)
    eq(code, 0)
    contains(output, "0.1.0")


def test_rejects_unknown_output_format(env: dict[str, str]) -> None:
    code, _ = invoke(["--format", "xml", "version"], env)
    eq(code, 2)


def test_config_lifecycle(tmp_path: Path, env: dict[str, str]) -> None:
    config = tmp_path / "config.yml"
    code, output = invoke(["config", "init"], env, config)
    eq(code, 0)
    eq(config.stat().st_mode & 0o777, 0o600)
    code, _ = invoke(["config", "init"], env, config)
    eq(code, 3)
    code, _ = invoke(["config", "init", "--force"], env, config)
    eq(code, 0)
    code, output = invoke(["config", "path"], env, config)
    eq(code, 0)
    contains(output, str(config))
    code, output = invoke(
        [
            "config",
            "add-server",
            "research",
            "--url",
            "https://misp.example",
            "--credential-key",
            ENV_KEY,
            "--groups",
            "all",
            "--role",
            "research",
            "--read-only",
        ],
        env,
        config,
    )
    eq(code, 0)
    code, _ = invoke(
        ["config", "add-server", "research", "--url", "https://x", "--credential-key", "K"],
        env,
        config,
    )
    eq(code, 3)
    code, output = invoke(["--format", "json", "config", "show"], env, config)
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["config"]["servers"]["research"]["credential"], "***REDACTED***")
    not_contains(output, API_KEY)
    code, output = invoke(["config", "validate"], env, config)
    eq(code, 0)
    code, _ = invoke(["config", "remove-server", "research"], env, config)
    eq(code, 0)
    code, _ = invoke(["config", "remove-server", "research"], env, config)
    eq(code, 3)


def test_config_init_to_an_unwritable_path_is_reported_cleanly(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """config init to a path under a regular file is a usage error, not a traceback.

    The mkdir/write_text ran unguarded outside run()/guard(), so an OSError
    escaped as exit 1 with a full traceback.
    """
    blocker = tmp_path / "afile"
    blocker.write_text("x", encoding="utf-8")
    target = blocker / "sub" / "config.yml"
    code, output = invoke(["config", "init"], env, target)
    eq(code, 2)
    not_contains(output, "Traceback")


def test_config_add_server_to_an_unwritable_path_is_reported_cleanly(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """add-server to a path under a regular file is a usage error, not a traceback.

    The mkdir/open/dump ran unguarded, so an OSError escaped as exit 1.
    """
    blocker = tmp_path / "afile"
    blocker.write_text("x", encoding="utf-8")
    target = blocker / "sub" / "config.yml"
    code, output = invoke(
        ["config", "add-server", "s", "--url", "https://x", "--credential-key", "K"], env, target
    )
    eq(code, 2)
    not_contains(output, "Traceback")


def test_config_validate_reports_problems(tmp_path: Path, env: dict[str, str]) -> None:
    config = tmp_path / "config.yml"
    config.write_text("servers: [broken", encoding="utf-8")
    code, _ = invoke(["config", "validate"], env, config)
    eq(code, 3)
    config.write_text(
        """
servers:
  a:
    url: https://a.example
    credential: {provider: env, key: MISPFLEET_DEFINITELY_MISSING_VAR}
  b:
    url: https://b.example
    credential: {provider: keyring, key: mispfleet-test-missing-entry}
""",
        encoding="utf-8",
    )
    code, output = invoke(["config", "validate"], env, config)
    eq(code, 0)
    contains(output, "MISPFLEET_DEFINITELY_MISSING_VAR")
    code, _ = invoke(["config", "remove-server", "missing"], env, tmp_path / "absent.yml")
    eq(code, 3)


def test_servers_commands(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _research, _production = cli_servers
    code, output = invoke(["servers", "list"], env, config)
    eq(code, 0)
    contains(output, "research")
    contains(output, "production")
    code, output = invoke(["--format", "json", "servers", "show", "research"], env, config)
    eq(code, 0)
    contains(output, "research")
    code, output = invoke(["servers", "health", "--all"], env, config)
    eq(code, 0)
    contains(output, "2.4.190")
    code, output = invoke(["servers", "test", "research"], env, config)
    eq(code, 0)
    code, output = invoke(["servers", "versions", "--all"], env, config)
    eq(code, 0)
    contains(output, "2.4.190")
    version_calls = len([s for s in _research.requests_seen if "getVersion" in s[1]])
    code, output = invoke(["--format", "yaml", "servers", "capabilities", "--all"], env, config)
    eq(code, 0)
    contains(output, "rest-search")
    eq(len([s for s in _research.requests_seen if "getVersion" in s[1]]), version_calls)
    code, output = invoke(["servers", "capabilities", "--all", "--refresh"], env, config)
    eq(code, 0)
    eq(len([s for s in _research.requests_seen if "getVersion" in s[1]]), version_calls + 1)
    code, output = invoke(
        ["servers", "templates", "diff", "--left", "research", "--right", "production"],
        env,
        config,
    )
    eq(code, 0)
    contains(output, "identical")


def test_servers_test_maps_failures_to_exit_codes(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, _production = cli_servers
    bad_env = dict(env)
    bad_env[ENV_KEY] = "wrong-key"
    code, _ = invoke(["servers", "test", "research"], bad_env, config)
    eq(code, 4)
    research.stop()
    code, _ = invoke(["--timeout", "1", "servers", "test", "research"], env, config)
    eq(code, 5)


def test_search_value_json_and_provenance(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    seed(research)
    seed(production)
    code, output = invoke(
        ["--format", "json", "search", "value", "evil.example", "--all"], env, config
    )
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["operation"], "federated-search")
    eq(payload["total_matches"], 2)
    eq({m["server"] for m in payload["matches"]}, {"research", "production"})
    not_contains(output, API_KEY)
    code, output = invoke(["search", "value", "evil.example", "--all"], env, config)
    eq(code, 0)
    contains(output, "evil.example")


def test_end_of_options_separator_protects_dash_leading_values(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    """Global-option hoisting rewrote arguments after ``--``.

    An indicator that happens to look like a flag was silently swallowed as
    the global selector, so the value could never be searched for at all.
    """
    config, _, _ = cli_servers
    code, _ = invoke(["search", "value", "--all", "--", "--all"], env, config)
    eq(code, 11)


def test_search_no_matches_exits_11(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _, _ = cli_servers
    code, _ = invoke(["search", "value", "nothing.example", "--all"], env, config)
    eq(code, 11)


def test_search_partial_failure_exits_6_with_valid_json(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    seed(research)
    production.stop()
    code, output = invoke(
        ["--format", "json", "--timeout", "1", "search", "value", "evil.example", "--all"],
        env,
        config,
    )
    eq(code, 6)
    payload = json.loads(output)
    eq(payload["partial"], True)
    contains(payload["failed_servers"], "production")


def test_search_sightings_across_fleet(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, _production = cli_servers
    seed(research)
    research.sightings = [
        {
            "id": "1",
            "attribute_uuid": research.attributes[0].get("uuid"),
            "event_id": "7",
            "type": "0",
            "date_sighting": "1754500000",
            "Organisation": {"name": "CERT-A"},
        }
    ]
    code, output = invoke(["search", "sightings", "evil.example", "--all"], env, config)
    eq(code, 0)
    contains(output, "research")
    contains(output, "CERT-A")
    code, _ = invoke(["search", "sightings", "absent.example", "--all"], env, config)
    eq(code, 11)
    _production.stop()
    code, output = invoke(
        ["--timeout", "1", "search", "sightings", "evil.example", "--all"], env, config
    )
    eq(code, 6)
    contains(output, "failed")


def test_sightings_push_across_fleet(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    seed(research)
    code, output = invoke(
        ["sightings", "push", "evil.example", "--source", "soc", "--all"], env, config
    )
    eq(code, 0)
    contains(output, "research: 1 sighting(s)")
    eq(research.sightings[0]["type"], "0")
    code, _ = invoke(["sightings", "push", "absent.example", "--all"], env, config)
    eq(code, 11)
    code, _ = invoke(["sightings", "push", "evil.example"], env, config)
    eq(code, 2)
    production.stop()
    code, output = invoke(
        ["--timeout", "1", "sightings", "push", "evil.example", "--all"], env, config
    )
    eq(code, 6)
    contains(output, "failed")


def test_jsonl_format_stays_line_delimited_for_every_command(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _research, _production = cli_servers
    code, output = invoke(["--format", "jsonl", "servers", "health", "--all"], env, config)
    eq(code, 0)
    lines = [line for line in output.splitlines() if line.strip()]
    eq(len(lines), 1)
    payload = json.loads(lines[0])
    eq(payload["operation"], "fleet-health")


def test_servers_audit_detects_drift_and_consistency(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    research.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": True, "version": "9"}]
    production.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": True, "version": "7"}]
    code, output = invoke(["servers", "audit", "--all"], env, config)
    eq(code, 9)
    contains(output, "tlp")
    production.taxonomies[0]["version"] = "9"
    code, output = invoke(["--format", "json", "servers", "audit", "--all"], env, config)
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["findings"], [])
    code, output = invoke(["servers", "audit", "--all"], env, config)
    eq(code, 0)
    contains(output, "consistent")
    production.stop()
    code, output = invoke(["--timeout", "1", "servers", "audit", "--all"], env, config)
    eq(code, 6)
    contains(output, "failed")


def test_servers_remediation_commands(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    research.warninglists = [{"id": "1", "name": "rfc5735", "enabled": False}]
    production.warninglists = [{"id": "2", "name": "rfc5735", "enabled": False}]
    research.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": False}]
    production.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": False}]
    code, output = invoke(["servers", "update-libraries", "--all"], env, config)
    eq(code, 0)
    contains(output, "taxonomies")
    code, _ = invoke(["servers", "update-libraries"], env, config)
    eq(code, 2)
    code, output = invoke(["servers", "enable-warninglist", "rfc5735", "--all"], env, config)
    eq(code, 0)
    ok(research.warninglists[0]["enabled"])
    ok(production.warninglists[0]["enabled"])
    code, _ = invoke(["servers", "enable-taxonomy", "tlp", "--all"], env, config)
    eq(code, 0)
    ok(research.taxonomies[0]["enabled"])
    code, _ = invoke(
        ["servers", "enable-taxonomy", "tlp", "--disable", "--server", "research"], env, config
    )
    eq(code, 0)
    ok(not research.taxonomies[0]["enabled"])
    ok(production.taxonomies[0]["enabled"])
    code, output = invoke(["servers", "enable-warninglist", "absent", "--all"], env, config)
    eq(code, 6)
    contains(output, "failed")


def test_health_with_a_down_server_exits_6(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _research, production = cli_servers
    production.stop()
    code, output = invoke(
        ["--timeout", "1", "servers", "health", "--all"],
        env,
        config,
    )
    eq(code, 6)
    contains(output, "research")


def test_search_events_attributes_and_jsonl_output(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, research, production = cli_servers
    seed(research)
    seed(production)
    code, output = invoke(
        ["--format", "jsonl", "search", "attributes", "--type", "domain", "--since", "30d"],
        env,
        config,
    )
    eq(code, 0)
    lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    eq(len(lines), 2)
    out_file = tmp_path / "hashes.jsonl"
    code, _ = invoke(
        ["--format", "jsonl", "--output", str(out_file), "search", "value", "evil.example"],
        env,
        config,
    )
    eq(code, 0)
    ok(out_file.exists())
    code, output = invoke(
        ["--format", "json", "search", "events", "--info", "Campaign", "--since", "30d"],
        env,
        config,
    )
    eq(code, 0)
    code, _ = invoke(["search", "events", "--since", "bogus"], env, config)
    eq(code, 2)


def test_attribute_get_and_streaming_search(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, research, production = cli_servers
    seed(research)
    seed(production)
    attribute_uuid = "1f2b8a1e-0000-4000-8000-000000000001"
    research.attributes[0]["uuid"] = attribute_uuid
    code, output = invoke(["--server", "research", "attribute", "get", attribute_uuid], env, config)
    eq(code, 0)
    contains(output, "evil.example")
    code, _ = invoke(["attribute", "get", attribute_uuid], env, config)
    eq(code, 2)
    code, output = invoke(["attribute", "search", "--type", "domain", "--all"], env, config)
    eq(code, 0)
    lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    eq(len(lines), 2)
    eq({line["server"] for line in lines}, {"research", "production"})
    out_file = tmp_path / "attributes.jsonl"
    code, _ = invoke(
        ["--output", str(out_file), "attribute", "search", "--type", "domain", "--all"],
        env,
        config,
    )
    eq(code, 0)
    eq(len(out_file.read_text(encoding="utf-8").splitlines()), 2)
    code, _ = invoke(["attribute", "search", "--type", "missing-type", "--all"], env, config)
    eq(code, 11)


def test_attribute_download_saves_attachment(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, research, _production = cli_servers
    seed(research)
    attribute_uuid = "1f2b8a1e-0000-4000-8000-000000000001"
    research.attributes[0]["uuid"] = attribute_uuid
    downloads = tmp_path / "downloads"
    code, _ = invoke(
        [
            "--server",
            "research",
            "attribute",
            "get",
            attribute_uuid,
            "--download",
            str(downloads),
        ],
        env,
        config,
    )
    eq(code, 11)
    research.attributes[0]["type"] = "attachment"
    research.attributes[0]["value"] = "../evil/dropper.bin|deadbeef"
    research.attributes[0]["data"] = "bWFsd2FyZQ=="
    code, _ = invoke(
        [
            "--server",
            "research",
            "attribute",
            "get",
            attribute_uuid,
            "--download",
            str(downloads),
        ],
        env,
        config,
    )
    eq(code, 0)
    eq((downloads / "dropper.bin").read_bytes(), b"malware")
    code, _ = invoke(
        [
            "--server",
            "research",
            "attribute",
            "get",
            attribute_uuid,
            "--download",
            str(downloads),
        ],
        env,
        config,
    )
    eq(code, 13)


def test_no_verify_tls_flag_warns_and_overrides(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _research, _production = cli_servers
    result = runner.invoke(
        app, ["--config", str(config), "--no-verify-tls", "servers", "list"], env=env
    )
    eq(result.exit_code, 0)
    contains(result.stderr, "TLS certificate verification is DISABLED")


def test_forbid_insecure_tls_blocks_config_and_flag(tmp_path: Path, env: dict[str, str]) -> None:
    config = tmp_path / "config.yml"
    config.write_text(
        f"""
version: 1
security:
  forbid_insecure_tls: true
servers:
  research:
    url: https://misp.example
    credential: {{provider: env, key: {ENV_KEY}}}
    verify_tls: false
""",
        encoding="utf-8",
    )
    code, _ = invoke(["servers", "list"], env, config)
    eq(code, 3)
    config.write_text(
        f"""
version: 1
security:
  forbid_insecure_tls: true
servers:
  research:
    url: https://misp.example
    credential: {{provider: env, key: {ENV_KEY}}}
""",
        encoding="utf-8",
    )
    code, _ = invoke(["servers", "list"], env, config)
    eq(code, 0)
    code, _ = invoke(["--no-verify-tls", "servers", "list"], env, config)
    eq(code, 3)


def test_completion_scripts(env: dict[str, str]) -> None:
    code, output = invoke(["completion", "zsh"], env)
    eq(code, 0)
    contains(output, "#compdef mispfleet")
    code, output = invoke(["completion", "bash"], env)
    eq(code, 0)
    contains(output, "_mispfleet_completion")
    code, _ = invoke(["completion", "tcsh"], env)
    eq(code, 2)


def test_search_extended_filters_reach_server(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, _production = cli_servers
    seed(research)
    research.attributes[0]["org"] = "CIRCL"
    # restSearch ignores `analysis` and `distribution`, so the fleet applies
    # them locally: the event has to carry the values the search asks for.
    research.attributes[0]["Event"]["distribution"] = "1"
    research.attributes[0]["Event"]["analysis"] = "1"
    code, _ = invoke(
        [
            "--server",
            "research",
            "search",
            "attributes",
            "--org",
            "CIRCL",
            "--distribution",
            "1",
            "--timestamp-since",
            "30d",
            "--timestamp-until",
            "1d",
        ],
        env,
        config,
    )
    eq(code, 0)
    body = research.search_bodies[-1]
    eq(body["org"], ["CIRCL"])
    not_contains(body, "object_name")
    eq(body["distribution"], "1")
    eq(len(body["timestamp"]), 2)
    code, _ = invoke(
        [
            "--server",
            "research",
            "search",
            "events",
            "--info",
            "Campaign",
            "--org",
            "CIRCL",
            "--threat-level",
            "2",
            "--analysis",
            "1",
            "--distribution",
            "1",
        ],
        env,
        config,
    )
    eq(code, 0)


def test_event_get_find_diff_export_validate(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, research, production = cli_servers
    seed(research)
    seed(production, info="Campaign X (edited)")
    code, output = invoke(
        ["--format", "json", "event", "get", EVENT_UUID, "--server", "research"], env, config
    )
    eq(code, 0)
    contains(output, "Campaign X")
    code, output = invoke(["event", "find", EVENT_UUID, "--all"], env, config)
    eq(code, 0)
    contains(output, "found research")
    code, _ = invoke(["event", "find", "missing-uuid", "--all"], env, config)
    eq(code, 11)
    code, output = invoke(
        ["event", "diff", EVENT_UUID, "--left", "research", "--right", "production"], env, config
    )
    eq(code, 0)
    contains(output, "change")
    code, output = invoke(
        [
            "--format",
            "patch",
            "event",
            "diff",
            EVENT_UUID,
            "--left",
            "research",
            "--right",
            "production",
        ],
        env,
        config,
    )
    eq(code, 0)
    contains(output, f"--- research/{EVENT_UUID}")
    contains(output, "~ info:")
    code, _ = invoke(["--format", "patch", "servers", "list"], env, config)
    eq(code, 2)
    code, output = invoke(
        ["--format", "yaml", "event", "export", EVENT_UUID, "--server", "research"], env, config
    )
    eq(code, 0)
    contains(output, EVENT_UUID)
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps({"Event": {"uuid": EVENT_UUID, "info": "Local"}}), encoding="utf-8"
    )
    code, output = invoke(["event", "validate", str(event_file)], env, config)
    eq(code, 0)
    contains(output, "valid")
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not json", encoding="utf-8")
    code, _ = invoke(["event", "validate", str(bad_file)], env, config)
    eq(code, 2)


def test_event_copy_dry_run_plan_file_and_apply(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, research, production = cli_servers
    seed(research)
    code, output = invoke(
        [
            "event",
            "copy",
            EVENT_UUID,
            "--from",
            "research",
            "--to",
            "production",
            "--policy",
            "production-import",
            "--dry-run",
        ],
        env,
        config,
    )
    eq(code, 0)
    contains(output, "add-tag")
    eq(production.events, {})
    plan_file = tmp_path / "copy-plan.json"
    code, _ = invoke(
        [
            "event",
            "copy",
            EVENT_UUID,
            "--from",
            "research",
            "--to",
            "production",
            "--policy",
            "production-import",
            "--plan-output",
            str(plan_file),
        ],
        env,
        config,
    )
    eq(code, 0)
    ok(plan_file.exists())
    not_contains(plan_file.read_text(encoding="utf-8"), API_KEY)
    code, output = invoke(["apply", str(plan_file)], env, config)
    eq(code, 0)
    contains(production.events, EVENT_UUID)
    code, _ = invoke(["apply", str(tmp_path / "missing-plan.json")], env, config)
    eq(code, 2)


def test_event_copy_plan_subcommand_writes_plan_without_mutating(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, research, production = cli_servers
    seed(research)
    code, output = invoke(
        ["event", "copy", "plan", EVENT_UUID, "--from", "research", "--to", "production"],
        env,
        config,
    )
    eq(code, 0)
    contains(output, EVENT_UUID)
    eq(production.events, {})
    plan_file = tmp_path / "copy-plan.json"
    code, _ = invoke(
        [
            "--output",
            str(plan_file),
            "event",
            "copy",
            "plan",
            EVENT_UUID,
            "--from",
            "research",
            "--to",
            "production",
            "--policy",
            "production-import",
        ],
        env,
        config,
    )
    eq(code, 0)
    ok(plan_file.exists())
    eq(production.events, {})
    not_contains(plan_file.read_text(encoding="utf-8"), API_KEY)
    code, _ = invoke(["apply", str(plan_file)], env, config)
    eq(code, 0)
    contains(production.events, EVENT_UUID)


def test_event_copy_plan_reports_policy_rejection(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    seed(research)
    code, _ = invoke(
        [
            "event",
            "copy",
            "plan",
            EVENT_UUID,
            "--from",
            "research",
            "--to",
            "production",
            "--policy",
            "strict",
        ],
        env,
        config,
    )
    eq(code, 7)
    eq(production.events, {})


def test_root_health_matches_servers_health(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _research, _production = cli_servers
    root_code, root_output = invoke(["--format", "json", "health", "--all"], env, config)
    nested_code, nested_output = invoke(
        ["--format", "json", "servers", "health", "--all"], env, config
    )
    eq(root_code, 0)
    eq(nested_code, 0)
    eq(json.loads(root_output)["operation"], json.loads(nested_output)["operation"])


def test_event_copy_immediate_apply_and_policy_rejection(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    seed(research)
    code, _ = invoke(
        [
            "--format",
            "json",
            "event",
            "copy",
            EVENT_UUID,
            "--from",
            "research",
            "--to",
            "production",
            "--policy",
            "strict",
        ],
        env,
        config,
    )
    eq(code, 7)
    eq(production.events, {})
    code, _ = invoke(
        ["event", "copy", EVENT_UUID, "--from", "research", "--to", "production"],
        env,
        config,
    )
    eq(code, 0)
    contains(production.events, EVENT_UUID)
    code, _ = invoke(
        ["event", "copy", EVENT_UUID, "--from", "research", "--to", "production"],
        env,
        config,
    )
    eq(code, 8)


def test_policy_commands(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, _, _ = cli_servers
    code, output = invoke(["policy", "list"], env, config)
    eq(code, 0)
    contains(output, "production-import")
    code, output = invoke(["--format", "json", "policy", "show", "production-import"], env, config)
    eq(code, 0)
    contains(output, "imported-by:mispfleet")
    code, output = invoke(["policy", "validate", "production-import"], env, config)
    eq(code, 0)
    code, _ = invoke(["policy", "show", "ghost"], env, config)
    eq(code, 3)
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps(
            {
                "Event": {
                    "uuid": EVENT_UUID,
                    "info": "Local",
                    "Tag": [{"name": "tlp:green"}, {"name": "internal-only"}],
                }
            }
        ),
        encoding="utf-8",
    )
    code, output = invoke(["policy", "test", "production-import", str(event_file)], env, config)
    eq(code, 0)
    contains(output, "accepted: True")
    code, output = invoke(["policy", "test", "strict", str(event_file)], env, config)
    eq(code, 7)
    contains(output, "violation")
    code, output = invoke(["policy", "test", "clamp", str(event_file)], env, config)
    eq(code, 0)
    contains(output, "warning")
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    code, _ = invoke(["policy", "test", "strict", str(bad)], env, config)
    eq(code, 2)


def test_state_commands(cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]) -> None:
    config, research, _production = cli_servers
    seed(research)
    code, _ = invoke(
        ["event", "copy", EVENT_UUID, "--from", "research", "--to", "production"], env, config
    )
    eq(code, 0)
    code, output = invoke(["state", "info"], env, config)
    eq(code, 0)
    contains(output, "1 operation(s)")
    code, output = invoke(["--format", "json", "state", "operations"], env, config)
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["operations"][0]["result"], "applied")
    code, output = invoke(["state", "operations"], env, config)
    eq(code, 0)
    contains(output, "research->production")
    code, output = invoke(["state", "checkpoints"], env, config)
    eq(code, 0)
    code, output = invoke(["state", "prune", "--older-than", "30d"], env, config)
    eq(code, 0)
    contains(output, "removed 0")


def test_state_checkpoint_commands(
    env: dict[str, str], tmp_path: Path, cli_servers: tuple[Path, FakeMisp, FakeMisp]
) -> None:
    import asyncio
    from datetime import UTC, datetime
    from uuid import uuid4

    from mispfleet.state.base import Checkpoint
    from mispfleet.state.sqlite import SqliteStateBackend

    config, _, _ = cli_servers
    state_path = Path(env["MISPFLEET_STATE_PATH"])
    checkpoint = Checkpoint(
        checkpoint_id=uuid4(),
        operation_type="attribute-search",
        query_fingerprint="fp",
        server="research",
        page=2,
        created_at=datetime.now(tz=UTC),
        updated_at=datetime.now(tz=UTC),
        client_version="0.1.0",
    )

    async def store() -> None:
        backend = SqliteStateBackend(state_path)
        await backend.initialize()
        await backend.save_checkpoint(checkpoint)
        await backend.close()

    asyncio.run(store())
    code, output = invoke(["state", "checkpoints"], env, config)
    eq(code, 0)
    contains(output, str(checkpoint.checkpoint_id))
    code, output = invoke(
        ["--format", "json", "state", "checkpoint", "show", str(checkpoint.checkpoint_id)],
        env,
        config,
    )
    eq(code, 0)
    contains(output, "fp")
    code, output = invoke(
        ["state", "checkpoint", "delete", str(checkpoint.checkpoint_id)], env, config
    )
    eq(code, 0)
    code, _ = invoke(["state", "checkpoint", "show", str(checkpoint.checkpoint_id)], env, config)
    eq(code, 1)


def test_malformed_checkpoint_id_is_a_usage_error(
    env: dict[str, str], cli_servers: tuple[Path, FakeMisp, FakeMisp]
) -> None:
    """UUID() raised ValueError inside the coroutine: traceback and exit 1."""
    config, _, _ = cli_servers
    for command in ("show", "delete"):
        code, _ = invoke(["state", "checkpoint", command, "not-a-uuid"], env, config)
        eq(code, 2)


def test_invalid_log_level_is_a_usage_error(env: dict[str, str]) -> None:
    """logger.setLevel raised ValueError for anything off the logging table."""
    code, _ = invoke(["--log-level", "banana", "version"], env)
    eq(code, 2)


def test_invalid_log_format_is_a_usage_error(env: dict[str, str]) -> None:
    """Unvalidated, anything but "json" silently fell back to text output."""
    for value in ("banana", "JSON", "jsonl"):
        code, _ = invoke(["--log-format", value, "version"], env)
        eq(code, 2)


def test_plugins_list(env: dict[str, str]) -> None:
    code, output = invoke(["plugins", "list"], env)
    eq(code, 0)
    contains(output, "no plugins installed")


def test_plugins_list_persists_metadata_when_configured(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _research, _production = cli_servers
    code, _ = invoke(["plugins", "list"], env, config)
    eq(code, 0)
    code, output = invoke(["--format", "json", "state", "info"], env, config)
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["operation"], "state-info")
    eq(payload["plugins"], 0)
    eq(payload["plans"], 0)
    eq(payload["queries"], 0)


def test_config_add_server_creates_file_and_minimal_entry(
    tmp_path: Path, env: dict[str, str]
) -> None:
    config = tmp_path / "fresh.yml"
    code, _ = invoke(
        ["config", "add-server", "minimal", "--url", "https://m.example", "--credential-key", "K"],
        env,
        config,
    )
    eq(code, 0)
    content = config.read_text(encoding="utf-8")
    contains(content, "minimal")
    not_contains(content, "groups")
    not_contains(content, "read_only")


def test_event_get_requires_exactly_one_server(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _, _ = cli_servers
    code, _ = invoke(["event", "get", EVENT_UUID], env, config)
    eq(code, 2)
    code, _ = invoke(
        ["event", "get", EVENT_UUID, "--server", "research", "--server", "production"],
        env,
        config,
    )
    eq(code, 2)


def test_servers_versions_and_capabilities_report_failed_servers(
    tmp_path: Path, env: dict[str, str], cli_servers: tuple[Path, FakeMisp, FakeMisp]
) -> None:
    _config, research, _production = cli_servers
    config = tmp_path / "mixed.yml"
    config.write_text(
        f"""
version: 1
servers:
  research:
    url: {research.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
  broken:
    url: https://broken.example
    credential: {{provider: env, key: MISPFLEET_DEFINITELY_MISSING_VAR}}
""",
        encoding="utf-8",
    )
    code, output = invoke(["servers", "capabilities", "--all"], env, config)
    eq(code, 6)
    contains(output, "unavailable")
    code, output = invoke(["servers", "versions", "--all"], env, config)
    eq(code, 6)
    contains(output, "unavailable")


def test_templates_diff_reports_asymmetries(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, research, production = cli_servers
    research.templates = [{"ObjectTemplate": {"name": "file"}}, {"name": "network"}]
    production.templates = [
        {"ObjectTemplate": {"name": "file"}},
        {"ObjectTemplate": {"name": "prod-only"}},
        {"not-a-template": True},
    ]
    code, output = invoke(
        ["servers", "templates", "diff", "--left", "research", "--right", "production"],
        env,
        config,
    )
    eq(code, 0)
    contains(output, "only on research: network")
    contains(output, "only on production: prod-only")


@pytest.fixture
def sync_config(tmp_path: Path) -> Iterator[tuple[Path, FakeMisp, FakeMisp]]:
    left = FakeMisp()
    right = FakeMisp()
    left.start()
    right.start()
    config = tmp_path / "sync-config.yml"
    config.write_text(
        f"""
version: 1
servers:
  left:
    url: {left.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
  right:
    url: {right.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
policies:
  reject-all:
    reject_if:
      tags: ["sync:me"]
sync_jobs:
  mirror:
    left: left
    right: right
    on_conflict: newer-wins
  blocked:
    left: left
    right: right
    direction: push
    policy_left_to_right: reject-all
""",
        encoding="utf-8",
    )
    yield config, left, right
    left.stop()
    right.stop()


def seed_sync_event(server: FakeMisp, uuid: str, info: str, timestamp: str) -> None:
    server.add_event(
        {
            "uuid": uuid,
            "info": info,
            "timestamp": timestamp,
            "Tag": [{"name": "sync:me"}],
            "Attribute": [{"type": "domain", "value": "sync.example"}],
        }
    )


def test_sync_cli_list_plan_and_run(
    sync_config: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    config, left, right = sync_config
    seed_sync_event(left, "44444444-0000-4000-8000-000000000004", "Left only", "100")
    code, output = invoke(["sync", "list"], env, config)
    eq(code, 0)
    contains(output, "mirror")
    contains(output, "newer-wins")
    plan_file = tmp_path / "sync-plan.json"
    code, output = invoke(["sync", "plan", "mirror", "--plan-output", str(plan_file)], env, config)
    eq(code, 0)
    ok(plan_file.exists())
    not_contains(plan_file.read_text(encoding="utf-8"), API_KEY)
    contains(output, "left -> right")
    eq(right.events, {})
    code, output = invoke(["sync", "run", "mirror", "--dry-run"], env, config)
    eq(code, 0)
    eq(right.events, {})
    code, output = invoke(["--format", "json", "sync", "run", "mirror"], env, config)
    eq(code, 0)
    contains(right.events, "44444444-0000-4000-8000-000000000004")
    code, output = invoke(["sync", "run", "mirror"], env, config)
    eq(code, 0)
    code, _ = invoke(["sync", "plan", "ghost"], env, config)
    eq(code, 3)


def test_plan_output_to_an_unwritable_path_is_reported_cleanly(
    sync_config: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """--plan-output to a missing directory is a usage error, not a traceback.

    emit() already typed this for --output; the plan-writing commands wrote
    the file directly and let the raw OSError escape as exit 1.
    """
    config, left, _ = sync_config
    seed_sync_event(left, "77777777-0000-4000-8000-000000000007", "Left only", "100")
    target = tmp_path / "missing-dir" / "plan.json"
    code, output = invoke(["sync", "plan", "mirror", "--plan-output", str(target)], env, config)
    eq(code, 2)
    not_contains(output, "Traceback")


def test_sync_cli_conflicts_blocked_and_partial_failures(
    sync_config: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, left, right = sync_config
    seed_sync_event(left, "55555555-0000-4000-8000-000000000005", "Left version", "300")
    seed_sync_event(right, "55555555-0000-4000-8000-000000000005", "Right version", "100")
    seed_sync_event(right, "66666666-0000-4000-8000-000000000006", "Right only", "100")
    code, output = invoke(["sync", "plan", "mirror"], env, config)
    eq(code, 0)
    contains(output, "conflict")
    contains(output, "right -> left")
    seed_sync_event(left, "77777777-0000-4000-8000-000000000007", "Rejected event", "100")
    code, output = invoke(["sync", "run", "blocked", "--dry-run"], env, config)
    eq(code, 8)
    contains(output, "blocking errors")
    # A blocked plan is refused before anything is applied, exactly like
    # 'event copy'. Applying it mutated the unblocked copies and reduced the
    # blocking error to a generic per-event failure string.
    code, output = invoke(["sync", "run", "blocked"], env, config)
    eq(code, 8)
    contains(output, "blocking errors")


def test_sync_cli_empty_job_list(env: dict[str, str], tmp_path: Path) -> None:
    config = tmp_path / "no-jobs.yml"
    config.write_text("version: 1\nservers: {}\n", encoding="utf-8")
    code, output = invoke(["sync", "list"], env, config)
    eq(code, 0)
    contains(output, "no sync jobs configured")


@pytest.fixture
def taxii_server() -> Iterator[FakeTaxii]:
    server = FakeTaxii()
    server.start()
    yield server
    server.stop()


def test_stix_export_and_taxii_push(
    cli_servers: tuple[Path, FakeMisp, FakeMisp],
    env: dict[str, str],
    taxii_server: FakeTaxii,
) -> None:
    config, research, _production = cli_servers
    research.add_event(
        {
            "uuid": EVENT_UUID,
            "info": "Campaign X",
            "timestamp": "1700000000",
            "Tag": [{"name": "tlp:green"}],
            "Attribute": [
                {"type": "domain", "value": "evil.example"},
                {"type": "passport-number", "value": "X123"},
            ],
        }
    )
    code, output = invoke(
        ["--server", "research", "--format", "json", "stix", "export", EVENT_UUID], env, config
    )
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["bundle"]["type"], "bundle")
    contains(payload["skipped"], "passport-number")
    code, output = invoke(["--server", "research", "stix", "export", EVENT_UUID], env, config)
    eq(code, 0)
    contains(output, "skipped")
    push_env = dict(env)
    push_env["MISPFLEET_TAXII_TOKEN"] = TAXII_TOKEN
    code, output = invoke(
        [
            "--server",
            "research",
            "stix",
            "push",
            EVENT_UUID,
            "--taxii-url",
            taxii_server.url,
            "--collection",
            TAXII_COLLECTION,
            "--credential-key",
            "MISPFLEET_TAXII_TOKEN",
        ],
        push_env,
        config,
    )
    eq(code, 0)
    contains(output, "pushed")
    ok(len(taxii_server.pushed) >= 1)


def test_stix_export_requires_exactly_one_server(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _, _ = cli_servers
    code, _ = invoke(["stix", "export", EVENT_UUID], env, config)
    eq(code, 2)


@pytest.fixture
def opencti_server() -> Iterator[FakeOpenCTI]:
    server = FakeOpenCTI()
    server.start()
    yield server
    server.stop()


def test_opencti_test_and_push(
    cli_servers: tuple[Path, FakeMisp, FakeMisp],
    env: dict[str, str],
    opencti_server: FakeOpenCTI,
) -> None:
    config, research, _production = cli_servers
    research.add_event(
        {
            "uuid": EVENT_UUID,
            "info": "Campaign X",
            "timestamp": "1700000000",
            "Tag": [{"name": "tlp:green"}],
            "Attribute": [{"type": "domain", "value": "evil.example"}],
        }
    )
    octi_env = dict(env)
    octi_env["MISPFLEET_OPENCTI_TOKEN"] = OPENCTI_TOKEN
    code, output = invoke(
        [
            "opencti",
            "test",
            "--opencti-url",
            opencti_server.url,
            "--credential-key",
            "MISPFLEET_OPENCTI_TOKEN",
        ],
        octi_env,
        config,
    )
    eq(code, 0)
    contains(output, OPENCTI_VERSION)
    code, output = invoke(
        [
            "--server",
            "research",
            "--format",
            "json",
            "opencti",
            "push",
            EVENT_UUID,
            "--opencti-url",
            opencti_server.url,
            "--credential-key",
            "MISPFLEET_OPENCTI_TOKEN",
        ],
        octi_env,
        config,
    )
    eq(code, 0)
    payload = json.loads(output)
    eq(payload["work_id"], "work-1")
    eq(len(opencti_server.pushed), 1)


def test_opencti_push_requires_one_server(
    cli_servers: tuple[Path, FakeMisp, FakeMisp],
    env: dict[str, str],
    opencti_server: FakeOpenCTI,
) -> None:
    config, _, _ = cli_servers
    octi_env = dict(env)
    octi_env["MISPFLEET_OPENCTI_TOKEN"] = OPENCTI_TOKEN
    code, _ = invoke(
        [
            "opencti",
            "push",
            EVENT_UUID,
            "--opencti-url",
            opencti_server.url,
            "--credential-key",
            "MISPFLEET_OPENCTI_TOKEN",
        ],
        octi_env,
        config,
    )
    eq(code, 2)


def test_invalid_timeout_and_concurrency_are_usage_errors(
    env: dict[str, str], cli_servers: tuple[Path, FakeMisp, FakeMisp]
) -> None:
    """The overrides are applied with model_copy(update=), which skips validation.

    A concurrency of 0 built an asyncio.Semaphore nothing could ever acquire,
    so every request hung forever instead of failing.
    """
    config, _, _ = cli_servers
    for flag, value in (
        ("--timeout", "-5"),
        ("--timeout", "0"),
        ("--concurrency", "0"),
        ("--concurrency", "-3"),
    ):
        code, _ = invoke([flag, value, "servers", "list"], env, config)
        eq(code, 2)
    code, _ = invoke(["--timeout", "5", "--concurrency", "2", "servers", "list"], env, config)
    eq(code, 0)


def test_servers_test_reports_an_unresolvable_credential_cleanly(
    env: dict[str, str], tmp_path: Path
) -> None:
    """A failure before the probe is a server error, never a health result.

    Indexing results[name] for it raised KeyError as a raw traceback with
    exit 1, while `servers health` on the same config reported it properly.
    """
    config = tmp_path / "no-credential.yml"
    config.write_text(
        """
version: 1
servers:
  prod:
    url: http://127.0.0.1:9
    credential: {provider: env, key: MISPFLEET_DEFINITELY_MISSING_VAR}
    allow_insecure_http: true
""",
        encoding="utf-8",
    )
    code, output = invoke(["--non-interactive", "servers", "test", "prod"], env, config)
    eq(code, 5)
    contains(output, "prod")


def test_add_server_keeps_its_own_role_and_refuses_invalid_entries(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """A subcommand's own option must not be stolen by the global hoister.

    --role was hoisted into the global server selector, so add-server silently
    wrote the default role, and no value was ever validated.
    """
    config = tmp_path / "added.yml"
    config.write_text("version: 1\nservers: {}\n", encoding="utf-8")
    base = [
        "config",
        "add-server",
        "beta",
        "--url",
        "https://beta.example",
        "--credential-key",
        "K",
    ]

    code, _ = invoke([*base, "--role", "research"], env, config)
    eq(code, 0)
    contains(config.read_text(encoding="utf-8"), "role: research")

    code, _ = invoke(
        [
            "config",
            "add-server",
            "gamma",
            "--url",
            "https://g.example",
            "--credential-key",
            "K",
            "--role",
            "not-a-role",
        ],
        env,
        config,
    )
    eq(code, 2)
    code, _ = invoke(
        ["config", "add-server", "delta", "--url", "not a url", "--credential-key", "K"],
        env,
        config,
    )
    eq(code, 2)
    not_contains(config.read_text(encoding="utf-8"), "delta")


def test_unusable_option_values_are_usage_errors_not_tracebacks(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    config, _, _ = cli_servers
    eq(invoke(["--role", "bogus", "health"], env, config)[0], 2)
    eq(invoke(["search", "value", "x", "--limit", "-1"], env, config)[0], 2)
    eq(invoke(["--timeout", "nan", "servers", "list"], env, config)[0], 2)
    eq(invoke(["--timeout", "inf", "servers", "list"], env, config)[0], 2)
    eq(invoke(["state", "prune", "--older-than", "5000000d"], env, config)[0], 2)


def test_malformed_config_is_a_configuration_error_everywhere(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """Commands that load config outside the guard used to dump a traceback."""
    config = tmp_path / "bad.yml"
    config.write_text("servers: [ unbalanced\n", encoding="utf-8")
    for args in (["config", "show"], ["sync", "list"], ["policy", "list"], ["servers", "list"]):
        eq(invoke(args, env, config)[0], 3)


def test_output_to_an_unwritable_path_is_reported_cleanly(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    target = tmp_path / "missing-dir" / "out.json"
    code, _ = invoke(
        ["servers", "list", "--format", "json", "--output", str(target)], env, config=cli_servers[0]
    )
    eq(code, 2)


def test_event_validate_rejects_a_structurally_wrong_file(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    document = tmp_path / "array.json"
    document.write_text("[]", encoding="utf-8")
    code, output = invoke(["event", "validate", str(document)], env, cli_servers[0])
    eq(code, 2)
    not_contains(output, "Traceback")


def test_global_selectors_work_after_the_subcommand_without_shadowing_it(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    """--tag reaches the global selector unless the subcommand owns it."""
    config, _, _ = cli_servers
    # health has no --tag of its own, so this is the fleet selector, not an error.
    ne(invoke(["health", "--tag", "unknown-tag"], env, config)[0], 2)
    # search events does own --tag, so it must still bind there.
    code, _ = invoke(["search", "events", "--tag", "tlp:green"], env, config)
    ne(code, 2)


def test_hostile_server_text_cannot_break_the_error_printer(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """The central error path renders server text too.

    An unbalanced markup tag inside an error message crashed guard()/run()
    themselves, replacing the documented exit code with a raw traceback.
    """
    document = tmp_path / "hostile.json"
    document.write_text('{"Event": {"uuid": "[/red]", "info": "[bold red]x"}}', encoding="utf-8")
    code, output = invoke(["event", "validate", str(document)], env, cli_servers[0])
    not_contains(output, "Traceback")
    ne(code, 1)


def test_config_file_edits_report_a_malformed_file_cleanly(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """add-server and remove-server edit the file textually, outside the model."""
    config = tmp_path / "broken.yml"
    config.write_text("servers: [ unbalanced\n", encoding="utf-8")
    add = ["config", "add-server", "z", "--url", "https://z.example", "--credential-key", "K"]
    eq(invoke(add, env, config)[0], 3)
    eq(invoke(["config", "remove-server", "z"], env, config)[0], 3)


def test_config_derived_names_are_not_parsed_as_markup(tmp_path: Path, env: dict[str, str]) -> None:
    """Policy and sync-job names reach rich too, not just their values."""
    config = tmp_path / "hostile-names.yml"
    config.write_text(
        "version: 1\n"
        "servers:\n"
        "  alpha:\n"
        "    url: https://alpha.example\n"
        "    credential: {provider: env, key: A}\n"
        'policies:\n  "[/red]":\n    add_tags: [x]\n'
        'sync_jobs:\n  "[/red]":\n    left: alpha\n    right: alpha\n',
        encoding="utf-8",
    )
    for args in (["policy", "list"], ["sync", "list"]):
        code, output = invoke(args, env, config)
        eq(code, 0)
        contains(output, "[/red]")


def test_a_config_document_of_the_wrong_shape_is_a_configuration_error(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """Valid YAML that is not a mapping parses, then fails on .get/.setdefault."""
    for name, body in (("list.yml", "- a\n"), ("scalar.yml", "hello\n")):
        config = tmp_path / name
        config.write_text(body, encoding="utf-8")
        add = ["config", "add-server", "z", "--url", "https://z.example", "--credential-key", "K"]
        eq(invoke(add, env, config)[0], 3)
        eq(invoke(["config", "remove-server", "z"], env, config)[0], 3)


def test_attribute_search_refuses_the_object_name_filter(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str]
) -> None:
    """/attributes/restSearch has no object_name filter and drops it silently.

    The search came back unscoped while the CLI presented it as scoped.
    """
    config, research, _production = cli_servers
    seed(research)
    code, _ = invoke(
        ["--server", "research", "search", "attributes", "--object-name", "file"], env, config
    )
    # Refused as an unsupported capability, not reported as one server's failure.
    eq(code, 10)


def test_attribute_search_treats_a_closed_pipe_as_success(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """`mispfleet attribute search | head` raised BrokenPipeError and exited 1.

    Every other output path already reports a reader closing the pipe as 0;
    the one command built for streaming was the one that crashed.
    """
    config, research, _production = cli_servers
    seed(research)
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    command = get_command(app)
    previous = dict(os.environ)
    os.environ.update(env)
    try:
        with (
            open(write_fd, "w", encoding="utf-8", buffering=1) as broken,
            contextlib.redirect_stdout(broken),
            pytest.raises(SystemExit) as raised,
        ):
            command.main(
                ["--config", str(config), "--server", "research", "attribute", "search"],
                standalone_mode=True,
            )
    finally:
        os.environ.clear()
        os.environ.update(previous)
    eq(raised.value.code, 0)


def test_taxii_push_reports_a_rejected_object_as_a_failure(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], taxii_server: FakeTaxii
) -> None:
    """The status resource is the outcome, not a receipt.

    A TAXII server that rejected every object still answers 202, so reading
    success from the HTTP code alone reported a total failure as exit 0.
    """
    config, research, _production = cli_servers
    seed(research)
    research.events[EVENT_UUID]["Attribute"] = [{"type": "domain", "value": "evil.example"}]
    taxii_server.reject_pushes = True
    push_env = dict(env)
    push_env["MISPFLEET_TAXII_TOKEN"] = TAXII_TOKEN
    code, output = invoke(
        [
            "--server",
            "research",
            "stix",
            "push",
            EVENT_UUID,
            "--taxii-url",
            taxii_server.url,
            "--collection",
            TAXII_COLLECTION,
            "--credential-key",
            "MISPFLEET_TAXII_TOKEN",
        ],
        push_env,
        config,
    )
    eq(code, 1)
    contains(output, "rejected")
    eq(taxii_server.pushed, [])


def test_event_find_does_not_call_an_unreachable_server_absent(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """A server that could not answer has not said the event is absent.

    Both were rendered "absent" and counted as "missing", so an outage was
    reported as a confident "this event exists nowhere", with exit 11.
    """
    _config, research, _production = cli_servers
    seed(research)
    config = tmp_path / "with-down.yml"
    config.write_text(
        f"""
version: 1
servers:
  research:
    url: {research.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
  down:
    url: http://127.0.0.1:9
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
    connect_timeout: 0.5
    retry: {{max_attempts: 1, initial_delay: 0.0, jitter: false}}
""",
        encoding="utf-8",
    )
    code, output = invoke(
        ["--format", "json", "--all", "event", "find", "9c5c1c2e-0000-4000-8000-0000000000ff"],
        env,
        config,
    )
    payload = json.loads(output)
    # research answered 404 — genuinely absent. down never answered at all.
    eq(payload["missing"], ["research"])
    contains(payload["failed"], "down")
    # Nothing was found and one server never answered: partial, not "no matches".
    eq(code, 6)
    code, output = invoke(
        ["--all", "event", "find", "9c5c1c2e-0000-4000-8000-0000000000ff"], env, config
    )
    eq(code, 6)
    contains(output, "absent")
    contains(output, "failed")
    # Finding it on one server says nothing about the one that never replied,
    # so an unreachable server stays partial exactly as it does elsewhere.
    code, _ = invoke(["--all", "event", "find", EVENT_UUID], env, config)
    eq(code, 6)


def test_a_reader_that_closes_the_pipe_early_still_exits_zero(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """Real piped stdout is block-buffered, unlike an in-process StringIO.

    Without the flush inside the try the write sat in the buffer, the broken
    pipe surfaced during interpreter shutdown — past the handler — and the
    command exited 120 for a run that had succeeded.
    """
    if sys.platform == "win32":
        pytest.skip("block-buffered pipe and broken-pipe semantics are POSIX")
    config, research, _production = cli_servers
    seed(research)
    binary = str(Path(sys.executable).parent / "mispfleet")
    child_env = {**os.environ, **env}
    process = subprocess.Popen(  # nosec B603
        [binary, "--config", str(config), "--server", "research", "attribute", "search"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=child_env,
    )
    not_none(process.stdout).close()  # the reader goes away before the child writes
    eq(process.wait(), 0)


def test_attribute_search_reports_an_unwritable_output_as_a_usage_error(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """emit() already types this; the streaming path let OSError escape as 1."""
    config, research, _production = cli_servers
    seed(research)
    code, _ = invoke(
        [
            "--output",
            str(tmp_path / "absent-dir" / "out.jsonl"),
            "--server",
            "research",
            "attribute",
            "search",
        ],
        env,
        config,
    )
    eq(code, 2)


def test_a_failed_attribute_search_does_not_truncate_the_output_file(
    cli_servers: tuple[Path, FakeMisp, FakeMisp], env: dict[str, str], tmp_path: Path
) -> None:
    """ "w" truncates on open, and the open happened before any work.

    An unknown selector destroyed the previous contents of --output before the
    fleet had been asked anything; emit() writes only once the operation
    succeeded, and the streaming path now matches it.
    """
    config, research, _production = cli_servers
    seed(research)
    destination = tmp_path / "out.jsonl"
    destination.write_text("PRECIOUS DATA\n", encoding="utf-8")
    code, _ = invoke(
        ["--output", str(destination), "--server", "nope", "attribute", "search"], env, config
    )
    eq(code, 3)
    eq(destination.read_text(encoding="utf-8"), "PRECIOUS DATA\n")
    # A run that reaches the fleet still writes, even with nothing to report.
    code, _ = invoke(
        [
            "--output",
            str(destination),
            "--server",
            "research",
            "attribute",
            "search",
            "--type",
            "never-present",
        ],
        env,
        config,
    )
    eq(code, 11)
    eq(destination.read_text(encoding="utf-8"), "")
