"""End-to-end CLI tests: every command runs against real local servers."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mispfleet.cli.app import app
from tests.fake_misp import API_KEY, FakeMisp
from tests.fake_opencti import TOKEN as OPENCTI_TOKEN
from tests.fake_opencti import VERSION as OPENCTI_VERSION
from tests.fake_opencti import FakeOpenCTI
from tests.fake_taxii import COLLECTION_ID as TAXII_COLLECTION
from tests.fake_taxii import TOKEN as TAXII_TOKEN
from tests.fake_taxii import FakeTaxii
from tests.support import contains, eq, not_contains, ok

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
    research.attributes[0]["object_name"] = "file"
    code, _ = invoke(
        [
            "--server",
            "research",
            "search",
            "attributes",
            "--org",
            "CIRCL",
            "--object-name",
            "file",
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
    eq(body["object_name"], "file")
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


def test_plugins_list(env: dict[str, str]) -> None:
    code, output = invoke(["plugins", "list"], env)
    eq(code, 0)
    contains(output, "no plugins installed")


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
    code, output = invoke(["sync", "run", "blocked"], env, config)
    eq(code, 6)
    contains(output, "failed")


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
