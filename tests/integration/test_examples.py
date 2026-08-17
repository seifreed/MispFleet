"""The documented examples are executed against real local servers.

Each script exposes an ``async def main(...)`` with explicit parameters, so the
tests import the module and await ``main`` directly instead of shelling out.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, ok

EXAMPLES = Path(__file__).resolve().parent.parent.parent / "examples"
EVENT_UUID = "9c5c1c2e-0000-4000-8000-00000000000e"
ENV_KEY = "MISPFLEET_EXAMPLES_TEST_KEY"


def load_example(name: str) -> ModuleType:
    """Import one example script by path, without running its CLI guard."""
    path = EXAMPLES / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mispfleet_example_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import example {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def example_env() -> Iterator[None]:
    """Expose the fake MISP API key through the environment credential provider."""
    os.environ[ENV_KEY] = API_KEY
    yield
    del os.environ[ENV_KEY]


@pytest.fixture
def example_config(
    tmp_path: Path, fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> Iterator[Path]:
    """A configuration file wiring both fake servers plus a sync job."""
    config = tmp_path / "config.yml"
    config.write_text(
        f"""
version: 1
state:
  path: {tmp_path / "state.db"}
servers:
  research:
    url: {fake_misp.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
    groups: [all]
  production:
    url: {second_fake_misp.url}
    credential: {{provider: env, key: {ENV_KEY}}}
    allow_insecure_http: true
    groups: [all]
sync_jobs:
  nightly:
    left: research
    right: production
    direction: push
""",
        encoding="utf-8",
    )
    yield config


def seed_event(app: FakeMisp) -> None:
    app.add_event(
        {
            "id": "7",
            "uuid": EVENT_UUID,
            "info": "Campaign X",
            "published": True,
            "Attribute": [{"type": "domain", "value": "evil.example"}],
        }
    )


async def test_health_check_example(
    example_config: Path,
    example_env: None,
    fake_misp: FakeMisp,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_example("health_check")
    await module.main(example_config)
    output = capsys.readouterr().out
    contains(output, "research")
    contains(output, "2.4.190")


async def test_federated_search_example(
    example_config: Path,
    example_env: None,
    fake_misp: FakeMisp,
    second_fake_misp: FakeMisp,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for app in (fake_misp, second_fake_misp):
        app.attributes = [
            {
                "id": "1",
                "uuid": "1f2b8a1e-0000-4000-8000-000000000001",
                "type": "domain",
                "value": "evil.example",
                "event_id": "7",
            }
        ]
    module = load_example("federated_search")
    await module.main(example_config, "evil.example")
    output = capsys.readouterr().out
    contains(output, "evil.example")
    eq(len([line for line in output.splitlines() if "evil.example" in line]), 2)


async def test_copy_with_policy_example(
    example_config: Path,
    example_env: None,
    fake_misp: FakeMisp,
    second_fake_misp: FakeMisp,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed_event(fake_misp)
    module = load_example("copy_with_policy")
    await module.main(example_config, EVENT_UUID, "research", "production")
    output = capsys.readouterr().out
    contains(output, "plan ")
    contains(output, "applied=True")
    contains(second_fake_misp.events, EVENT_UUID)


async def test_copy_with_policy_example_reports_blocking_errors(
    example_config: Path,
    example_env: None,
    fake_misp: FakeMisp,
    second_fake_misp: FakeMisp,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed_event(fake_misp)
    seed_event(second_fake_misp)
    module = load_example("copy_with_policy")
    await module.main(example_config, EVENT_UUID, "research", "production")
    output = capsys.readouterr().out
    contains(output, "blocking:")


async def test_sync_fleet_example(
    example_config: Path,
    example_env: None,
    fake_misp: FakeMisp,
    second_fake_misp: FakeMisp,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed_event(fake_misp)
    module = load_example("sync_fleet")
    await module.main(example_config, "nightly")
    output = capsys.readouterr().out
    contains(output, "left→right")
    contains(output, "applied 1 change(s)")
    contains(second_fake_misp.events, EVENT_UUID)


async def test_examples_declare_a_cli_entry_point() -> None:
    for name in ("health_check", "federated_search", "copy_with_policy", "sync_fleet"):
        source = (EXAMPLES / f"{name}.py").read_text(encoding="utf-8")
        contains(source, 'if __name__ == "__main__":')
        ok(sys.modules.get(f"mispfleet_example_{name}") is None)
