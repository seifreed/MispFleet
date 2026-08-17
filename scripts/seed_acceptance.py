"""Seed the local acceptance fleet with deterministic test events.

Populates the two containerized MISP instances described in
``tests/contract/docker-compose.yml`` so the runbook in ``docs/acceptance.md``
has data to diff, search and copy. Idempotent: fixed UUIDs are skipped when
they already exist.

Usage::

    MISP_KEY_RESEARCH=... MISP_KEY_PRODUCTION=... python scripts/seed_acceptance.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from pydantic import AnyHttpUrl

from mispfleet.client import MispClient
from mispfleet.exceptions import NotFoundError
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent
from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig

SHARED_EVENT_UUID = "6a3f31a0-9c1d-4d3a-8f6e-000000000001"
COPY_EVENT_UUID = "6a3f31a0-9c1d-4d3a-8f6e-000000000002"
HASHES_EVENT_UUID = "6a3f31a0-9c1d-4d3a-8f6e-000000000003"

SAMPLE_SHA256 = "4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5"


def server_config(name: str, url: str) -> ServerConfig:
    """Configuration for one local acceptance instance (self-signed TLS)."""
    return ServerConfig(
        name=name,
        url=AnyHttpUrl(url),
        credential=CredentialReference(provider="memory", key=name),
        verify_tls=False,
        request_timeout=60.0,
        connect_timeout=15.0,
        retry=RetryConfig(max_attempts=2, initial_delay=0.5, jitter=False),
    )


def research_events() -> list[MISPEvent]:
    """Events seeded on the research instance."""
    return [
        MISPEvent(
            uuid=SHARED_EVENT_UUID,
            info="Acceptance: shared campaign indicators",
            date="2026-08-01",
            distribution="1",
            threat_level="2",
            analysis="1",
            tags={"tlp:green", "internal-only"},
            attributes=[
                MISPAttribute(type="domain", category="Network activity", value="evil.example"),
                MISPAttribute(
                    type="ip-dst",
                    category="Network activity",
                    value="203.0.113.10",
                    to_ids=True,
                ),
                MISPAttribute(
                    type="sha256",
                    category="Payload delivery",
                    value=SAMPLE_SHA256,
                    to_ids=True,
                    comment="research-only observation",
                ),
            ],
        ),
        MISPEvent(
            uuid=COPY_EVENT_UUID,
            info="Acceptance: event to copy across servers",
            date="2026-08-02",
            distribution="1",
            threat_level="3",
            analysis="0",
            tags={"tlp:green", "do-not-share"},
            attributes=[
                MISPAttribute(type="domain", category="Network activity", value="copy-me.example"),
                MISPAttribute(
                    type="url",
                    category="Network activity",
                    value="https://copy-me.example/payload",
                ),
            ],
        ),
        MISPEvent(
            uuid=HASHES_EVENT_UUID,
            info="Acceptance: hash corpus for streaming search",
            date="2026-08-03",
            distribution="1",
            threat_level="3",
            analysis="2",
            tags={"tlp:green"},
            attributes=[
                MISPAttribute(
                    type="sha256",
                    category="Payload delivery",
                    value=f"{index:02x}" * 32,
                    to_ids=True,
                )
                for index in range(1, 21)
            ],
        ),
    ]


def production_events() -> list[MISPEvent]:
    """Events seeded on the production instance.

    The shared event deliberately diverges from the research copy (missing
    attribute, different tag and analysis) so ``event diff`` reports changes.
    """
    return [
        MISPEvent(
            uuid=SHARED_EVENT_UUID,
            info="Acceptance: shared campaign indicators",
            date="2026-08-01",
            distribution="1",
            threat_level="2",
            analysis="2",
            tags={"tlp:green", "reviewed"},
            attributes=[
                MISPAttribute(type="domain", category="Network activity", value="evil.example"),
                MISPAttribute(
                    type="ip-dst",
                    category="Network activity",
                    value="203.0.113.10",
                    to_ids=True,
                ),
            ],
        ),
    ]


async def seed_instance(name: str, url: str, api_key: str, events: list[MISPEvent]) -> None:
    """Create the given events on one instance, skipping existing UUIDs."""
    async with MispClient(server_config(name, url), api_key=api_key) as client:
        for event in events:
            try:
                await client.events.get(event.uuid)
            except NotFoundError:
                created = await client.events.add(event)
                print(f"{name}: created {created.uuid} ({created.info})")
            else:
                print(f"{name}: exists {event.uuid}, skipped")


async def main() -> int:
    """Seed both acceptance instances from environment-provided keys."""
    research_key = os.environ.get("MISP_KEY_RESEARCH")
    production_key = os.environ.get("MISP_KEY_PRODUCTION")
    if not research_key or not production_key:
        print("set MISP_KEY_RESEARCH and MISP_KEY_PRODUCTION", file=sys.stderr)
        return 2
    research_url = os.environ.get("MISP_RESEARCH_URL", "https://localhost:10443")
    production_url = os.environ.get("MISP_PRODUCTION_URL", "https://localhost:20443")
    await seed_instance("research", research_url, research_key, research_events())
    await seed_instance("production", production_url, production_key, production_events())
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
