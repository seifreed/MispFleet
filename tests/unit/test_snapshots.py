"""Snapshot tests pinning the serialized shape of public outputs.

Snapshots live in ``tests/snapshots/``. Set ``MISPFLEET_UPDATE_SNAPSHOTS=1``
to rewrite them after an intentional format change, then review the diff.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mispfleet.models.attribute import MISPAttribute, MISPObject, ObjectReference
from mispfleet.models.event import Galaxy, MISPEvent, Proposal, Sighting
from mispfleet.models.query import SearchQuery
from mispfleet.output.renderers import patch_from_diff
from mispfleet.services.diff import diff_events
from tests.support import eq

SNAPSHOTS = Path(__file__).resolve().parent.parent / "snapshots"
UPDATE = os.environ.get("MISPFLEET_UPDATE_SNAPSHOTS") == "1"


def assert_snapshot(name: str, payload: Any) -> None:
    """Compare a JSON-serializable payload against its stored snapshot."""
    path = SNAPSHOTS / f"{name}.json"
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if UPDATE or not path.exists():
        SNAPSHOTS.mkdir(parents=True, exist_ok=True)
        path.write_text(serialized, encoding="utf-8")
    eq(path.read_text(encoding="utf-8"), serialized)


def sample_event(info: str = "Campaign X") -> MISPEvent:
    return MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        info=info,
        date="2026-01-01",
        published=True,
        distribution="1",
        sharing_group_id="3",
        threat_level="2",
        analysis="1",
        orgc="CIRCL",
        orgc_uuid="5c5c1c2e-0000-4000-8000-000000000010",
        tags={"tlp:green"},
        attributes=[
            MISPAttribute(
                uuid="1f2b8a1e-0000-4000-8000-000000000001",
                type="domain",
                category="Network activity",
                value="evil.example",
                to_ids=True,
                tags={"tlp:green"},
            )
        ],
        objects=[
            MISPObject(
                uuid="3a5c1c2e-0000-4000-8000-00000000000f",
                name="file",
                template_uuid="t-1",
                attributes=[MISPAttribute(type="sha256", value="aa" * 32)],
                references=[
                    ObjectReference(
                        referenced_uuid="1f2b8a1e-0000-4000-8000-000000000001",
                        relationship_type="related-to",
                    )
                ],
            )
        ],
        galaxies=[Galaxy(name="Threat Actor", clusters={"APT-X"})],
        sightings=[Sighting(attribute_uuid="1f2b8a1e-0000-4000-8000-000000000001")],
        proposals=[Proposal(type="domain", value="proposed.example")],
    )


def test_event_misp_serialization_snapshot() -> None:
    assert_snapshot("event-to-misp", sample_event().to_misp())


def test_event_diff_snapshot() -> None:
    diff = diff_events(
        "9c5c1c2e-0000-4000-8000-00000000000e",
        "research",
        "production",
        sample_event(),
        sample_event(info="Campaign X (edited)"),
    )
    assert_snapshot("event-diff", diff.model_dump(mode="json"))


def test_event_diff_patch_snapshot() -> None:
    diff = diff_events(
        "9c5c1c2e-0000-4000-8000-00000000000e",
        "research",
        "production",
        sample_event(),
        sample_event(info="Campaign X (edited)"),
    )
    assert_snapshot("event-diff-patch", patch_from_diff(diff).splitlines())


def test_search_query_payload_snapshot() -> None:
    query = SearchQuery(
        value="evil.example",
        attribute_types={"domain", "ip-dst"},
        tags={"tlp:green"},
        excluded_tags={"tlp:red"},
        organisations={"CIRCL"},
        threat_level="2",
        analysis="1",
        object_name="file",
        distribution="1",
        published=True,
        metadata_only=True,
        include_deleted=True,
        enforce_warninglists=True,
    )
    assert_snapshot("search-query-payload", query.to_misp_payload())
