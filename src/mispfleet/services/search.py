"""Federated search normalization and deterministic duplicate grouping."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from mispfleet.models.query import SearchQuery
from mispfleet.models.result import (
    FederatedMatch,
    FederatedSearchResult,
    MatchGroup,
    MatchLevel,
    MultiServerResult,
)


def normalized_value(value: str) -> str:
    """Canonical form used to group attribute values across servers."""
    return value.strip().lower()


def _uuid_or_none(raw: Any) -> UUID | None:
    try:
        return UUID(str(raw)) if raw else None
    except ValueError:
        return None


def normalize_match(
    server: str,
    raw: dict[str, Any],
    fetched_at: datetime,
) -> FederatedMatch:
    """Build a provenance-preserving match from a raw MISP attribute."""
    event = raw.get("Event", {})
    tags = {str(tag["name"]) for tag in raw.get("Tag", []) if "name" in tag}
    return FederatedMatch(
        server=server,
        event_id=str(raw["event_id"]) if raw.get("event_id") else None,
        event_uuid=_uuid_or_none(event.get("uuid")),
        attribute_id=str(raw["id"]) if raw.get("id") else None,
        attribute_uuid=_uuid_or_none(raw.get("uuid")),
        value=str(raw["value"]) if raw.get("value") is not None else None,
        attribute_type=str(raw["type"]) if raw.get("type") else None,
        category=str(raw["category"]) if raw.get("category") else None,
        event_info=str(event["info"]) if event.get("info") else None,
        tags=tags,
        fetched_at=fetched_at,
        raw=raw,
    )


def group_matches(matches: list[FederatedMatch]) -> list[MatchGroup]:
    """Group duplicates deterministically; provenance is never erased.

    Attributes with identical normalized value and type are grouped, as are
    matches sharing an event UUID. Only groups with two or more members are
    reported.
    """
    by_value: dict[str, list[FederatedMatch]] = {}
    by_event: dict[str, list[FederatedMatch]] = {}
    for match in matches:
        if match.value is not None and match.attribute_type is not None:
            key = f"{match.attribute_type}|{normalized_value(match.value)}"
            by_value.setdefault(key, []).append(match)
        if match.event_uuid is not None:
            by_event.setdefault(str(match.event_uuid), []).append(match)
    groups = [
        MatchGroup(level=MatchLevel.SAME_VALUE_AND_TYPE, key=key, matches=members)
        for key, members in sorted(by_value.items())
        if len(members) > 1
    ]
    groups.extend(
        MatchGroup(level=MatchLevel.SAME_UUID, key=key, matches=members)
        for key, members in sorted(by_event.items())
        if len(members) > 1
    )
    return groups


def build_search_result(
    envelope: MultiServerResult[list[FederatedMatch]],
) -> FederatedSearchResult:
    """Assemble the final federated result from the executor envelope."""
    matches: list[FederatedMatch] = []
    for server in envelope.successful_servers:
        matches.extend(envelope.results[server])
    for match in matches:
        match.operation_id = envelope.operation_id
    unique = {
        f"{match.attribute_type}|{normalized_value(match.value)}"
        for match in matches
        if match.value is not None
    }
    return FederatedSearchResult(
        **envelope.model_dump(),
        matches=matches,
        groups=group_matches(matches),
        total_matches=len(matches),
        unique_values=len(unique),
    )


def collect_query_limit(query: SearchQuery, page_size: int) -> int:
    """Effective page size honoring the per-server limit."""
    if query.limit_per_server is not None:
        return min(page_size, query.limit_per_server)
    return page_size
