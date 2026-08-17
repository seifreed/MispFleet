"""Federated search normalization and deterministic duplicate grouping."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from mispfleet.models.event import composite_key
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import (
    FederatedMatch,
    FederatedSearchResult,
    MatchGroup,
    MatchLevel,
    MultiServerResult,
)
from mispfleet.services.similarity import (
    POSSIBLE_MATCH_THRESHOLD,
    SHARED_INDICATORS_MINIMUM,
    similarity_from_parts,
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
            key = composite_key(match.attribute_type, normalized_value(match.value))
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
    groups.extend(_similarity_groups(by_event))
    return groups


def _similarity_groups(by_event: dict[str, list[FederatedMatch]]) -> list[MatchGroup]:
    """Pairwise similarity grouping of distinct events (never a merge, §19).

    Two events with different UUIDs land in a ``shared-indicators`` group when
    they have at least ``SHARED_INDICATORS_MINIMUM`` identical indicators, or
    in a ``possible-match`` group when their similarity score reaches the
    threshold without that much hard overlap.
    """
    groups: list[MatchGroup] = []
    event_uuids = sorted(by_event)
    for index, left_uuid in enumerate(event_uuids):
        for right_uuid in event_uuids[index + 1 :]:
            left, right = by_event[left_uuid], by_event[right_uuid]
            score = similarity_from_parts(
                _indicators(left),
                _indicators(right),
                _tags(left),
                _tags(right),
                _info(left),
                _info(right),
            )
            if score.shared_indicators >= SHARED_INDICATORS_MINIMUM:
                level = MatchLevel.SHARED_INDICATORS
            elif score.score >= POSSIBLE_MATCH_THRESHOLD:
                level = MatchLevel.POSSIBLE_MATCH
            else:
                continue
            groups.append(
                MatchGroup(level=level, key=f"{left_uuid}|{right_uuid}", matches=left + right)
            )
    return groups


def _indicators(matches: list[FederatedMatch]) -> set[str]:
    return {
        composite_key(m.attribute_type, normalized_value(m.value))
        for m in matches
        if m.attribute_type is not None and m.value is not None
    }


def _tags(matches: list[FederatedMatch]) -> set[str]:
    return {tag for m in matches for tag in m.tags}


def _info(matches: list[FederatedMatch]) -> str:
    return next((m.event_info for m in matches if m.event_info), "")


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
        composite_key(match.attribute_type, normalized_value(match.value))
        for match in matches
        # Both, as group_matches requires: a type-less hit otherwise counted
        # under the literal string "None".
        if match.value is not None and match.attribute_type is not None
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
