"""Federated search query model."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from mispfleet.exceptions import CapabilityError

# Query fields that map one-to-one onto a restSearch key. Scalars are copied
# when set; sorted sets when non-empty; flags emit ``True`` when truthy.
_SCALAR_FIELDS: tuple[tuple[str, str], ...] = (
    ("value", "value"),
    ("threat_level", "threat_level_id"),
    ("analysis", "analysis"),
    ("object_name", "object_name"),
    ("distribution", "distribution"),
    ("published", "published"),
)
_SORTED_SET_FIELDS: tuple[tuple[str, str], ...] = (
    ("attribute_types", "type"),
    ("categories", "category"),
    ("organisations", "org"),
)
_FLAG_FIELDS: tuple[tuple[str, str], ...] = (
    ("metadata_only", "metadata"),
    ("include_deleted", "deleted"),
    ("enforce_warninglists", "enforceWarninglist"),
)


def _keeps(event: dict[str, Any], field: str, wanted: str | None) -> bool:
    """Whether ``event`` survives a criterion restSearch accepted and ignored.

    An absent — or explicitly null — field means the payload cannot answer the
    question: the reduced ``Event`` embedded in an attribute hit carries only a
    handful of keys. Excluding those would turn ``str(None)`` into the literal
    "None", which matches no valid value, and quietly filter every hit away.
    """
    if wanted is None or event.get(field) is None:
        return True
    return str(event[field]) == wanted


class SearchQuery(BaseModel):
    """Declarative search criteria applied across one or more MISP servers."""

    value: str | list[str] | None = None
    event_info: str | None = None
    event_uuid: UUID | None = None
    event_id: int | None = Field(default=None, ge=1)
    attribute_uuid: UUID | None = None
    attribute_types: set[str] = Field(default_factory=set)
    categories: set[str] = Field(default_factory=set)
    tags: set[str] = Field(default_factory=set)
    excluded_tags: set[str] = Field(default_factory=set)
    organisations: set[str] = Field(default_factory=set)
    threat_level: str | None = None
    analysis: str | None = None
    object_name: str | None = None
    distribution: str | None = None
    published: bool | None = None
    date_from: date | datetime | None = None
    date_to: date | datetime | None = None
    timestamp_from: datetime | None = None
    timestamp_to: datetime | None = None
    metadata_only: bool = False
    include_deleted: bool = False
    enforce_warninglists: bool = False
    limit_per_server: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _reject_ambiguous_event_reference(self) -> SearchQuery:
        """Two names for one event must not become two events.

        MISP unions a list of ``eventid``, so sending a uuid and an id turned
        two constraints into "either" and returned events the caller never
        asked for, presented as if both criteria had applied.
        """
        if self.event_uuid is not None and self.event_id is not None:
            raise ValueError("event_uuid and event_id both identify one event; supply only one")
        return self

    def matches_locally(self, raw: dict[str, Any]) -> bool:
        """Apply the criteria restSearch accepts in the body and then ignores.

        Verified against MISP 2.5.44: ``analysis`` and ``distribution`` change
        nothing in a restSearch response, so filtering them server-side
        silently returned every event instead of the scoped subset. Both
        describe the containing event, matching ``/events/index``'s
        ``searchanalysis`` and ``searchdistribution``; ``raw`` may be an
        attribute carrying its event, or the event itself.
        """
        nested = raw.get("Event")
        event = nested if isinstance(nested, dict) else raw
        return _keeps(event, "analysis", self.analysis) and _keeps(
            event, "distribution", self.distribution
        )

    def attribute_payload(self) -> dict[str, Any]:
        """The request body for ``/attributes/restSearch``.

        That endpoint has no ``object_name`` filter (only ``/objects/restsearch``
        does) and MISP drops unknown restSearch keys in silence, so the search
        came back scoped in appearance only. The attribute hit carries
        ``object_id`` and ``object_relation`` but never the object's name, so
        the criterion cannot be re-applied client-side either.
        """
        if self.object_name is not None:
            raise CapabilityError(
                "/attributes/restSearch cannot filter by object_name; "
                "search objects instead of attributes to scope by object"
            )
        return self.to_misp_payload()

    def event_payload(self) -> dict[str, Any]:
        """The request body for ``/events/restSearch``.

        That endpoint's filter (``RestSearchEventsRequest``) has no
        ``object_name`` — only ``/objects/restsearch`` does — and MISP drops
        unknown restSearch keys in silence, so the search came back scoped in
        appearance only. Scoping events by an object's name is an object
        search, not an event one, so the criterion is refused rather than
        answered against the wrong endpoint. ``analysis`` and ``distribution``
        stay: restSearch ignores them too, but ``matches_locally`` re-applies
        them against the returned events.
        """
        if self.object_name is not None:
            raise CapabilityError(
                "/events/restSearch cannot filter by object_name; "
                "search objects instead of events to scope by object"
            )
        return self.to_misp_payload()

    def object_payload(self) -> dict[str, Any]:
        """The request body for ``/objects/restsearch``.

        That endpoint's filter (``ObjectRestSearchFilter``) has no
        ``analysis``, ``distribution`` or ``threat_level_id`` — those describe
        the containing event, and an object hit does not carry them, so the
        criterion cannot be re-applied locally either. MISP drops unknown
        restSearch keys in silence, so leaving them in returned every object
        as if it were the scoped subset.
        """
        unsupported = [
            name
            for name, value in (
                ("analysis", self.analysis),
                ("distribution", self.distribution),
                ("threat_level", self.threat_level),
            )
            if value is not None
        ]
        if unsupported:
            raise CapabilityError(
                f"/objects/restsearch cannot filter by {', '.join(unsupported)}; "
                "those describe the event, not the object"
            )
        return self.to_misp_payload()

    def to_misp_payload(self) -> dict[str, Any]:
        """Serialize the query into a MISP ``restSearch`` request body."""
        payload: dict[str, Any] = {"returnFormat": "json"}
        for field, key in _SCALAR_FIELDS:
            value = getattr(self, field)
            if value is not None:
                payload[key] = value
        for field, key in _SORTED_SET_FIELDS:
            values = getattr(self, field)
            if values:
                payload[key] = sorted(values)
        for field, key in _FLAG_FIELDS:
            if getattr(self, field):
                payload[key] = True
        self._add_free_form_filters(payload)
        return payload

    def _add_free_form_filters(self, payload: dict[str, Any]) -> None:
        """Filters whose serialization does not fit the flat field tables."""
        if self.event_info is not None:
            # MISP matches eventinfo literally unless the caller supplies
            # % wildcards; the model promises substring semantics.
            info = self.event_info
            payload["eventinfo"] = info if "%" in info else f"%{info}%"
        event_ref = self.event_uuid if self.event_uuid is not None else self.event_id
        if event_ref is not None:
            payload["eventid"] = str(event_ref)
        if self.attribute_uuid is not None:
            payload["uuid"] = str(self.attribute_uuid)
        if self.tags or self.excluded_tags:
            payload["tags"] = sorted(self.tags) + [f"!{tag}" for tag in sorted(self.excluded_tags)]
        if self.date_from is not None:
            payload["from"] = self.date_from.isoformat()
        if self.date_to is not None:
            payload["to"] = self.date_to.isoformat()
        timestamp = self._timestamp_filter()
        if timestamp is not None:
            payload["timestamp"] = timestamp

    def _timestamp_filter(self) -> str | list[str] | None:
        """MISP's overloaded ``timestamp`` filter: a range, an open start, or an open end."""
        if self.timestamp_from is not None and self.timestamp_to is not None:
            return [self.timestamp_from.isoformat(), self.timestamp_to.isoformat()]
        if self.timestamp_from is not None:
            return self.timestamp_from.isoformat()
        if self.timestamp_to is not None:
            return ["0", self.timestamp_to.isoformat()]
        return None

    def fingerprint(self) -> str:
        """Deterministic fingerprint used to match checkpoints to queries."""
        data = self.model_dump(mode="json", exclude_none=True)
        for field in ("attribute_types", "categories", "tags", "excluded_tags", "organisations"):
            data[field] = sorted(data[field])
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
