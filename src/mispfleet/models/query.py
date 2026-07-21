"""Federated search query model."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class SearchQuery(BaseModel):
    """Declarative search criteria applied across one or more MISP servers."""

    value: str | list[str] | None = None
    event_info: str | None = None
    event_uuid: UUID | None = None
    attribute_uuid: UUID | None = None
    attribute_types: set[str] = Field(default_factory=set)
    categories: set[str] = Field(default_factory=set)
    tags: set[str] = Field(default_factory=set)
    excluded_tags: set[str] = Field(default_factory=set)
    published: bool | None = None
    date_from: date | datetime | None = None
    date_to: date | datetime | None = None
    metadata_only: bool = False
    include_deleted: bool = False
    enforce_warninglists: bool = False
    limit_per_server: int | None = Field(default=None, ge=1)

    def to_misp_payload(self) -> dict[str, Any]:
        """Serialize the query into a MISP ``restSearch`` request body."""
        payload: dict[str, Any] = {"returnFormat": "json"}
        if self.value is not None:
            payload["value"] = self.value
        if self.event_info is not None:
            payload["eventinfo"] = self.event_info
        if self.event_uuid is not None:
            payload["eventid"] = str(self.event_uuid)
        if self.attribute_uuid is not None:
            payload["uuid"] = str(self.attribute_uuid)
        if self.attribute_types:
            payload["type"] = sorted(self.attribute_types)
        if self.categories:
            payload["category"] = sorted(self.categories)
        if self.tags or self.excluded_tags:
            payload["tags"] = sorted(self.tags) + [f"!{tag}" for tag in sorted(self.excluded_tags)]
        if self.published is not None:
            payload["published"] = self.published
        if self.date_from is not None:
            payload["from"] = self.date_from.isoformat()
        if self.date_to is not None:
            payload["to"] = self.date_to.isoformat()
        if self.metadata_only:
            payload["metadata"] = True
        if self.include_deleted:
            payload["deleted"] = True
        if self.enforce_warninglists:
            payload["enforceWarninglist"] = True
        return payload

    def fingerprint(self) -> str:
        """Deterministic fingerprint used to match checkpoints to queries."""
        data = self.model_dump(mode="json", exclude_none=True)
        for field in ("attribute_types", "categories", "tags", "excluded_tags"):
            data[field] = sorted(data[field])
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
