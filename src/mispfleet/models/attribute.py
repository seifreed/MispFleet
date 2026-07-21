"""Normalized MISP attribute and object models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


def tag_names(raw: dict[str, Any]) -> set[str]:
    """Extract tag names from a raw MISP entity payload."""
    return {str(tag["name"]) for tag in raw.get("Tag", []) if "name" in tag}


class MISPAttribute(BaseModel):
    """Normalized representation of a MISP attribute."""

    uuid: str | None = None
    event_id: str | None = None
    type: str
    category: str | None = None
    value: str
    to_ids: bool = False
    comment: str = ""
    deleted: bool = False
    timestamp: str | None = None
    tags: set[str] = Field(default_factory=set)

    @classmethod
    def from_misp(cls, raw: dict[str, Any]) -> MISPAttribute:
        """Build a normalized attribute from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            event_id=str(raw["event_id"]) if "event_id" in raw else None,
            type=str(raw["type"]),
            category=raw.get("category"),
            value=str(raw["value"]),
            to_ids=bool(raw.get("to_ids", False)),
            comment=str(raw.get("comment", "")),
            deleted=bool(raw.get("deleted", False)),
            timestamp=str(raw["timestamp"]) if "timestamp" in raw else None,
            tags=tag_names(raw),
        )


class MISPObject(BaseModel):
    """Normalized representation of a MISP object."""

    uuid: str | None = None
    name: str
    template_uuid: str | None = None
    comment: str = ""
    attributes: list[MISPAttribute] = Field(default_factory=list)

    @classmethod
    def from_misp(cls, raw: dict[str, Any]) -> MISPObject:
        """Build a normalized object from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            name=str(raw["name"]),
            template_uuid=raw.get("template_uuid"),
            comment=str(raw.get("comment", "")),
            attributes=[MISPAttribute.from_misp(item) for item in raw.get("Attribute", [])],
        )
