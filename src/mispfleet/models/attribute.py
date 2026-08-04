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
    distribution: str | None = None
    sharing_group_id: str | None = None
    data: str | None = None
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
            distribution=str(raw["distribution"]) if "distribution" in raw else None,
            sharing_group_id=str(raw["sharing_group_id"]) if "sharing_group_id" in raw else None,
            data=raw.get("data"),
            tags=tag_names(raw),
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API attribute payload."""
        payload: dict[str, Any] = {
            "type": self.type,
            "value": self.value,
            "to_ids": self.to_ids,
            "comment": self.comment,
            "Tag": [{"name": name} for name in sorted(self.tags)],
        }
        if self.uuid is not None:
            payload["uuid"] = self.uuid
        if self.category is not None:
            payload["category"] = self.category
        if self.distribution is not None:
            payload["distribution"] = self.distribution
        if self.sharing_group_id is not None:
            payload["sharing_group_id"] = self.sharing_group_id
        if self.data is not None:
            payload["data"] = self.data
        return payload


class ObjectReference(BaseModel):
    """Normalized representation of a MISP object reference."""

    uuid: str | None = None
    object_uuid: str | None = None
    referenced_uuid: str
    relationship_type: str = ""

    @classmethod
    def from_misp(cls, raw: dict[str, Any]) -> ObjectReference:
        """Build a normalized object reference from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            object_uuid=raw.get("object_uuid"),
            referenced_uuid=str(raw["referenced_uuid"]),
            relationship_type=str(raw.get("relationship_type", "")),
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API object-reference payload."""
        payload: dict[str, Any] = {
            "referenced_uuid": self.referenced_uuid,
            "relationship_type": self.relationship_type,
        }
        if self.uuid is not None:
            payload["uuid"] = self.uuid
        if self.object_uuid is not None:
            payload["object_uuid"] = self.object_uuid
        return payload


class MISPObject(BaseModel):
    """Normalized representation of a MISP object."""

    uuid: str | None = None
    name: str
    template_uuid: str | None = None
    comment: str = ""
    distribution: str | None = None
    sharing_group_id: str | None = None
    attributes: list[MISPAttribute] = Field(default_factory=list)
    references: list[ObjectReference] = Field(default_factory=list)

    @classmethod
    def from_misp(cls, raw: dict[str, Any]) -> MISPObject:
        """Build a normalized object from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            name=str(raw["name"]),
            template_uuid=raw.get("template_uuid"),
            comment=str(raw.get("comment", "")),
            distribution=str(raw["distribution"]) if "distribution" in raw else None,
            sharing_group_id=str(raw["sharing_group_id"]) if "sharing_group_id" in raw else None,
            attributes=[MISPAttribute.from_misp(item) for item in raw.get("Attribute", [])],
            references=[ObjectReference.from_misp(item) for item in raw.get("ObjectReference", [])],
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API object payload."""
        payload: dict[str, Any] = {
            "name": self.name,
            "comment": self.comment,
            "Attribute": [attribute.to_misp() for attribute in self.attributes],
            "ObjectReference": [reference.to_misp() for reference in self.references],
        }
        if self.uuid is not None:
            payload["uuid"] = self.uuid
        if self.template_uuid is not None:
            payload["template_uuid"] = self.template_uuid
        if self.distribution is not None:
            payload["distribution"] = self.distribution
        if self.sharing_group_id is not None:
            payload["sharing_group_id"] = self.sharing_group_id
        return payload
