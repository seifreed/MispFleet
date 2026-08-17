"""Normalized MISP attribute and object models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from mispfleet.models.common import optional_str, parses_misp


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
    object_relation: str | None = None
    # Carried because copy writes to_misp() straight to the destination: an
    # attribute the model does not know about is silently dropped on every
    # copy, and a sync tool losing the sightings window is losing evidence.
    first_seen: str | None = None
    last_seen: str | None = None
    disable_correlation: bool = False
    tags: set[str] = Field(default_factory=set)

    @classmethod
    @parses_misp("attribute")
    def from_misp(cls, raw: dict[str, Any]) -> MISPAttribute:
        """Build a normalized attribute from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            event_id=optional_str(raw, "event_id"),
            type=str(raw["type"]),
            category=raw.get("category"),
            value=str(raw["value"]),
            to_ids=bool(raw.get("to_ids", False)),
            comment=str(raw.get("comment", "")),
            deleted=bool(raw.get("deleted", False)),
            timestamp=optional_str(raw, "timestamp"),
            distribution=optional_str(raw, "distribution"),
            sharing_group_id=optional_str(raw, "sharing_group_id"),
            data=raw.get("data"),
            object_relation=optional_str(raw, "object_relation"),
            first_seen=optional_str(raw, "first_seen"),
            last_seen=optional_str(raw, "last_seen"),
            disable_correlation=bool(raw.get("disable_correlation", False)),
            tags=tag_names(raw),
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API attribute payload."""
        payload: dict[str, Any] = {
            "type": self.type,
            "value": self.value,
            "to_ids": self.to_ids,
            "comment": self.comment,
            # Without this a soft-deleted attribute fetched with
            # include_deleted would be recreated as a live indicator.
            "deleted": self.deleted,
            "disable_correlation": self.disable_correlation,
            "Tag": [{"name": name} for name in sorted(self.tags)],
        }
        if self.first_seen is not None:
            payload["first_seen"] = self.first_seen
        if self.last_seen is not None:
            payload["last_seen"] = self.last_seen
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
        if self.object_relation is not None:
            # An object attribute without its relation is dropped by MISP.
            payload["object_relation"] = self.object_relation
        return payload


class ObjectReference(BaseModel):
    """Normalized representation of a MISP object reference."""

    uuid: str | None = None
    object_uuid: str | None = None
    referenced_uuid: str
    relationship_type: str = ""

    @classmethod
    @parses_misp("object reference")
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
    template_version: str | None = None
    meta_category: str | None = None
    description: str | None = None
    comment: str = ""
    distribution: str | None = None
    sharing_group_id: str | None = None
    attributes: list[MISPAttribute] = Field(default_factory=list)
    references: list[ObjectReference] = Field(default_factory=list)

    @classmethod
    @parses_misp("object")
    def from_misp(cls, raw: dict[str, Any]) -> MISPObject:
        """Build a normalized object from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            name=str(raw["name"]),
            template_uuid=raw.get("template_uuid"),
            template_version=optional_str(raw, "template_version"),
            meta_category=optional_str(raw, "meta-category"),
            description=optional_str(raw, "description"),
            comment=str(raw.get("comment", "")),
            distribution=optional_str(raw, "distribution"),
            sharing_group_id=optional_str(raw, "sharing_group_id"),
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
        if self.template_version is not None:
            payload["template_version"] = self.template_version
        if self.meta_category is not None:
            # MISP spells this one with a hyphen, and needs all four together.
            payload["meta-category"] = self.meta_category
        if self.description is not None:
            payload["description"] = self.description
        if self.distribution is not None:
            payload["distribution"] = self.distribution
        if self.sharing_group_id is not None:
            payload["sharing_group_id"] = self.sharing_group_id
        return payload


# The object's scalar metadata fields — everything but its identity (name),
# uuid and the nested attributes/references. The merge adopts these into a
# destination object; the diff compares them (plus ``name``).
OBJECT_METADATA_FIELDS = (
    "comment",
    "distribution",
    "sharing_group_id",
    "template_uuid",
    "template_version",
    "meta_category",
    "description",
)
