"""Normalized MISP event model with canonical fingerprinting."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from mispfleet.models.attribute import MISPAttribute, MISPObject, tag_names
from mispfleet.models.common import optional_str, parses_misp


class Galaxy(BaseModel):
    """Normalized representation of a MISP galaxy with its cluster values."""

    uuid: str | None = None
    name: str
    clusters: set[str] = Field(default_factory=set)

    @classmethod
    @parses_misp("galaxy")
    def from_misp(cls, raw: dict[str, Any]) -> Galaxy:
        """Build a normalized galaxy from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            name=str(raw["name"]),
            clusters={
                str(cluster["value"])
                for cluster in raw.get("GalaxyCluster", [])
                if "value" in cluster
            },
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API galaxy payload."""
        payload: dict[str, Any] = {
            "name": self.name,
            "GalaxyCluster": [{"value": value} for value in sorted(self.clusters)],
        }
        if self.uuid is not None:
            payload["uuid"] = self.uuid
        return payload


class Sighting(BaseModel):
    """Normalized representation of a MISP sighting."""

    uuid: str | None = None
    attribute_uuid: str | None = None
    type: str = "0"
    date_sighting: str | None = None
    organisation: str | None = None

    @classmethod
    @parses_misp("sighting")
    def from_misp(cls, raw: dict[str, Any]) -> Sighting:
        """Build a normalized sighting from a raw MISP JSON payload."""
        organisation = raw.get("Organisation", {})
        return cls(
            uuid=raw.get("uuid"),
            attribute_uuid=raw.get("attribute_uuid"),
            type=str(raw.get("type", "0")),
            date_sighting=optional_str(raw, "date_sighting"),
            organisation=optional_str(organisation, "name"),
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API sighting payload."""
        payload: dict[str, Any] = {"type": self.type}
        if self.uuid is not None:
            payload["uuid"] = self.uuid
        if self.attribute_uuid is not None:
            payload["attribute_uuid"] = self.attribute_uuid
        if self.date_sighting is not None:
            payload["date_sighting"] = self.date_sighting
        if self.organisation is not None:
            payload["Organisation"] = {"name": self.organisation}
        return payload


class Proposal(BaseModel):
    """Normalized representation of a MISP shadow attribute (proposal)."""

    uuid: str | None = None
    type: str
    value: str
    category: str | None = None
    to_ids: bool = False

    @classmethod
    @parses_misp("proposal")
    def from_misp(cls, raw: dict[str, Any]) -> Proposal:
        """Build a normalized proposal from a raw MISP JSON payload."""
        return cls(
            uuid=raw.get("uuid"),
            type=str(raw["type"]),
            value=str(raw["value"]),
            category=raw.get("category"),
            to_ids=bool(raw.get("to_ids", False)),
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API shadow-attribute payload."""
        payload: dict[str, Any] = {
            "type": self.type,
            "value": self.value,
            "to_ids": self.to_ids,
        }
        if self.uuid is not None:
            payload["uuid"] = self.uuid
        if self.category is not None:
            payload["category"] = self.category
        return payload


class MISPEvent(BaseModel):
    """Normalized representation of a MISP event."""

    uuid: str
    info: str = ""
    date: str | None = None
    published: bool = False
    distribution: str | None = None
    sharing_group_id: str | None = None
    threat_level: str | None = None
    analysis: str | None = None
    orgc: str | None = None
    orgc_uuid: str | None = None
    timestamp: str | None = None
    tags: set[str] = Field(default_factory=set)
    attributes: list[MISPAttribute] = Field(default_factory=list)
    objects: list[MISPObject] = Field(default_factory=list)
    galaxies: list[Galaxy] = Field(default_factory=list)
    sightings: list[Sighting] = Field(default_factory=list)
    proposals: list[Proposal] = Field(default_factory=list)

    @classmethod
    @parses_misp("event")
    def from_misp(cls, raw: dict[str, Any]) -> MISPEvent:
        """Build a normalized event from a raw MISP JSON payload.

        Accepts either the wrapped ``{"Event": {...}}`` form returned by the
        MISP API or the inner event dictionary directly.
        """
        event = raw.get("Event", raw)
        orgc = event.get("Orgc", {})
        return cls(
            uuid=str(event["uuid"]),
            info=str(event.get("info", "")),
            date=optional_str(event, "date"),
            published=bool(event.get("published", False)),
            distribution=optional_str(event, "distribution"),
            sharing_group_id=(optional_str(event, "sharing_group_id")),
            threat_level=optional_str(event, "threat_level_id"),
            analysis=optional_str(event, "analysis"),
            orgc=optional_str(orgc, "name"),
            orgc_uuid=optional_str(orgc, "uuid"),
            timestamp=optional_str(event, "timestamp"),
            tags=tag_names(event),
            attributes=[MISPAttribute.from_misp(item) for item in event.get("Attribute", [])],
            objects=[MISPObject.from_misp(item) for item in event.get("Object", [])],
            galaxies=[Galaxy.from_misp(item) for item in event.get("Galaxy", [])],
            sightings=[Sighting.from_misp(item) for item in event.get("Sighting", [])],
            proposals=[Proposal.from_misp(item) for item in event.get("ShadowAttribute", [])],
        )

    def to_misp(self) -> dict[str, Any]:
        """Serialize back into a MISP API event payload."""
        payload: dict[str, Any] = {
            "uuid": self.uuid,
            "info": self.info,
            "published": self.published,
            "Tag": [{"name": name} for name in sorted(self.tags)],
            "Attribute": [attribute.to_misp() for attribute in self.attributes],
            "Object": [obj.to_misp() for obj in self.objects],
            "Galaxy": [galaxy.to_misp() for galaxy in self.galaxies],
            "Sighting": [sighting.to_misp() for sighting in self.sightings],
            "ShadowAttribute": [proposal.to_misp() for proposal in self.proposals],
        }
        if self.date is not None:
            payload["date"] = self.date
        if self.distribution is not None:
            payload["distribution"] = self.distribution
        if self.sharing_group_id is not None:
            payload["sharing_group_id"] = self.sharing_group_id
        if self.threat_level is not None:
            payload["threat_level_id"] = self.threat_level
        if self.analysis is not None:
            payload["analysis"] = self.analysis
        if self.orgc is not None or self.orgc_uuid is not None:
            orgc: dict[str, Any] = {}
            if self.orgc is not None:
                orgc["name"] = self.orgc
            if self.orgc_uuid is not None:
                orgc["uuid"] = self.orgc_uuid
            payload["Orgc"] = orgc
        return payload

    def canonical_fingerprint(self) -> str:
        """Deterministic SHA-256 fingerprint of the canonical event content.

        Volatile fields (timestamps) and server-local observations (sightings
        and proposals) are excluded so equivalent content on two servers
        produces the same fingerprint.
        """
        canonical = self.model_dump(exclude={"timestamp", "sightings", "proposals"})
        canonical["tags"] = fold_tags(canonical["tags"])
        for attribute in canonical["attributes"]:
            canonicalize_attribute(attribute)
        canonical["attributes"].sort(key=_ordering_key)
        for obj in canonical["objects"]:
            for attribute in obj["attributes"]:
                canonicalize_attribute(attribute)
            obj["attributes"].sort(key=_ordering_key)
            obj["references"].sort(key=_ordering_key)
        canonical["objects"].sort(key=_ordering_key)
        for galaxy in canonical["galaxies"]:
            galaxy["clusters"] = sorted(galaxy["clusters"])
        canonical["galaxies"].sort(key=_ordering_key)
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ordering_key(item: dict[str, Any]) -> str:
    """Total ordering key for a canonicalized item.

    Partial keys such as ``(type, value)`` leave ties in each server's own
    insertion order, so the same content stored in a different order hashed
    differently and sync reported the two events as permanently divergent.
    """
    return json.dumps(item, sort_keys=True, separators=(",", ":"))


def composite_key(*parts: str) -> str:
    """Join key components so the separator cannot be forged by the data.

    MISP's composite types put a "|" in the type *and* in the value
    (``regkey|value`` holding ``HKLM\\Software\\X|data``), so a plain
    ``f"{type}|{value}"`` made ``("regkey", "value|x")`` and
    ``("regkey|value", "x")`` collide on ``regkey|value|x``: two unrelated
    indicators paired up, inflating similarity and duplicate grouping and
    making a real difference invisible. Backslash-escaping the separator (and
    the escape itself) keeps every component recoverable.
    """
    return "|".join(part.replace("\\", "\\\\").replace("|", "\\|") for part in parts)


def fold_tags(names: Iterable[str]) -> list[str]:
    """Canonical tag list: case-folded and sorted.

    MISP stores tag names under a case-insensitive collation, so ``TLP:RED``
    and ``tlp:red`` are the same tag there. Folding before hashing keeps a
    case-only difference from making two equivalent events fingerprint apart
    and re-propose forever. Duplicates are preserved (hashed as a list, not a
    set) so a genuine repeated tag stays a real difference.
    """
    return sorted(name.casefold() for name in names)


def canonicalize_attribute(attribute: dict[str, Any]) -> None:
    """Strip volatile attribute fields and sort set-valued fields in place."""
    attribute.pop("timestamp")
    attribute.pop("event_id")
    attribute["tags"] = fold_tags(attribute["tags"])
