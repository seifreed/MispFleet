"""Normalized MISP event model with canonical fingerprinting."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field

from mispfleet.models.attribute import MISPAttribute, MISPObject, tag_names


class MISPEvent(BaseModel):
    """Normalized representation of a MISP event."""

    uuid: str
    info: str = ""
    date: str | None = None
    published: bool = False
    distribution: str | None = None
    threat_level: str | None = None
    analysis: str | None = None
    orgc: str | None = None
    timestamp: str | None = None
    tags: set[str] = Field(default_factory=set)
    attributes: list[MISPAttribute] = Field(default_factory=list)
    objects: list[MISPObject] = Field(default_factory=list)

    @classmethod
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
            date=str(event["date"]) if "date" in event else None,
            published=bool(event.get("published", False)),
            distribution=str(event["distribution"]) if "distribution" in event else None,
            threat_level=str(event["threat_level_id"]) if "threat_level_id" in event else None,
            analysis=str(event["analysis"]) if "analysis" in event else None,
            orgc=str(orgc["name"]) if "name" in orgc else None,
            timestamp=str(event["timestamp"]) if "timestamp" in event else None,
            tags=tag_names(event),
            attributes=[MISPAttribute.from_misp(item) for item in event.get("Attribute", [])],
            objects=[MISPObject.from_misp(item) for item in event.get("Object", [])],
        )

    def canonical_fingerprint(self) -> str:
        """Deterministic SHA-256 fingerprint of the canonical event content.

        Volatile fields (timestamps) are excluded so equivalent content on two
        servers produces the same fingerprint.
        """
        canonical = self.model_dump(exclude={"timestamp"})
        canonical["tags"] = sorted(canonical["tags"])
        for attribute in canonical["attributes"]:
            attribute.pop("timestamp")
            attribute.pop("event_id")
            attribute["tags"] = sorted(attribute["tags"])
        canonical["attributes"].sort(key=lambda item: (item["type"], item["value"]))
        for obj in canonical["objects"]:
            for attribute in obj["attributes"]:
                attribute.pop("timestamp")
                attribute.pop("event_id")
                attribute["tags"] = sorted(attribute["tags"])
            obj["attributes"].sort(key=lambda item: (item["type"], item["value"]))
        canonical["objects"].sort(key=lambda item: (item["name"], item["uuid"] or ""))
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
