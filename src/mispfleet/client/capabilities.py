"""Capability discovery from server version metadata."""

from __future__ import annotations

from typing import Any

CAPABILITY_REST_SEARCH = "rest-search"
CAPABILITY_EVENTS = "events"
CAPABILITY_VERSION = "version"
CAPABILITY_SYNC = "sync"
CAPABILITY_SIGHTINGS = "sightings"
CAPABILITY_GALAXIES = "galaxies"


def capabilities_from_version(payload: dict[str, Any]) -> set[str]:
    """Derive a capability set from a ``/servers/getVersion`` response.

    Behavior must be driven by discovered capabilities, not version-string
    comparisons; this keeps the mapping in one place.
    """
    capabilities = {CAPABILITY_REST_SEARCH, CAPABILITY_EVENTS}
    if payload.get("version"):
        capabilities.add(CAPABILITY_VERSION)
    if payload.get("perm_sync"):
        capabilities.add(CAPABILITY_SYNC)
    if payload.get("perm_sighting"):
        capabilities.add(CAPABILITY_SIGHTINGS)
    if payload.get("perm_galaxy_editor"):
        capabilities.add(CAPABILITY_GALAXIES)
    return capabilities
