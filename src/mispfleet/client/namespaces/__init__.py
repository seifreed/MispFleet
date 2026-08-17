"""Per-resource namespaces exposed on :class:`~mispfleet.client.client.MispClient`."""

from __future__ import annotations

from mispfleet.client.namespaces._base import ListNamespace
from mispfleet.client.namespaces.administration import (
    AuthKeysNamespace,
    FeedsNamespace,
    OrganisationsNamespace,
    ServersNamespace,
    SharingGroupBlueprintsNamespace,
    SharingGroupsNamespace,
    UserSettingsNamespace,
    UsersNamespace,
)
from mispfleet.client.namespaces.content import (
    AttributesNamespace,
    EventsNamespace,
    ObjectsNamespace,
    SightingsNamespace,
    TagsNamespace,
)
from mispfleet.client.namespaces.reporting import (
    AnalystDataNamespace,
    CollectionsNamespace,
    EventReportsNamespace,
    LogsNamespace,
)
from mispfleet.client.namespaces.system import SystemNamespace
from mispfleet.client.namespaces.taxonomy import (
    GalaxiesNamespace,
    GalaxyClustersNamespace,
    NoticelistsNamespace,
    TaxonomiesNamespace,
    WarninglistsNamespace,
)

__all__ = [
    "AnalystDataNamespace",
    "AttributesNamespace",
    "AuthKeysNamespace",
    "CollectionsNamespace",
    "EventReportsNamespace",
    "EventsNamespace",
    "FeedsNamespace",
    "GalaxiesNamespace",
    "GalaxyClustersNamespace",
    "ListNamespace",
    "LogsNamespace",
    "NoticelistsNamespace",
    "ObjectsNamespace",
    "OrganisationsNamespace",
    "ServersNamespace",
    "SharingGroupBlueprintsNamespace",
    "SharingGroupsNamespace",
    "SightingsNamespace",
    "SystemNamespace",
    "TagsNamespace",
    "TaxonomiesNamespace",
    "UserSettingsNamespace",
    "UsersNamespace",
    "WarninglistsNamespace",
]
