"""Public asynchronous single-server MISP client."""

from __future__ import annotations

from types import TracebackType

from mispfleet.client.namespaces import (
    AnalystDataNamespace,
    AttributesNamespace,
    AuthKeysNamespace,
    CollectionsNamespace,
    EventReportsNamespace,
    EventsNamespace,
    FeedsNamespace,
    GalaxiesNamespace,
    GalaxyClustersNamespace,
    ListNamespace,
    LogsNamespace,
    NoticelistsNamespace,
    ObjectsNamespace,
    OrganisationsNamespace,
    ServersNamespace,
    SharingGroupBlueprintsNamespace,
    SharingGroupsNamespace,
    SightingsNamespace,
    SystemNamespace,
    TagsNamespace,
    TaxonomiesNamespace,
    UserSettingsNamespace,
    UsersNamespace,
    WarninglistsNamespace,
)
from mispfleet.client.transport import AsyncTransport
from mispfleet.credentials import CredentialResolver
from mispfleet.credentials.base import default_resolver
from mispfleet.exceptions import CapabilityError, ErrorContext
from mispfleet.models.server import ServerConfig
from mispfleet.observability import MetricsSink


class MispClient:
    """Asynchronous client for a single MISP server.

    Usable standalone or as the per-server building block of a fleet::

        async with MispClient(config, api_key="...") as client:
            event = await client.events.get("event-uuid")
    """

    def __init__(
        self,
        config: ServerConfig,
        api_key: str | None = None,
        resolver: CredentialResolver | None = None,
        transport: AsyncTransport | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        self.config = config
        if transport is None:
            key = api_key or (resolver or default_resolver()).resolve(config.credential)
            transport = AsyncTransport(config, key, metrics=metrics)
        self._transport = transport
        self._capabilities: set[str] | None = None
        self.events = EventsNamespace(transport)
        self.attributes = AttributesNamespace(transport)
        self.system = SystemNamespace(transport)
        self.objects = ObjectsNamespace(transport)
        self.sightings = SightingsNamespace(transport)
        self.tags = TagsNamespace(transport)
        self.taxonomies = TaxonomiesNamespace(transport)
        self.galaxies = GalaxiesNamespace(transport)
        self.galaxy_clusters = GalaxyClustersNamespace(transport)
        self.warninglists = WarninglistsNamespace(transport)
        self.noticelists = NoticelistsNamespace(transport)
        self.templates = ListNamespace(transport, "/objectTemplates")
        self.organisations = OrganisationsNamespace(transport)
        self.users = UsersNamespace(transport)
        self.auth_keys = AuthKeysNamespace(transport)
        self.user_settings = UserSettingsNamespace(transport)
        self.feeds = FeedsNamespace(transport)
        self.sharing_groups = SharingGroupsNamespace(transport)
        self.sharing_group_blueprints = SharingGroupBlueprintsNamespace(transport)
        self.event_reports = EventReportsNamespace(transport)
        self.analyst_data = AnalystDataNamespace(transport)
        self.collections = CollectionsNamespace(transport)
        self.logs = LogsNamespace(transport)
        self.servers = ServersNamespace(transport)

    async def __aenter__(self) -> MispClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def require_capability(self, capability: str) -> None:
        """Fail with ``CapabilityError`` when the server cannot serve ``capability``.

        Discovery is probed once per client and cached. Capabilities were
        derived and displayed but never consulted, so an operation a server
        has no permission for was sent anyway and came back as whatever
        generic error MISP chose.
        """
        if self._capabilities is None:
            self._capabilities = await self.system.capabilities()
        if capability not in self._capabilities:
            raise CapabilityError(
                f"server {self.config.name!r} does not support {capability!r}",
                ErrorContext(server=self.config.name),
            )

    async def aclose(self) -> None:
        """Release the underlying transport."""
        await self._transport.aclose()
