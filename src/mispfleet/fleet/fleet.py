"""The MispFleet facade: one asynchronous interface over many MISP servers."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import UUID, uuid4

from mispfleet.client import MispClient
from mispfleet.client.capabilities import capabilities_from_version
from mispfleet.client.pagination import paginate
from mispfleet.credentials import CredentialResolver
from mispfleet.credentials.base import default_resolver
from mispfleet.exceptions import InvalidConfigurationError, MispFleetError
from mispfleet.fleet.executor import FleetExecutor
from mispfleet.fleet.registry import ServerRegistry
from mispfleet.fleet.selector import ServerSelector
from mispfleet.models.common import EventIdentifier, ExecutionOptions
from mispfleet.models.diff import EventDiff
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import ApplyResult, ConflictAction, CopyPlan
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import (
    FederatedMatch,
    FederatedSearchResult,
    FleetHealthResult,
    MultiServerResult,
    ServerHealth,
)
from mispfleet.models.server import ServerConfig
from mispfleet.models.sync import SyncJobSpec, SyncPlan, SyncResult
from mispfleet.policies.base import PolicySpec
from mispfleet.policies.engine import PolicyEngine
from mispfleet.services.copy import apply_copy_plan, build_copy_plan
from mispfleet.services.diff import diff_events
from mispfleet.services.health import check_server
from mispfleet.services.search import build_search_result, collect_query_limit, normalize_match
from mispfleet.services.sync import apply_sync, plan_sync
from mispfleet.settings import FleetConfig, load_fleet_config
from mispfleet.state.base import CapabilityRecord, OperationRecord, StateBackend


class MispFleet:
    """Operate a collection of MISP servers as one coordinated fleet."""

    def __init__(
        self,
        servers: dict[str, ServerConfig],
        policies: dict[str, PolicySpec] | None = None,
        sync_jobs: dict[str, SyncJobSpec] | None = None,
        resolver: CredentialResolver | None = None,
        interactive: bool = True,
        state: StateBackend | None = None,
    ) -> None:
        self.registry = ServerRegistry(servers)
        self.policies = dict(policies or {})
        self.sync_jobs = dict(sync_jobs or {})
        self.policy_engine = PolicyEngine(self.policies)
        self._resolver = resolver or default_resolver(interactive=interactive)
        self._executor = FleetExecutor()
        self._clients: dict[str, MispClient] = {}
        self._state = state

    @classmethod
    async def from_file(
        cls,
        path: Path | None = None,
        profile: str | None = None,
        resolver: CredentialResolver | None = None,
        interactive: bool = True,
        state: StateBackend | None = None,
    ) -> MispFleet:
        """Build a fleet from a configuration file."""
        config = load_fleet_config(path, profile)
        return cls.from_config(config, resolver=resolver, interactive=interactive, state=state)

    @classmethod
    def from_config(
        cls,
        config: FleetConfig,
        resolver: CredentialResolver | None = None,
        interactive: bool = True,
        state: StateBackend | None = None,
    ) -> MispFleet:
        """Build a fleet from an already validated configuration."""
        return cls(
            config.servers,
            policies=config.policies,
            sync_jobs=config.sync_jobs,
            resolver=resolver,
            interactive=interactive,
            state=state,
        )

    def client(self, name: str) -> MispClient:
        """Return (and cache) the client for one configured server."""
        if name not in self._clients:
            self._clients[name] = MispClient(self.registry.get(name), resolver=self._resolver)
        return self._clients[name]

    def select(self, selector: ServerSelector | None) -> list[str]:
        """Resolve a selector into concrete server names."""
        effective = selector or ServerSelector.all()
        known = set(self.registry.names())
        unknown = effective.server_names - known
        if unknown:
            raise InvalidConfigurationError(f"unknown servers in selector: {sorted(unknown)}")
        selected = [server.name for server in effective.select(self.registry.all())]
        if not selected:
            raise InvalidConfigurationError("selector matched no enabled servers")
        return selected

    async def search(
        self,
        query: SearchQuery,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
        page_size: int = 1000,
    ) -> FederatedSearchResult:
        """Search every selected server concurrently, preserving provenance."""
        servers = self.select(selector)
        fetched_at = datetime.now(tz=UTC)
        limit = collect_query_limit(query, page_size)

        async def per_server(name: str) -> list[FederatedMatch]:
            matches = [
                normalize_match(name, raw, fetched_at)
                async for raw in self._iter_raw(name, query, limit)
            ]
            return matches

        envelope = await self._executor.run(servers, per_server, execution)
        return build_search_result(envelope)

    async def iter_search(
        self,
        query: SearchQuery,
        selector: ServerSelector | None = None,
        page_size: int = 1000,
    ) -> AsyncIterator[FederatedMatch]:
        """Stream matches server by server without materializing the dataset."""
        fetched_at = datetime.now(tz=UTC)
        limit = collect_query_limit(query, page_size)
        for name in self.select(selector):
            async for raw in self._iter_raw(name, query, limit):
                yield normalize_match(name, raw, fetched_at)

    def _iter_raw(
        self,
        server: str,
        query: SearchQuery,
        page_size: int,
    ) -> AsyncIterator[dict[str, Any]]:
        client = self.client(server)

        async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
            return await client.attributes.search_page(query, page=page, limit=limit)

        return paginate(fetch, page_size=page_size, max_records=query.limit_per_server)

    async def health(
        self,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> FleetHealthResult:
        """Check the health of every selected server."""

        async def per_server(name: str) -> ServerHealth:
            return await check_server(self.client(name))

        envelope = await self._executor.run(self.select(selector), per_server, execution)
        return FleetHealthResult(**envelope.model_dump())

    async def server_capabilities(
        self,
        name: str,
        refresh: bool = False,
        ttl_seconds: float = 3600.0,
    ) -> CapabilityRecord:
        """Discover one server's capabilities, using the state cache when valid."""
        self.registry.get(name)
        now = datetime.now(tz=UTC)
        if self._state is not None and not refresh:
            cached = await self._state.load_capabilities(name)
            if cached is not None and not cached.expired(now):
                return cached
        version = await self.client(name).system.version()
        record = CapabilityRecord(
            server=name,
            misp_version=str(version.get("version")) if version.get("version") else None,
            capabilities=capabilities_from_version(version),
            fetched_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        if self._state is not None:
            await self._state.save_capabilities(record)
        return record

    async def get_event(
        self,
        event_id: EventIdentifier | str,
        selector: ServerSelector,
        execution: ExecutionOptions | None = None,
    ) -> MultiServerResult[MISPEvent]:
        """Fetch one event from every selected server."""

        async def per_server(name: str) -> MISPEvent:
            return await self.client(name).events.get(str(event_id))

        return await self._executor.run(self.select(selector), per_server, execution)

    async def compare_event(
        self,
        event_id: EventIdentifier | str,
        left: str,
        right: str,
    ) -> EventDiff:
        """Fetch one event from two servers and compare normalized content."""
        self.registry.get(left)
        self.registry.get(right)
        left_event, right_event = await asyncio.gather(
            self.client(left).events.get(str(event_id)),
            self.client(right).events.get(str(event_id)),
        )
        return diff_events(str(event_id), left, right, left_event, right_event)

    async def plan_copy(
        self,
        event_id: EventIdentifier | str,
        source: str,
        destination: str,
        policy: str | None = None,
        on_conflict: ConflictAction = ConflictAction.ABORT,
    ) -> CopyPlan:
        """Build a reviewable copy plan; the destination is never mutated."""
        self.registry.get(source)
        self.registry.get(destination)
        return await build_copy_plan(
            self.client(source),
            self.client(destination),
            str(event_id),
            self.policy_engine,
            policy=policy,
            on_conflict=on_conflict,
        )

    async def apply(self, plan: CopyPlan) -> ApplyResult:
        """Re-validate and apply a plan, recording an audit trail."""
        source = self.client(plan.source_server)
        destination = self.client(plan.destination_server)
        try:
            result = await apply_copy_plan(source, destination, plan)
        except MispFleetError as error:
            await self._record_apply(plan, result="failed", error=error.message)
            raise
        await self._record_apply(
            plan,
            result="applied" if result.applied else "skipped",
            operation_id=result.operation_id,
        )
        return result

    async def plan_sync(self, job_name: str) -> SyncPlan:
        """Build a reviewable plan for a configured synchronization job."""
        job = self.sync_jobs.get(job_name)
        if job is None:
            raise InvalidConfigurationError(f"unknown sync job {job_name!r}")
        self.registry.get(job.left)
        self.registry.get(job.right)
        return await plan_sync(
            self.client(job.left),
            self.client(job.right),
            self.policy_engine,
            job_name,
            job,
        )

    async def apply_sync(self, plan: SyncPlan) -> SyncResult:
        """Apply a synchronization plan, recording an audit trail."""
        result = await apply_sync(
            self.client(plan.left_server), self.client(plan.right_server), plan
        )
        if self._state is not None:
            await self._state.save_operation(
                OperationRecord(
                    operation_id=uuid4(),
                    kind="sync-apply",
                    timestamp=datetime.now(tz=UTC),
                    source_server=plan.left_server,
                    destination_server=plan.right_server,
                    event_identifier=None,
                    plan_fingerprint=str(plan.plan_id),
                    policy=None,
                    result=f"{len(result.applied)} applied, {len(result.failures)} failed",
                    error="; ".join(sorted(result.failures.values())) or None,
                )
            )
        return result

    async def _record_apply(
        self,
        plan: CopyPlan,
        result: str,
        error: str | None = None,
        operation_id: UUID | None = None,
    ) -> None:
        if self._state is None:
            return
        await self._state.save_operation(
            OperationRecord(
                operation_id=operation_id or uuid4(),
                kind="copy-apply",
                timestamp=datetime.now(tz=UTC),
                source_server=plan.source_server,
                destination_server=plan.destination_server,
                event_identifier=str(plan.source_event_uuid),
                plan_fingerprint=plan.fingerprint(),
                policy=plan.policy,
                result=result,
                error=error,
            )
        )

    async def __aenter__(self) -> MispFleet:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close every cached client."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
