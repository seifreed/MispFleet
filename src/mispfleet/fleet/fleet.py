"""The MispFleet facade: one asynchronous interface over many MISP servers."""

from __future__ import annotations

import asyncio
import re
import threading
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import UUID, uuid4

from mispfleet.client import MispClient
from mispfleet.client.capabilities import CAPABILITY_SIGHTINGS, capabilities_from_version
from mispfleet.client.pagination import paginate
from mispfleet.credentials import CredentialResolver
from mispfleet.credentials.base import default_resolver
from mispfleet.exceptions import InvalidConfigurationError, MispFleetError, NotFoundError
from mispfleet.fleet.executor import FleetExecutor
from mispfleet.fleet.registry import ServerRegistry
from mispfleet.fleet.selector import ServerSelector
from mispfleet.models.audit import AuditSnapshot, FleetAuditResult
from mispfleet.models.common import EventIdentifier, ExecutionOptions
from mispfleet.models.diff import EventDiff
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import ApplyResult, ConflictAction, CopyPlan
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import (
    FederatedMatch,
    FederatedSearchResult,
    FederatedSightingsResult,
    FleetHealthResult,
    MultiServerResult,
    ServerHealth,
    SightingRecord,
)
from mispfleet.models.server import ServerConfig
from mispfleet.models.sync import SyncJobSpec, SyncPlan, SyncResult
from mispfleet.observability import MetricsSink
from mispfleet.policies.base import PolicySpec
from mispfleet.policies.engine import PolicyEngine
from mispfleet.services.audit import collect_snapshot, compare_snapshots
from mispfleet.services.copy import apply_copy_plan, build_copy_plan
from mispfleet.services.diff import diff_events
from mispfleet.services.health import check_server
from mispfleet.services.search import build_search_result, collect_query_limit, normalize_match
from mispfleet.services.sync import apply_sync, plan_sync
from mispfleet.settings import FleetConfig, load_fleet_config
from mispfleet.state.base import (
    CapabilityRecord,
    OperationRecord,
    PlanRecord,
    QueryRecord,
    StateBackend,
)

_SIGHTING_KEYS = frozenset({"attribute_uuid", "attribute_id", "date_sighting"})


def _sighting_count(response: dict[str, Any]) -> int:
    """How many sightings a ``/sightings/add`` response reports as created.

    openapi.yaml declares SightingResponse as the ``Sighting`` object itself,
    unwrapped, so counting only a ``Sighting`` envelope reported 0 created
    against a conforming server and exited 11 for a sighting that did land.
    The wrapped and message forms are still recognised.
    """
    payload = response.get("Sighting")
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        return 1
    if _SIGHTING_KEYS & response.keys():
        return 1
    # Anchored: the count leads the message, and searching anywhere read the
    # 203 out of "No match for 203.0.113.10" as a count of sightings.
    match = re.match(r"\s*(\d+)\b", str(response.get("message", "")))
    return int(match.group(1)) if match else 0


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
        metrics: MetricsSink | None = None,
        actor: str | None = None,
    ) -> None:
        self.registry = ServerRegistry(servers)
        self.policies = dict(policies or {})
        self.sync_jobs = dict(sync_jobs or {})
        self.policy_engine = PolicyEngine(self.policies)
        self._resolver = resolver or default_resolver(interactive=interactive)
        self._executor = FleetExecutor()
        self._clients: dict[str, MispClient] = {}
        self._clients_lock = threading.Lock()
        self._discarded: list[MispClient] = []
        self._closed = False
        self._building = 0
        self._state = state
        self._metrics = metrics or MetricsSink()
        self._actor = actor

    @classmethod
    async def from_file(
        cls,
        path: Path | None = None,
        profile: str | None = None,
        resolver: CredentialResolver | None = None,
        interactive: bool = True,
        state: StateBackend | None = None,
        metrics: MetricsSink | None = None,
        actor: str | None = None,
    ) -> MispFleet:
        """Build a fleet from a configuration file."""
        config = load_fleet_config(path, profile)
        return cls.from_config(
            config,
            resolver=resolver,
            interactive=interactive,
            state=state,
            metrics=metrics,
            actor=actor,
        )

    @classmethod
    def from_config(
        cls,
        config: FleetConfig,
        resolver: CredentialResolver | None = None,
        interactive: bool = True,
        state: StateBackend | None = None,
        metrics: MetricsSink | None = None,
        actor: str | None = None,
    ) -> MispFleet:
        """Build a fleet from an already validated configuration."""
        return cls(
            config.servers,
            policies=config.policies,
            sync_jobs=config.sync_jobs,
            resolver=resolver,
            interactive=interactive,
            state=state,
            metrics=metrics,
            actor=actor,
        )

    async def _fan_out[T](
        self,
        servers: list[str],
        operation: Callable[[str], Awaitable[T]],
        options: ExecutionOptions | None = None,
    ) -> MultiServerResult[T]:
        """Run one operation across servers, with clients built up front.

        Credential providers are synchronous: the prompt provider waits for a
        human and the 1Password one runs a subprocess. Building a client
        inside a fan-out task therefore froze the whole event loop mid-flight,
        stalling every other server's in-flight request. Build them off the
        loop first instead.
        """
        pending = [name for name in servers if name not in self._clients]
        failures: dict[str, Exception] = {}
        if pending:

            def build() -> None:
                for name in pending:
                    # Keep the failure instead of letting the server's own task
                    # retry it: that retry would run the blocking provider on
                    # the loop, which is what building off the loop avoids.
                    # Any exception counts — one server's provider must not
                    # abort the fan-out the executor isolates per server.
                    try:
                        self.client(name)
                    except Exception as error:
                        failures[name] = error

            await asyncio.to_thread(build)

        async def guarded(name: str) -> T:
            failure = failures.get(name)
            if failure is not None:
                raise failure
            return await operation(name)

        return await self._executor.run(servers, guarded, options)

    def client(self, name: str) -> MispClient:
        """Return (and cache) the client for one configured server.

        Locked because ``_fan_out`` builds clients on a worker thread while the
        loop keeps running: an unguarded check-then-insert let two concurrent
        fan-outs each build a client, and the overwritten one was never closed.
        """
        config = self.registry.get(name)
        if not config.enabled:
            # Selectors already refuse a disabled server, but every
            # single-server command goes through here instead, so an operator
            # who disabled a decommissioned instance could still copy to it.
            raise InvalidConfigurationError(f"server {name!r} is disabled")
        with self._clients_lock:
            if self._closed:
                # Checked before the cache, not after: aclose() sets the flag
                # and then waits for builds already in flight, and _clients
                # stays populated for the whole of that wait — so the cache hit
                # handed back a client aclose was about to close.
                raise InvalidConfigurationError(f"fleet is closed; cannot use {name!r}")
            existing = self._clients.get(name)
            if existing is not None:
                return existing
            # Announced before the lock is released so aclose() waits for this
            # build instead of draining ahead of it and leaving the result
            # open with nothing left to close it.
            self._building += 1
        # Built outside the lock on purpose: credential resolution is
        # synchronous and can block for seconds (a prompt, an `op` subprocess),
        # and client() is called on the event loop as well as from the prebuild
        # thread. Holding the lock across it made a cache miss on the thread
        # stall every loop-side caller — the exact freeze the off-loop prebuild
        # exists to prevent.
        try:
            built = MispClient(config, resolver=self._resolver, metrics=self._metrics)
        except BaseException:
            with self._clients_lock:
                self._building -= 1
            raise
        with self._clients_lock:
            self._building -= 1
            current = self._clients.setdefault(name, built)
            if current is not built:
                # Another caller won the race. Its transport is already open,
                # so keep ours for aclose() rather than leak the pool.
                self._discarded.append(built)
            closed = self._closed
        if closed:
            # aclose() was waiting on this build and will close what we just
            # handed it. Returning the client anyway gave the caller a closed
            # transport, whose httpx RuntimeError escapes the typed-error
            # handling every command relies on.
            raise InvalidConfigurationError(
                f"fleet was closed while building a client for {name!r}"
            )
        return current

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
        # Validated before the fan-out: a criterion the endpoint cannot answer
        # is wrong for every server, and inside a task it would be reported as
        # one server's failure rather than as the bad query it is.
        query.attribute_payload()
        servers = self.select(selector)
        fetched_at = datetime.now(tz=UTC)
        limit = collect_query_limit(query, page_size)

        async def per_server(name: str) -> list[FederatedMatch]:
            matches = [
                normalize_match(name, raw, fetched_at)
                async for raw in self._iter_raw(name, query, limit)
            ]
            return matches

        envelope = await self._fan_out(servers, per_server, execution)
        result = build_search_result(envelope)
        await self._record_query(query, "federated-search", servers, result.total_matches)
        return result

    async def iter_search(
        self,
        query: SearchQuery,
        selector: ServerSelector | None = None,
        page_size: int = 1000,
    ) -> AsyncIterator[FederatedMatch]:
        """Stream matches server by server without materializing the dataset.

        The query is recorded once the stream is exhausted. A caller that
        abandons it early records nothing: breaking out of ``async for`` does
        not close the generator, so a write from a ``finally`` here would run
        at finalization time in a detached task, typically after the state
        backend has been closed.
        """
        query.attribute_payload()
        fetched_at = datetime.now(tz=UTC)
        limit = collect_query_limit(query, page_size)
        servers = self.select(selector)
        seen = 0
        for name in servers:
            async for raw in self._iter_raw(name, query, limit):
                seen += 1
                yield normalize_match(name, raw, fetched_at)
        await self._record_query(query, "federated-stream", servers, seen)

    async def _iter_raw(
        self,
        server: str,
        query: SearchQuery,
        page_size: int,
    ) -> AsyncIterator[dict[str, Any]]:
        client = self.client(server)

        async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
            return await client.attributes.search_page(query, page=page, limit=limit)

        seen = 0

        def on_page(page: int, records: int) -> None:
            nonlocal seen
            self._metrics.on_page(server, page, records)
            # paginate reports the cumulative count for checkpointing; adding
            # that to a records counter would grow it quadratically.
            self._metrics.on_records(server, records - seen)
            seen = records

        pages = paginate(
            fetch,
            page_size=page_size,
            max_records=None,
            on_page=on_page,
        )
        # The cap counts records the caller actually receives: applying it
        # inside paginate counted the ones the local filter then dropped.
        kept = 0
        async for raw in pages:
            if not query.matches_locally(raw):
                continue
            yield raw
            kept += 1
            if query.limit_per_server is not None and kept >= query.limit_per_server:
                return

    async def health(
        self,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> FleetHealthResult:
        """Check the health of every selected server."""

        async def per_server(name: str) -> ServerHealth:
            result = await check_server(self.client(name))
            self._metrics.on_availability(name, result.reachable)
            return result

        envelope = await self._fan_out(self.select(selector), per_server, execution)
        return FleetHealthResult(**envelope.model_dump())

    async def sightings(
        self,
        value: str,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> FederatedSightingsResult:
        """Report who has sighted an indicator value across the fleet.

        Each selected server is asked which attributes carry ``value`` and
        which sightings exist for their events; every record keeps its server,
        event and attribute provenance.
        """

        async def per_server(name: str) -> list[SightingRecord]:
            client = self.client(name)
            fetched_at = datetime.now(tz=UTC)
            attributes = await client.attributes.search(SearchQuery(value=value))
            wanted_uuids = {str(a["uuid"]) for a in attributes if a.get("uuid")}
            event_ids = {str(a["event_id"]) for a in attributes if a.get("event_id")}
            records: list[SightingRecord] = []
            for event_id in sorted(event_ids):
                for sighting in await client.sightings.index(event_id):
                    if sighting.attribute_uuid and sighting.attribute_uuid not in wanted_uuids:
                        continue
                    records.append(
                        SightingRecord(
                            server=name,
                            value=value,
                            sighting_uuid=sighting.uuid,
                            attribute_uuid=sighting.attribute_uuid,
                            event_id=event_id,
                            type=sighting.type,
                            date_sighting=sighting.date_sighting,
                            organisation=sighting.organisation,
                            fetched_at=fetched_at,
                        )
                    )
            return records

        envelope = await self._fan_out(self.select(selector), per_server, execution)
        flattened = [
            record.model_copy(update={"operation_id": envelope.operation_id})
            for name in sorted(envelope.results)
            for record in envelope.results[name]
        ]
        return FederatedSightingsResult(
            **envelope.model_dump(),
            sightings=flattened,
            total_sightings=len(flattened),
        )

    async def add_sighting(
        self,
        value: str,
        selector: ServerSelector | None = None,
        source: str = "",
        sighting_type: str = "0",
        execution: ExecutionOptions | None = None,
    ) -> MultiServerResult[int]:
        """Record a sighting of ``value`` on every selected server.

        The write counterpart of :meth:`sightings`: each server records one
        sighting per attribute matching the value and reports how many it
        created (zero when the indicator is unknown there).
        """

        async def per_server(name: str) -> int:
            client = self.client(name)
            await client.require_capability(CAPABILITY_SIGHTINGS)
            response = await client.sightings.add(value, source=source, sighting_type=sighting_type)
            return _sighting_count(response)

        return await self._fan_out(self.select(selector), per_server, execution)

    async def audit(
        self,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> FleetAuditResult:
        """Audit configuration consistency across the selected servers.

        Collects each server's taxonomies, warninglists, galaxies, feeds and
        object templates concurrently, then reports every key that is missing
        somewhere or configured differently.
        """

        async def per_server(name: str) -> AuditSnapshot:
            return await collect_snapshot(self.client(name))

        envelope = await self._fan_out(self.select(selector), per_server, execution)
        return FleetAuditResult(
            **envelope.model_dump(),
            findings=compare_snapshots(envelope.results),
        )

    async def update_libraries(
        self,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> MultiServerResult[dict[str, str]]:
        """Update the taxonomy, warninglist, galaxy and noticelist libraries fleet-wide.

        This is the remediation counterpart of :meth:`audit` for stale library
        versions: every selected server refreshes its bundled definitions.
        """

        async def per_server(name: str) -> dict[str, str]:
            client = self.client(name)
            return {
                "taxonomies": str((await client.taxonomies.update()).get("message", "updated")),
                "warninglists": str((await client.warninglists.update()).get("message", "updated")),
                "galaxies": str((await client.galaxies.update()).get("message", "updated")),
                "noticelists": str((await client.noticelists.update()).get("message", "updated")),
            }

        return await self._fan_out(self.select(selector), per_server, execution)

    async def set_warninglist(
        self,
        name: str,
        enabled: bool,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> MultiServerResult[str]:
        """Enable or disable one warninglist by name on every selected server."""

        async def per_server(server: str) -> str:
            client = self.client(server)
            for item in await client.warninglists.list():
                warninglist = item.get("Warninglist", item)
                if warninglist.get("name") == name:
                    await client.warninglists.toggle([str(warninglist["id"])], enabled)
                    return f"{name} {'enabled' if enabled else 'disabled'}"
            raise NotFoundError(f"warninglist {name!r} does not exist on {server}")

        return await self._fan_out(self.select(selector), per_server, execution)

    async def set_taxonomy(
        self,
        namespace: str,
        enabled: bool,
        selector: ServerSelector | None = None,
        execution: ExecutionOptions | None = None,
    ) -> MultiServerResult[str]:
        """Enable or disable one taxonomy by namespace on every selected server."""

        async def per_server(server: str) -> str:
            client = self.client(server)
            for item in await client.taxonomies.list():
                taxonomy = item.get("Taxonomy", item)
                if taxonomy.get("namespace") == namespace:
                    identifier = str(taxonomy["id"])
                    if enabled:
                        await client.taxonomies.enable(identifier)
                    else:
                        await client.taxonomies.disable(identifier)
                    return f"{namespace} {'enabled' if enabled else 'disabled'}"
            raise NotFoundError(f"taxonomy {namespace!r} does not exist on {server}")

        return await self._fan_out(self.select(selector), per_server, execution)

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

        return await self._fan_out(self.select(selector), per_server, execution)

    async def compare_event(
        self,
        event_id: EventIdentifier | str,
        left: str,
        right: str,
    ) -> EventDiff:
        """Fetch one event from two servers and compare normalized content."""
        self.registry.get(left)
        self.registry.get(right)
        # return_exceptions keeps both fetches awaited: letting the first
        # failure propagate would leave the sibling request orphaned.
        left_event, right_event = await asyncio.gather(
            self.client(left).events.get(str(event_id)),
            self.client(right).events.get(str(event_id)),
            return_exceptions=True,
        )
        if isinstance(left_event, BaseException):
            raise left_event
        if isinstance(right_event, BaseException):
            raise right_event
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
        plan = await build_copy_plan(
            self.client(source),
            self.client(destination),
            str(event_id),
            self.policy_engine,
            policy=policy,
            on_conflict=on_conflict,
        )
        if any(issue.code == "policy-violation" for issue in plan.blocking_errors):
            self._metrics.on_policy_rejection(policy or "")
        if plan.blocking_errors:
            self._metrics.on_plan_validation_failure(plan.kind)
        if self._state is not None:
            await self._state.save_plan(
                PlanRecord(
                    plan_id=plan.plan_id,
                    kind=plan.kind,
                    schema_version=plan.schema_version,
                    fingerprint=plan.fingerprint(),
                    source_server=plan.source_server,
                    destination_server=plan.destination_server,
                    event_identifier=str(plan.source_event_uuid),
                    policy=plan.policy,
                    on_conflict=str(plan.on_conflict),
                    generated_at=plan.generated_at,
                    expires_at=plan.expires_at,
                    transformations=len(plan.transformations),
                    validations=len(plan.validations),
                    warnings=len(plan.warnings),
                    blocking_errors=len(plan.blocking_errors),
                )
            )
        return plan

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
                    actor=self._actor,
                )
            )
        return result

    async def _record_query(
        self,
        query: SearchQuery,
        operation: str,
        servers: list[str],
        record_count: int,
    ) -> None:
        if self._state is None:
            return
        await self._state.save_query(
            QueryRecord(
                fingerprint=query.fingerprint(),
                operation=operation,
                servers=list(servers),
                executed_at=datetime.now(tz=UTC),
                record_count=record_count,
            )
        )

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
                actor=self._actor,
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
        """Close every cached client, even when one of them fails to close.

        A TaskGroup would cancel the siblings of the first failure, leaving
        their connection pools open; gather lets every close run to completion.
        """
        # The gate shuts first, then we wait out the builds already past it:
        # _fan_out builds clients on a worker thread that a cancelled await
        # does not stop, and draining ahead of one left its transport open
        # with nothing remaining to close it.
        self._closed = True
        while True:
            with self._clients_lock:
                if not self._building:
                    clients = [*self._clients.values(), *self._discarded]
                    self._clients.clear()
                    self._discarded.clear()
                    break
            await asyncio.sleep(0.005)
        outcomes = await asyncio.gather(
            *(client.aclose() for client in clients), return_exceptions=True
        )
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                raise outcome
