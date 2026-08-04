"""Metrics callbacks and operation context (§27.2).

Metrics are exposed through a callback sink instead of an HTTP server:
subclass :class:`MetricsSink`, override the hooks you care about and pass
the instance to :class:`~mispfleet.fleet.MispFleet` or
:class:`~mispfleet.client.MispClient`.
"""

from __future__ import annotations

from contextvars import ContextVar

current_operation_id: ContextVar[str | None] = ContextVar("mispfleet_operation_id", default=None)
"""Operation identifier attached to structured log records during fleet runs."""


class MetricsSink:
    """Instrumentation hooks; every hook is a no-op by default."""

    def on_request(self, server: str, endpoint: str, duration_seconds: float, status: int) -> None:
        """One HTTP request completed with a status code."""

    def on_retry(self, server: str, endpoint: str) -> None:
        """One request attempt is being retried."""

    def on_error(self, server: str, endpoint: str, kind: str) -> None:
        """One request failed at the transport level."""

    def on_page(self, server: str, page: int, records: int) -> None:
        """One page of records was fetched during pagination."""

    def on_records(self, server: str, records: int) -> None:
        """Records were fetched from a server."""

    def on_availability(self, server: str, available: bool) -> None:
        """A health probe classified a server as reachable or not."""

    def on_policy_rejection(self, policy: str) -> None:
        """A policy rejected an event."""

    def on_plan_validation_failure(self, plan_kind: str) -> None:
        """A plan was generated with blocking validation errors."""
