"""Metrics callbacks and operation context (§27.2).

Metrics are exposed through a callback sink instead of an HTTP server:
subclass :class:`MetricsSink`, override the hooks you care about and pass
the instance to :class:`~mispfleet.fleet.MispFleet` or
:class:`~mispfleet.client.MispClient`.

:class:`OTelMetricsSink` bridges those callbacks to OpenTelemetry for
deployments that already collect it (optional ``telemetry`` extra).
"""

from __future__ import annotations

import importlib
from contextvars import ContextVar
from types import ModuleType
from typing import Any

from mispfleet.exceptions import ConfigurationError

current_operation_id: ContextVar[str | None] = ContextVar("mispfleet_operation_id", default=None)
"""Operation identifier attached to structured log records during fleet runs."""


class MetricsSink:
    """Instrumentation hooks; every hook is a no-op by default.

    Hooks are called inline on the request path and their exceptions are not
    caught: a hook that raises turns a successful request into a failure, so
    an implementation must swallow its own errors.
    """

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


def load_otel_module(module_name: str = "opentelemetry.metrics") -> ModuleType:
    """Import the OpenTelemetry metrics API, translating a missing extra."""
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        raise ConfigurationError(
            "OpenTelemetry metrics require the 'telemetry' extra: "
            "pip install 'mispfleet[telemetry]'"
        ) from error


class OTelMetricsSink(MetricsSink):
    """Publishes the metric callbacks through an OpenTelemetry meter.

    The instruments follow the metric concepts of the build contract: request
    count and duration, retries, errors, records and pages fetched, server
    availability, policy rejections and plan validation failures.
    """

    def __init__(self, meter: Any = None, module_name: str = "opentelemetry.metrics") -> None:
        metrics = load_otel_module(module_name)
        self._meter = meter if meter is not None else metrics.get_meter("mispfleet")
        self._requests = self._meter.create_counter(
            "mispfleet.requests", unit="1", description="HTTP requests sent to MISP servers"
        )
        self._duration = self._meter.create_histogram(
            "mispfleet.request.duration", unit="s", description="HTTP request duration"
        )
        self._retries = self._meter.create_counter(
            "mispfleet.retries", unit="1", description="Retried request attempts"
        )
        self._errors = self._meter.create_counter(
            "mispfleet.errors", unit="1", description="Transport failures"
        )
        self._pages = self._meter.create_counter(
            "mispfleet.pages", unit="1", description="Pages fetched during pagination"
        )
        self._records = self._meter.create_counter(
            "mispfleet.records", unit="1", description="Records fetched from MISP servers"
        )
        self._availability = self._meter.create_up_down_counter(
            "mispfleet.server.available", unit="1", description="Server reachability"
        )
        self._last_availability: dict[str, bool] = {}
        self._policy_rejections = self._meter.create_counter(
            "mispfleet.policy.rejections", unit="1", description="Events rejected by a policy"
        )
        self._plan_failures = self._meter.create_counter(
            "mispfleet.plan.validation_failures",
            unit="1",
            description="Plans generated with blocking validation errors",
        )

    def on_request(self, server: str, endpoint: str, duration_seconds: float, status: int) -> None:
        """Count the request and record its duration."""
        attributes = {"server": server, "endpoint": endpoint, "status": status}
        self._requests.add(1, attributes)
        self._duration.record(duration_seconds, attributes)

    def on_retry(self, server: str, endpoint: str) -> None:
        """Count one retried attempt."""
        self._retries.add(1, {"server": server, "endpoint": endpoint})

    def on_error(self, server: str, endpoint: str, kind: str) -> None:
        """Count one transport failure by kind."""
        self._errors.add(1, {"server": server, "endpoint": endpoint, "kind": kind})

    def on_page(self, server: str, page: int, records: int) -> None:
        """Count one fetched page."""
        self._pages.add(1, {"server": server})

    def on_records(self, server: str, records: int) -> None:
        """Count the records fetched from one server."""
        self._records.add(records, {"server": server})

    def on_availability(self, server: str, available: bool) -> None:
        """Record whether a server answered its health probe.

        Only transitions are counted, so the value is the number of servers
        currently available. Adding a delta per probe made it a probe tally:
        five successes then three failures read as "available".
        """
        previous = self._last_availability.get(server)
        if previous is available:
            return
        self._last_availability[server] = available
        # A first observation that is already down contributes 0, not -1: the
        # counter would otherwise go negative for a server never seen up.
        delta = 1 if available else -1 if previous is not None else 0
        self._availability.add(delta, {"server": server})

    def on_policy_rejection(self, policy: str) -> None:
        """Count one policy rejection."""
        self._policy_rejections.add(1, {"policy": policy})

    def on_plan_validation_failure(self, plan_kind: str) -> None:
        """Count one plan blocked by validation."""
        self._plan_failures.add(1, {"kind": plan_kind})
