"""Integration tests for the OpenTelemetry metrics sink using the real SDK."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from mispfleet.exceptions import ConfigurationError
from mispfleet.observability import OTelMetricsSink, load_otel_module
from tests.support import contains, eq, ok


def collected(reader: InMemoryMetricReader) -> dict[str, list[Any]]:
    """Flatten the exported metrics into ``{instrument name: data points}``."""
    data = reader.get_metrics_data()
    points: dict[str, list[Any]] = {}
    for resource_metric in data.resource_metrics if data else []:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                points.setdefault(metric.name, []).extend(metric.data.data_points)
    return points


def sink_with_reader() -> tuple[OTelMetricsSink, InMemoryMetricReader]:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    return OTelMetricsSink(meter=provider.get_meter("mispfleet-test")), reader


def test_otel_sink_publishes_every_metric_concept() -> None:
    sink, reader = sink_with_reader()
    sink.on_request("alpha", "/servers/getVersion", 0.25, 200)
    sink.on_retry("alpha", "/servers/getVersion")
    sink.on_error("alpha", "/servers/getVersion", "timeout")
    sink.on_page("alpha", 1, 500)
    sink.on_records("alpha", 500)
    sink.on_availability("alpha", True)
    sink.on_availability("beta", False)
    sink.on_policy_rejection("strict")
    sink.on_plan_validation_failure("copy")
    points = collected(reader)
    eq(points["mispfleet.requests"][0].value, 1)
    eq(points["mispfleet.retries"][0].value, 1)
    eq(points["mispfleet.errors"][0].value, 1)
    eq(points["mispfleet.pages"][0].value, 1)
    eq(points["mispfleet.records"][0].value, 500)
    eq(points["mispfleet.policy.rejections"][0].value, 1)
    eq(points["mispfleet.plan.validation_failures"][0].value, 1)
    availability = {
        point.attributes["server"]: point.value for point in points["mispfleet.server.available"]
    }
    eq(availability, {"alpha": 1, "beta": 0})
    duration = points["mispfleet.request.duration"][0]
    eq(duration.count, 1)
    ok(duration.sum >= 0.25)
    eq(duration.attributes["status"], 200)


def test_otel_sink_uses_the_global_meter_by_default() -> None:
    sink = OTelMetricsSink()
    sink.on_records("alpha", 3)
    ok(isinstance(sink, OTelMetricsSink))


def test_otel_sink_reports_the_missing_extra() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        OTelMetricsSink(module_name=f"missing_otel_{uuid4().hex}")
    contains(str(excinfo.value), "mispfleet[telemetry]")


def test_load_otel_module_returns_the_real_api() -> None:
    import opentelemetry.metrics

    eq(load_otel_module("opentelemetry.metrics"), opentelemetry.metrics)


def test_availability_counts_state_not_probes() -> None:
    """Adding a delta per probe made the value a probe tally.

    Five successes then three failures read as "available" instead of down.
    """
    sink, reader = sink_with_reader()
    for _ in range(5):
        sink.on_availability("alpha", True)
    for _ in range(3):
        sink.on_availability("alpha", False)
    points = collected(reader)
    availability = {
        point.attributes["server"]: point.value for point in points["mispfleet.server.available"]
    }
    eq(availability, {"alpha": 0})
    sink.on_availability("alpha", True)
    points = collected(reader)
    availability = {
        point.attributes["server"]: point.value for point in points["mispfleet.server.available"]
    }
    eq(availability, {"alpha": 1})
