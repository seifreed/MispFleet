# Python API

The top-level package exposes the stable public API:

```python
from mispfleet import (
    MispClient,
    MispFleet,
    MetricsSink,
    SearchQuery,
    ServerConfig,
    ServerSelector,
    ExecutionOptions,
    FailurePolicy,
    FederatedSearchResult,
    EventDiff,
    CopyPlan,
    MispFleetError,
)
```

## Single-server client

```python
async with MispClient(config, api_key="...") as client:
    event = await client.events.get("event-uuid")
    async for attribute in client.attributes.iter_search(query, page_size=1000):
        ...
    capabilities = await client.system.capabilities()
```

Service namespaces: `events`, `attributes`, `objects`, `tags`, `taxonomies`,
`galaxies`, `warninglists`, `templates`, `organisations`, `servers`, `system`.

## Fleet

```python
async with await MispFleet.from_file(path) as fleet:
    result = await fleet.search(query, selector=ServerSelector.group("all"))
    health = await fleet.health()
    events = await fleet.get_event(uuid, ServerSelector.names("production"))
    diff = await fleet.compare_event(uuid, "production", "research")
    plan = await fleet.plan_copy(uuid, "research", "production", policy="production-import")
    outcome = await fleet.apply(plan)
```

## Result envelope

Every multiserver operation returns a `MultiServerResult[T]` with
`operation_id`, timings, `requested/successful/failed_servers`, per-server
`results`, typed `errors` and `warnings`. `result.partial` is `True` when any
server failed — a partial result is never presented as a total success.
Failure policies (`continue`, `fail-fast`, `require-all`, `require-any`)
select between data-based and exception-based (`PartialFleetError`) behavior.

## Metrics

Instrumentation is exposed through callbacks; MispFleet never starts a metrics
server. Subclass `MetricsSink`, override the hooks you need and pass it to the
fleet or the client:

```python
from mispfleet import MetricsSink, MispFleet

class PrometheusSink(MetricsSink):
    def on_request(self, server, endpoint, duration_seconds, status):
        REQUESTS.labels(server, endpoint, status).observe(duration_seconds)

    def on_availability(self, server, available):
        UP.labels(server).set(1 if available else 0)

fleet = await MispFleet.from_file(metrics=PrometheusSink())
```

Available hooks: `on_request`, `on_retry`, `on_error`, `on_page`,
`on_records`, `on_availability`, `on_policy_rejection` and
`on_plan_validation_failure`. Every hook is a no-op by default, so partial
implementations are fine.

For deployments that already collect OpenTelemetry, `OTelMetricsSink` publishes
the same callbacks as OTel instruments (`pip install 'mispfleet[telemetry]'`):

```python
from mispfleet.observability import OTelMetricsSink

fleet = await MispFleet.from_file(metrics=OTelMetricsSink())
```

It uses the global meter unless one is passed explicitly, and emits
`mispfleet.requests`, `mispfleet.request.duration`, `mispfleet.retries`,
`mispfleet.errors`, `mispfleet.pages`, `mispfleet.records`,
`mispfleet.server.available`, `mispfleet.policy.rejections` and
`mispfleet.plan.validation_failures`.

Transport debug logs carry `server`, `endpoint`, `request_id` and, inside a
fleet operation, `operation_id` — the JSON log formatter emits them as
structured fields.

## Errors

All errors derive from `MispFleetError` and carry a redacted `ErrorContext`
(`operation_id`, `server`, `endpoint`, `status_code`, `retryable`,
`request_id`, `safe_response_excerpt`). See
[Error handling](error-handling.md) for the full hierarchy, the exit-code
mapping and partial-failure semantics.
