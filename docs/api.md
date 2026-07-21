# Python API

The top-level package exposes the stable public API:

```python
from mispfleet import (
    MispClient,
    MispFleet,
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

## Errors

All errors derive from `MispFleetError` and carry a redacted `ErrorContext`
(`operation_id`, `server`, `endpoint`, `status_code`, `retryable`,
`request_id`, `safe_response_excerpt`). See `mispfleet.exceptions` for the
full hierarchy (configuration, transport, API, capability, policy, plan,
state, partial fleet).
