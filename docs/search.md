# Federated search

Searches run concurrently against every selected server with bounded
concurrency; results always preserve provenance (server name, event and
attribute identifiers, fetch timestamp, operation id).

## CLI

```bash
mispfleet search value evil.example --all --format json
mispfleet search value HASH --group partners
mispfleet search events --info ransomware --since 30d --all
mispfleet search attributes --type sha256 --tag tlp:green --since 7d \
  --all --format jsonl --output hashes.jsonl
mispfleet search events --org CIRCL --threat-level 2 --analysis 1 --all
mispfleet search attributes --object-name file --timestamp-since 7d --all
mispfleet attribute search --type sha256 --all --output hashes.jsonl
```

Supported criteria: indicator value, attribute or event UUID, numeric event
id, event info text, attribute type, category, tags (required and excluded),
organisations, published state, date range, timestamp range, distribution,
threat level, analysis level, object name, deleted attributes, warning-list
enforcement and metadata-only mode.

`analysis` and `distribution` are applied by MispFleet after fetching, not by
the server: MISP's `restSearch` accepts both in the request body and silently
ignores them (verified against 2.5.44), so filtering server-side would return
every event instead of the scoped subset. Both describe the *containing
event*, matching `/events/index`'s `searchanalysis` and `searchdistribution`.
Because the filter runs locally, `--limit` still caps what each server sends,
so a run may return fewer records than the limit.

`object_name` is honored server-side only by object search: it is absent from
`AttributeRestSearchFilter`, and MISP drops unknown restSearch keys in silence.
An attribute hit carries `object_id` and `object_relation` but never the
object's name, so the criterion cannot be re-applied locally either. Rather
than return unscoped results that look scoped, attribute search now refuses
`--object-name` with exit code `10`.

Exit codes: `0` matches found, `6` partial fleet failure (output stays valid),
`11` no matching records.

## Python

```python
result = await fleet.search(
    SearchQuery(value="evil.example"),
    selector=ServerSelector.group("partners"),
    execution=ExecutionOptions(max_concurrency=20, failure_policy=FailurePolicy.CONTINUE),
)
for group in result.groups:          # deterministic duplicate grouping
    print(group.level, group.key, [m.server for m in group.matches])
```

## Streaming and pagination

`fleet.iter_search` and `client.attributes.iter_search` stream records page by
page without materializing the dataset, detect non-advancing pagination, honor
`limit_per_server` and expose an `on_page` hook for checkpointing:

```python
async for match in fleet.iter_search(query, selector=ServerSelector.all()):
    await process(match)
```

## Federated sightings

Ask who has sighted an indicator anywhere in the fleet:

```bash
mispfleet search sightings evil.example --all
```

```python
result = await fleet.sightings("evil.example")
for record in result.sightings:
    print(record.server, record.event_id, record.date_sighting, record.organisation)
```

Every record keeps its server, event and attribute provenance. Exit codes
follow the search conventions: `11` when nothing was sighted, `6` on partial
fleet failure.

The write counterpart propagates a confirmation to the whole fleet — each
server records one sighting per attribute matching the value. It mutates the
servers, so an explicit selector is required:

```bash
mispfleet sightings push evil.example --all --source "soc-triage"
```

```python
result = await fleet.add_sighting("evil.example", source="soc-triage")
print(result.results)   # {"research": 1, "production": 0, ...}
```

Exit codes: `0` when at least one sighting was recorded, `11` when no server
knew the indicator, `6` on partial failure.

## Deduplication model

Grouping is deterministic and never merges events:

- `same-value-and-type` — identical normalized value (trimmed, lowercased) and type.
- `same-uuid` — matches sharing an event UUID.
- `shared-indicators` — two distinct events share at least two identical
  `type|value` indicators.
- `possible-match` — the deterministic similarity score (attribute overlap,
  tag overlap and event-info similarity, weighted 0.5/0.2/0.3) reaches 0.7
  without that much hard overlap.

All source records are preserved; only groups with two or more members are
reported, and nothing is ever merged automatically.
