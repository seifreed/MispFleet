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
```

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

## Deduplication model

Grouping is deterministic and never merges events:

- `same-value-and-type` — identical normalized value (trimmed, lowercased) and type.
- `same-uuid` — matches sharing an event UUID.

All source records are preserved; only groups with two or more members are reported.
