# Event diff

```bash
mispfleet event diff EVENT_UUID --left production --right research --format json
```

The diff engine compares normalized representations of the same event on two
servers across metadata (info, date, publication state, distribution, threat
level, analysis, organisation), tags, attributes, objects and object
attributes.

Differences are classified:

- `add` — present only on the right server.
- `remove` — present only on the left server.
- `change` — metadata scalar changed.
- `conflict` — the same logical attribute differs (category, to_ids, comment,
  deleted flag or tags).

The result includes a summary (`added`, `removed`, `changed`, `conflicts`) and
`equivalent: true` when the normalized content matches exactly. Volatile
fields (timestamps) never affect equivalence: both servers can report
different modification times for identical content.

Output formats: `table` (default), `json`, `yaml`, `jsonl`.
