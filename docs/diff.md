# Event diff

```bash
mispfleet event diff EVENT_UUID --left production --right research --format json
```

The diff engine compares normalized representations of the same event on two
servers across metadata (info, date, publication state, distribution, sharing
group, threat level, analysis, organisation), tags, attributes, objects,
object attributes, object references, galaxies, sightings and proposals.

Objects are matched by UUID (falling back to their name when a server does not
report one), so several objects of the same type in one event are compared
individually instead of collapsing into a single entry.

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

Output formats: `table` (default), `json`, `yaml`, `jsonl` and `patch`.

`--format patch` renders a deterministic, review-friendly text document:

```text
--- production/9c5c1c2e-0000-4000-8000-00000000000e
+++ research/9c5c1c2e-0000-4000-8000-00000000000e
~ info: 'Campaign X' -> 'Campaign X (edited)'
+ tags[tlp:amber]
- tags[internal-only]
! attributes[domain|evil.example].to_ids: True -> False
@@ added=1 removed=1 changed=1 conflicts=1
```

The symbols map to the difference operations: `+` add, `-` remove, `~` change,
`!` conflict. The trailing `@@` line repeats the summary counters. This format
is only available on `event diff`.
