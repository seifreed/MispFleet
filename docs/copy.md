# Copy planning & policies

Cross-server copy is a mandatory two-stage operation: **plan**, then **apply**.

```bash
# Review without mutating anything
mispfleet event copy EVENT_UUID --from research --to production \
  --policy production-import --dry-run

# Persist the plan for review, then apply it later
mispfleet event copy plan EVENT_UUID --from research --to production \
  --policy production-import --output copy-plan.json
mispfleet apply copy-plan.json

# Equivalent, as an option on the copy command itself
mispfleet event copy EVENT_UUID --from research --to production \
  --policy production-import --plan-output copy-plan.json
```

`event copy plan` only ever plans: it never applies, whatever the outcome.
Without `--output` it prints the plan; with it, the plan JSON is written to that
path for review and later `mispfleet apply`. `event copy` without the `plan`
subcommand plans and then applies, unless `--dry-run` or `--plan-output` is
given.

## What a plan contains

A `CopyPlan` is a credential-free JSON document with the source fingerprint,
the fully transformed proposed event, every policy transformation, validation
results, warnings and blocking errors. Regenerating an identical plan yields
an identical `fingerprint()`.

## Safety model

Before applying, MispFleet re-validates that:

- the plan has no blocking errors and has not expired;
- source and destination servers match the plan;
- the destination is still writable;
- the source event still matches the planned fingerprint (`StalePlanError` otherwise);
- for `update` and `merge`, the destination event still matches the
  fingerprint recorded when the plan was reviewed (`StalePlanError`
  otherwise), so an analyst enriching that side between review and apply is
  never overwritten with older content;
- the destination conflict situation still matches the plan.

If the destination already contains the event UUID the default is **abort**;
`skip`, `update`, `create-new-uuid` and `merge` must be selected explicitly
with `--on-conflict`. There is no implicit overwrite. Every apply writes a
secret-free audit record to the local state database.

`create-new-uuid` regenerates the UUID of the event **and of every attribute,
object and object reference it carries**, rewriting references so they still
point inside the new event. MISP enforces server-wide uniqueness for those
child UUIDs, so renaming only the event makes the destination reject every
child and store an empty shell.

`merge` performs a deterministic union: the destination's metadata is kept,
attributes are united by their `(type, value)` pair (the destination's copy
wins on overlap), objects by UUID, galaxies by UUID with their clusters
united, and tags are the set union. Nothing is ever removed from the
destination.

## Policies

Declarative policies transform and validate events before mutation:

```yaml
policies:
  production-import:
    maximum_distribution: connected-communities   # organisation|community|connected-communities|all-communities
    remove_tags: [internal-only]
    add_tags: ["imported-by:mispfleet"]
    rename_tags: {"tlp:green": "tlp:clear"}
    required_tags: []
    remove_attribute_types: [passport-number]
    reject_attribute_types: [btc]                 # drops those attributes, keeps the event
    remove_comments: true
    set_published: false
    set_to_ids: false                             # force to_ids on every attribute
    redact_values: ['^198\.51\.']                 # regex; matches become ***REDACTED***
    organisation_map: {"Research Org": "Public Org"}
    sharing_group_map: {"1": "9"}                 # event, attribute and object sharing groups
    allowed_object_names: [file, domain-ip]       # anything else rejects the event
    max_attachment_bytes: 10485760                # oversized attachments are stripped
    reject_if:
      tags: ["tlp:red"]
      attribute_types: []                         # rejects the whole event
```

`maximum_distribution` clamps the event and every attribute and object that
carries its own level. It only applies to the widening scale 0-3. MISP's
level 4 (restricted to a named sharing group) and level 5 (inherit the
event's level) are not points on that scale, so they are never rewritten —
lowering them numerically would *widen* the audience. Level 4 is reported as
a warning so you know the maximum could not be enforced numerically; level 5
needs nothing, since it inherits the already-clamped event.

`reject_if.tags`, `remove_tags` and `rename_tags` consider attribute-level
tags as well as event-level ones: an attribute tagged `tlp:red` rejects the
event just like a `tlp:red` event would.

Two ways to deal with unwanted attribute types: `reject_if.attribute_types`
rejects the **entire event** when one is present, while
`reject_attribute_types` filters those attributes out and lets the rest
through with a warning. `remove_attribute_types` removes them silently.

Policies are deterministic: the same input always produces the same
transformations. Test them locally:

```bash
mispfleet policy list
mispfleet policy show production-import
mispfleet policy test production-import event.json   # exit 7 when rejected
```
