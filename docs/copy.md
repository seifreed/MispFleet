# Copy planning & policies

Cross-server copy is a mandatory two-stage operation: **plan**, then **apply**.

```bash
# Review without mutating anything
mispfleet event copy EVENT_UUID --from research --to production \
  --policy production-import --dry-run

# Persist the plan for review, then apply it later
mispfleet event copy EVENT_UUID --from research --to production \
  --policy production-import --plan-output copy-plan.json
mispfleet apply copy-plan.json
```

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
- the destination conflict situation still matches the plan.

If the destination already contains the event UUID the default is **abort**;
`skip`, `update` and `create-new-uuid` must be selected explicitly with
`--on-conflict`. There is no implicit overwrite. Every apply writes a
secret-free audit record to the local state database.

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
