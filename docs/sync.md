# Synchronization

Declarative, repeatable synchronization jobs mirror events between two servers
through the same safe plan → apply model as event copy.

## Configuration

```yaml
sync_jobs:
  partners-mirror:
    left: production
    right: partner-cert
    direction: both            # push | pull | both
    filter_tags: [share:partners]
    policy_left_to_right: production-import
    policy_right_to_left: partner-import
    on_conflict: newer-wins    # skip | newer-wins | prefer-left | prefer-right
```

## CLI

```bash
mispfleet sync list
mispfleet sync plan partners-mirror --plan-output sync-plan.json
mispfleet sync run partners-mirror --dry-run
mispfleet sync run partners-mirror
```

Exit codes: `0` success, `8` plan has blocking errors, `6` a partial failure
during apply.

## How planning works

1. Both servers are enumerated (`/events/index`), optionally filtered by tag.
2. Events present on only one side become copy plans in the allowed direction,
   reusing the copy planner (policies, validations and blocking checks apply).
3. Events present on both sides are compared by canonical fingerprint:
   - identical content counts as *in sync*;
   - diverging content is a conflict, resolved by the job strategy.

## Conflict strategies

| Strategy | Behavior |
| -------- | -------- |
| `skip` (default) | Report the conflict, change nothing. |
| `newer-wins` | Copy the side with the newer MISP timestamp (ties favor the left). |
| `prefer-left` | Always copy left → right. |
| `prefer-right` | Always copy right → left. |

A resolution that a strategy selects is still suppressed when the job direction
forbids it (a `pull` job never pushes, a `push` job never pulls). Conflict
copies apply with `update` semantics; every applied change is audited in local
state with kind `sync-apply`. Partial failures are reported per event and never
abort the rest of the job.
