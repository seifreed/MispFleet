# Compatibility & troubleshooting

## MISP compatibility

Behavior is driven by **discovered capabilities**, not version strings:
`client.system.capabilities()` derives the capability set (`rest-search`,
`events`, `version`, `sync`, `sightings`, `galaxies`) from
`/servers/getVersion` metadata. When a server lacks a capability an operation
requires, that operation fails with `CapabilityError` identifying the server
and the missing capability, while other servers continue if the failure
policy permits — through a fleet the error is recorded per server, so
`fleet.add_sighting` on a key without `perm_sighting` reports
`kind: CapabilityError` for that server and still records the sighting
everywhere else. Discovery is probed once per client and cached.

The library targets MISP 2.4/2.5 REST APIs.

Capability discovery results are cached in the state backend with the server
identity, MISP version, fetch timestamp and an expiry
(`state.capability_ttl_seconds`, one hour by default). Force a re-probe with
`mispfleet servers capabilities --all --refresh`.

## Contract test matrix

Contract tests run against real MISP releases in Docker
(`tests/contract/docker-compose.yml`, workflow `Contract tests`). They are
manual: the normal suite stays hermetic and skips them unless
`MISPFLEET_CONTRACT_URL` and `MISPFLEET_CONTRACT_KEY` are set.

| | Version |
| --- | --- |
| Oldest supported MISP | 2.4.190 |
| Latest tested MISP | 2.5 (`misp-core:latest`) |

```bash
MISP_IMAGE_TAG=core-v2.5.0 docker compose -f tests/contract/docker-compose.yml up -d
MISPFLEET_CONTRACT_URL=https://localhost:8443 \
MISPFLEET_CONTRACT_KEY=<automation key> \
  pytest tests/contract -q --no-cov
```

### Known API differences

- `/servers/getVersion` exposes `pymisp_recommended_version` only on some
  builds; `api_version` is `None` when absent.
- `object_name` is not part of `/attributes/restSearch` on any build; MISP
  discards it silently and returns unfiltered results. Attribute search
  refuses the filter (exit code `10`) instead of passing the results off as
  scoped.
- `openapi.yaml` declares the `/sightings/add` response as a bare `Sighting`,
  but 2.5.44 returns it under a `Sighting` envelope, and answers with a
  message carrying no leading count when nothing matched. The client accepts
  the envelope, the bare object and the message form.
- `/user_settings/setSetting/{userId}/{settingName}` validates the body
  **per setting**: 2.5.44 accepts `{"path": …}` for `dashboard_access` and
  `publish_alert_filter` but rejects it with HTTP 405 for `homepage`, which
  wants `{"value": {"path": …}}`. The client sends the value it is given
  verbatim, so pass whichever shape the target setting accepts.
- `/collections/index/{filter}` answers HTTP 500 on a stock 2.5.44 for every
  filter, including the two its own enum defines. The endpoint is
  implemented against the specification and left unexercised in the
  acceptance lab.
- Sightings and proposals are only returned by `/events/view` when the
  authenticated user has permission to see them; the diff treats absent
  dimensions as empty rather than as a difference.

### Unsupported functionality

Server-side deletion, user and organisation administration, feed management
and MISP-native synchronization configuration are out of scope: MispFleet
coordinates instances, it does not administer them.

## Troubleshooting

| Symptom | Likely cause / fix |
| ------- | ------------------ |
| exit 3, "configuration file not found" | run `mispfleet config init` or set `MISPFLEET_CONFIG` |
| exit 4 on one server | wrong or expired API key for that server's credential reference |
| exit 5 / `ConnectionFailedError` | DNS/TCP problem; check `mispfleet servers test NAME` |
| exit 13 / `TLSVerificationError` | certificate problem; configure `ca_bundle` rather than disabling verification |
| exit 6 | partial fleet failure; inspect `errors` in the JSON output |
| `StalePlanError` on apply | the source event changed; regenerate the plan |
| pagination warning "not advancing" | the remote dataset changed or the server ignores paging; results were truncated safely |

## Upgrades

See [Migration & upgrades](migration.md) for the versioning policy, the
configuration and state schema evolution, and the post-upgrade checklist.
