# Compatibility & troubleshooting

## MISP compatibility

Behavior is driven by **discovered capabilities**, not version strings:
`client.system.capabilities()` derives the capability set (`rest-search`,
`events`, `version`, `sync`, `sightings`, `galaxies`) from
`/servers/getVersion` metadata. When a server lacks a required capability the
operation fails with `CapabilityError` identifying the server and the missing
capability, while other servers continue if the failure policy permits.

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
- `object_name` filtering on `/attributes/restSearch` is ignored by older
  2.4 builds, which return unfiltered results rather than an error.
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
