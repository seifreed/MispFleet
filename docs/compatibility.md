# Compatibility & troubleshooting

## MISP compatibility

Behavior is driven by **discovered capabilities**, not version strings:
`client.system.capabilities()` derives the capability set (`rest-search`,
`events`, `version`, `sync`, `sightings`, `galaxies`) from
`/servers/getVersion` metadata. When a server lacks a required capability the
operation fails with `CapabilityError` identifying the server and the missing
capability, while other servers continue if the failure policy permits.

The library targets MISP 2.4/2.5 REST APIs. Contract tests against live MISP
releases (Docker-based) are part of the release checklist; the tested matrix
is documented per release.

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

MispFleet follows semantic versioning; `0.x` releases may change APIs between
minors. The documented public API (`mispfleet` top-level exports) is the
stability contract from `1.0.0` onward.
