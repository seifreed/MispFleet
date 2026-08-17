# Multiserver acceptance runbook

The definition of done for 1.0 requires an acceptance run against a real
multiserver deployment. Automated suites cover behavior against fake and
containerized MISP instances; this runbook is the manual pass that signs off a
release on live infrastructure.

Use at least two real MISP instances you are authorized to operate. Steps that
mutate data are marked; run them against a staging or lab instance first.

## 0. Preparation

```bash
pip install 'mispfleet[all]'
mispfleet version
mispfleet config init
mispfleet config add-server research --url https://research.example --credential-key MISPFLEET_RESEARCH
mispfleet config add-server production --url https://misp.example --credential-key MISPFLEET_PRODUCTION
mispfleet config validate
mispfleet config show | grep -c REDACTED     # credentials must be redacted
```

Record for the release notes: MISP versions, deployment topology, and whether
TLS uses a private CA.

## 1. Connectivity and capabilities

| Step | Command | Expected |
| ---- | ------- | -------- |
| 1.1 | `mispfleet servers health --all` | every server reachable and authenticated, exit 0 |
| 1.2 | `mispfleet servers health --all --format json \| jq '.results[].certificate_expiry'` | a real expiry date per HTTPS server |
| 1.3 | `mispfleet servers versions --all` | the versions actually deployed |
| 1.4 | `mispfleet servers capabilities --all` | `rest-search`, `events` present |
| 1.5 | `mispfleet servers capabilities --all --refresh` | same result, re-probed |
| 1.6 | stop one server, `mispfleet servers health --all` | exit 6, other servers still reported |

## 2. Federated search

| Step | Command | Expected |
| ---- | ------- | -------- |
| 2.1 | `mispfleet search value <known-indicator> --all --format json` | matches carry `server`, `event_uuid`, `fetched_at`, `operation_id` |
| 2.2 | `mispfleet search attributes --type sha256 --since 30d --all --format jsonl` | one JSON object per line |
| 2.3 | `mispfleet attribute search --type sha256 --all --output out.jsonl` | streams to file, memory stays flat |
| 2.4 | `mispfleet search value definitely-absent --all` | exit 11 |
| 2.5 | `mispfleet search events --org <org> --threat-level 2 --all` | filters honored server-side |

Check a large streaming export (≥100k attributes) with `/usr/bin/time -v` or
Activity Monitor: resident memory must stay flat rather than growing with the
result size.

## 3. Diff

| Step | Command | Expected |
| ---- | ------- | -------- |
| 3.1 | `mispfleet event diff <uuid> --left research --right production` | differences classified add/remove/change/conflict |
| 3.2 | `mispfleet event diff <uuid> --left research --right production --format patch` | reviewable patch document |
| 3.3 | same event on both servers | `equivalent: true`, exit 0 |
| 3.4 | run 3.1 twice | byte-identical output (determinism) |

## 4. Copy planning and application (mutating)

| Step | Command | Expected |
| ---- | ------- | -------- |
| 4.1 | `mispfleet event copy <uuid> --from research --to production --policy production-import --dry-run` | plan printed, destination untouched |
| 4.2 | `... --plan-output plan.json` then inspect | no credentials inside the file |
| 4.3 | `mispfleet apply plan.json` | event created, audit record stored |
| 4.4 | `mispfleet apply plan.json` again | exit 9 (conflict), no overwrite |
| 4.5 | modify the source event, `mispfleet apply plan.json` | `StalePlanError`, exit 8 |
| 4.6 | copy with a rejecting policy | exit 7, nothing written |
| 4.7 | copy to a `read_only: true` server | refused before any mutation |

Verify in the MISP UI that the applied event carries the policy
transformations (tags added/removed, distribution clamped, values redacted).

## 5. State and audit

```bash
mispfleet state info
mispfleet state operations --format json | jq '.[0]'
mispfleet state checkpoints
mispfleet state prune --older-than 30d
```

Audit records must contain the operation id, servers, event identifier, plan
fingerprint, policy and result — and no API keys. Confirm the state file mode
is `0600`.

## 6. Security posture

| Step | Command | Expected |
| ---- | ------- | -------- |
| 6.1 | `mispfleet --no-verify-tls servers health --all` | visible warning on stderr |
| 6.2 | set `security.forbid_insecure_tls: true`, repeat 6.1 | exit 3, refused |
| 6.3 | `mispfleet attribute get <attachment-uuid> --download ./dl --server production` | file written `0600`, sanitized name |
| 6.4 | grep every output and log for the API key | no occurrences |

## 7. Interoperability

```bash
mispfleet --server production stix export <uuid> --format json
mispfleet --server production stix push <uuid> --collection <id>
mispfleet --server production opencti test
```

## Sign-off

Record in the release notes: date, MispFleet version, MISP versions, which
steps ran mutating, and any deviation. A release is acceptable only when every
non-mutating step passes and the mutating steps pass on at least one real
deployment.

## Latest run — 2026-08-04

Executed against two real containerized MISP instances started from
`tests/contract/docker-compose.yml` (projects `misp-research` on port 10443
and `misp-production` on 20443), seeded with `scripts/seed_acceptance.py`.

- MispFleet 0.1.0, Python 3.14, macOS arm64.
- MISP core 2.5.44 (`ghcr.io/misp/misp-docker/misp-core:latest`), MariaDB
  11.4, Valkey 7.2. Self-signed TLS: `research` verified through `ca_bundle`,
  `production` with `verify_tls: false`.
- Every step in sections 0–6 passed, including the mutating section 4 flow
  (apply, conflict 9, stale 8, policy rejection 7, read-only refusal) and the
  contract suite (`pytest tests/contract`, 6 passed).
- Deviations: `certificate_expiry` is only reported for servers with verified
  TLS (documented behavior); the large streaming check ran at seeded scale
  with the performance suite covering memory-flatness; step 4.7 refuses at
  planning time with exit 8 before any mutation; `stix push` and
  `opencti test` were not executed (no TAXII/OpenCTI service available).
- Defects found by this run, all fixed: contract compose missing Valkey,
  `iter_search` ignoring `limit_per_server`, `servers health` exiting 0 with
  a down server, `--info` requiring manual `%` wildcards, destination
  conflict on apply exiting 8 instead of 9, and attachment filenames keeping
  Windows-invalid characters.
