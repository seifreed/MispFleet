# State backends

MispFleet keeps checkpoints and secret-free operational records in a local
state store. Two backends are available; neither ever stores API keys.

## What is stored

| Record | Contents | Pruned by age |
| ------ | -------- | ------------- |
| Checkpoints | resumable position of a paginated operation, with its query fingerprint | yes |
| Operations | audit record of one mutating operation (§35) | yes |
| Plans | metadata of a generated copy plan: id, fingerprint, servers, policy, counters | yes |
| Queries | fingerprint of an executed search, servers touched and record count | yes |
| Capabilities | cached server capabilities and MISP version, with an expiry | no, invalidated explicitly |
| Plugins | discovered plugin entry points | no, refreshed on discovery |

Plans and queries record *metadata*, never event content: a plan record carries
counters and identifiers, while the reviewable plan itself is the JSON document
written by `mispfleet event copy plan --output`.

## SQLite (default)

```yaml
state:
  backend: sqlite
  path: /var/lib/mispfleet/state.db   # optional; platform default otherwise
```

The database file is created with mode `0600`.

## MariaDB (shared)

For teams that share operational state across hosts
(`pip install 'mispfleet[mariadb]'`):

```yaml
state:
  backend: mariadb
  dsn: mysql://mispfleet@db.example:3306/fleetstate
  password_env: MISPFLEET_STATE_DB_PASSWORD   # optional
```

The referenced database must already exist; MispFleet creates its tables on
first use. DSN userinfo is percent-decoded, as URI syntax requires, so a
username or password containing `@` or `:` must be encoded (`p@ss` becomes
`p%40ss`) — and a literal `%` must be written `%25`. The password is resolved from the named environment variable so it
never appears in the configuration file, and the DSN is redacted before it
appears in any log or error.

## Audit actor

Set `MISPFLEET_ACTOR` to record who ran a mutating operation. The value is
stored verbatim in the `actor` field of every operation record and is never
used for authentication:

```bash
MISPFLEET_ACTOR="$USER@$(hostname)" mispfleet apply copy-plan.json
mispfleet --format json state operations | jq '.[0].actor'
```

## Commands

```bash
mispfleet state info          # location and per-record counts
mispfleet state operations
mispfleet state checkpoints
mispfleet state checkpoint show ID
mispfleet state checkpoint delete ID
mispfleet state prune --older-than 30d
```

All commands work identically against either backend.
