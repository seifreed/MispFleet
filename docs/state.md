# State backends

MispFleet keeps checkpoints and secret-free audit records in a local state
store. Two backends are available; neither ever stores API keys.

## SQLite (default)

```yaml
state:
  backend: sqlite
  path: /var/lib/mispfleet/state.db   # optional; platform default otherwise
```

The database file is created with mode `0600`.

## MariaDB (shared)

For teams that share operational state across hosts, use the MariaDB backend
(install the extra: `pip install 'mispfleet[mariadb]'`):

```yaml
state:
  backend: mariadb
  dsn: mysql://mispfleet@db.example:3306/fleetstate
  password_env: MISPFLEET_STATE_DB_PASSWORD   # optional
```

The referenced database must already exist; MispFleet creates its tables on
first use. The password is resolved from the named environment variable so it
never appears in the configuration file, and the DSN is redacted before it
appears in any log or error.

## Commands

```bash
mispfleet state info
mispfleet state operations
mispfleet state checkpoints
mispfleet state checkpoint show ID
mispfleet state checkpoint delete ID
mispfleet state prune --older-than 30d
```

All commands work identically against either backend.
