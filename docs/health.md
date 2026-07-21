# Health checks

```bash
mispfleet servers health --all
mispfleet servers versions --all
mispfleet servers capabilities --group partners
mispfleet servers test production      # exit 5 unreachable, 4 unauthenticated
mispfleet servers templates diff --left production --right research
```

Each server health result reports reachability, authentication, latency, MISP
version, discovered capabilities, warnings (for example disabled TLS
verification) and a typed error when the probe failed. Failure kinds are
distinguished through the error `kind` (connection, TLS, timeout,
authentication, permission, invalid response, MISP application failure).

```python
result = await fleet.health(ServerSelector.all())
for server, health in result.results.items():
    print(server, health.reachable, health.misp_version)
for server, error in result.errors.items():
    print(f"{server}: {error.message}")
```

Capabilities are discovered from `/servers/getVersion` metadata, not version
string comparisons, and drive feature selection across the fleet.
