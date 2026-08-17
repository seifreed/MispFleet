# Health checks

```bash
mispfleet servers health --all
mispfleet servers versions --all
mispfleet servers capabilities --group partners
mispfleet servers test production      # exit 5 unreachable, 4 unauthenticated
mispfleet servers templates diff --left production --right research
```

Each server health result reports reachability, authentication, latency, MISP
version, discovered capabilities, TLS validity and certificate expiry,
warnings (for example disabled TLS verification) and a typed error when the
probe failed. For HTTPS servers the peer certificate is inspected with the
same trust settings used for requests, so `certificate_expiry` reflects the
real `notAfter` date. `tls_valid` is `true` only when the certificate was
actually verified: with `verify_tls` disabled nothing was checked, so it is
`null` (unknown) rather than `true`. Failure kinds are
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

## Fleet configuration audit

```bash
mispfleet servers audit --all
```

Collects every selected server's taxonomies, warninglists, galaxies, feeds
and object templates concurrently and reports each key that is missing
somewhere (`missing`) or configured differently (`mismatch`) — for example a
taxonomy at v9 on research but v7 on production, or a warninglist disabled on
one partner instance. MISP versions are compared as their own dimension. Exit
codes: `0` when consistent, `9` when drift was found, `6` when a server could
not be audited.

```python
result = await fleet.audit()
for finding in result.findings:
    print(finding.dimension, finding.key, finding.kind, finding.values)
```

## Remediation

Once the audit shows drift, fix it from the same CLI. These commands mutate
the servers, so an explicit selector (`--server`, `--group`, `--tag`,
`--role` or `--all`) is required:

```bash
mispfleet servers update-libraries --all          # refresh taxonomies, warninglists,
                                                  # galaxies and noticelists everywhere
mispfleet servers enable-warninglist rfc5735 --all
mispfleet servers enable-taxonomy tlp --group partners
mispfleet servers enable-taxonomy tlp --disable --server research
```

Names are resolved per server; a server that does not know the warninglist or
taxonomy is reported as a typed failure (exit `6`) without affecting the
others.

```python
await fleet.update_libraries(ServerSelector.all())
await fleet.set_warninglist("rfc5735", enabled=True)
await fleet.set_taxonomy("tlp", enabled=True)
```

Discovery results are cached in the state backend (server identity, MISP
version, fetch timestamp, expiry) so repeated `versions` and `capabilities`
calls do not re-probe the fleet. The lifetime is
`state.capability_ttl_seconds` (one hour by default); `--refresh` invalidates
the entry and probes again:

```bash
mispfleet servers capabilities --all --refresh
```
