# Configuration

## Locations

| Platform | Config | State |
| -------- | ------ | ----- |
| Linux    | `~/.config/mispfleet/config.yml` | `~/.local/state/mispfleet/state.db` |
| macOS    | `~/Library/Application Support/mispfleet/config.yml` | same directory |
| Windows  | `%APPDATA%\mispfleet\config.yml` | `%LOCALAPPDATA%\mispfleet\state.db` |

Paths are resolved with `platformdirs` and can be overridden with
`MISPFLEET_CONFIG` and `MISPFLEET_STATE_PATH`.

## Format

```yaml
version: 1
defaults:
  verify_tls: true
  request_timeout: 60
  connect_timeout: 10
  concurrency: 5
servers:
  production:
    url: https://misp.company.example
    credential:
      provider: env
      key: MISPFLEET_PRODUCTION_API_KEY
    role: primary
    groups: [internal, all]
  partner-cert:
    url: https://misp.partner.example
    credential:
      provider: keyring
      key: partner-cert
    role: partner
    read_only: true
    groups: [partners, all]
policies:
  production-import:
    maximum_distribution: connected-communities
    remove_tags: [internal-only, do-not-share]
    add_tags: ["imported-by:mispfleet"]
    reject_if:
      tags: ["tlp:red"]
security:
  forbid_insecure_tls: true
state:
  backend: sqlite
  capability_ttl_seconds: 3600
profiles:
  lab:
    defaults:
      request_timeout: 5
```

## Precedence

Highest first:

1. Explicit method or CLI arguments (`--timeout`, `--concurrency`, ...).
2. Environment variables (`MISPFLEET_CONFIG`, `MISPFLEET_PROFILE`,
   `MISPFLEET_OUTPUT`, `MISPFLEET_LOG_LEVEL`, `MISPFLEET_NO_COLOR`,
   `MISPFLEET_STATE_PATH`, `MISPFLEET_ACTOR`).
3. The selected configuration profile (`--profile` / `MISPFLEET_PROFILE`).
4. The main configuration file.
5. Built-in defaults.

## Server fields

Every server accepts: `url`, `credential`, `enabled`, `read_only`,
`verify_tls`, `ca_bundle`, `client_certificate`, `client_key`, `tags`,
`groups`, `role` (`general`, `primary`, `research`, `partner`),
`request_timeout`, `connect_timeout`, `concurrency`, `rate_limit`, `retry`
(`max_attempts`, `initial_delay`, `multiplier`, `max_delay`, `jitter`,
`respect_retry_after`), `proxy`, `allow_insecure_http`, `http2`,
`max_keepalive_connections`, `keepalive_expiry` and `max_response_bytes`.

`http2: true` needs the optional extra (`pip install 'mispfleet[http2]'`) and
falls back to HTTP/1.1 when the server does not negotiate HTTP/2. Keepalive
settings map to the connection pool; unset means httpx defaults.

Plain `http://` URLs are rejected unless `allow_insecure_http: true` is set
explicitly. Duplicate server names (case-insensitive) are rejected.

## Fleet-wide sections

`defaults` accepts the transport subset applied to every server
(`verify_tls`, `request_timeout`, `connect_timeout`, `concurrency`, `http2`,
`max_keepalive_connections`, `keepalive_expiry`, `max_response_bytes`).

`security.forbid_insecure_tls: true` refuses any configuration or CLI flag
that would disable TLS verification. `state` selects the backend (`sqlite` or
`mariadb`), its location and `capability_ttl_seconds`, the lifetime of cached
server capabilities. Unknown keys in these sections are configuration errors,
not silently ignored settings.
