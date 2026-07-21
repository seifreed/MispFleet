# Security model

## Network security

- TLS verification is enabled by default; disabling it logs a visible warning.
- Plain `http://` URLs require an explicit `allow_insecure_http: true` opt-in.
- Redirects are never followed; an unexpected redirect is a typed error.
- Custom CA bundles and mutual TLS are supported per server.
- Proxies are explicit per-server configuration.
- Response bodies are size-limited (50 MiB default) to protect memory.

## Secrets

- Configuration stores credential *references*, never values.
- The state database never stores API keys.
- Plans, audit records, logs, exceptions and debug excerpts are redacted.
- `config show` redacts credential blocks.

## Local security

- `config init` and `add-server` write the config file with mode `0600`.
- The SQLite state database is created with mode `0600`.
- Exported plans exclude secrets by construction.

## Retry safety

Only idempotent requests are retried (429/502/503/504, connection resets,
timeouts). Mutating requests are attempted exactly once because independent
MISP servers offer no idempotency guarantee — there is no cross-server
transaction and MispFleet never pretends otherwise.

## Supply chain

CI runs `black`, `ruff`, `mypy`, `pytest` (100% coverage), `bandit`,
`pip-audit`, CodeQL and secret scanning; releases are published to PyPI via
GitHub Actions Trusted Publishing (OIDC, no long-lived tokens). Dependabot
keeps dependencies current.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/seifreed/MispFleet/blob/main/SECURITY.md)
for the private reporting channel and disclosure policy.
