# Security model

## Network security

- TLS verification is enabled by default; disabling it logs a visible warning.
- `--no-verify-tls` disables verification fleet-wide and prints a warning on
  stderr before any request is made.
- `security.forbid_insecure_tls: true` refuses both `verify_tls: false` in the
  configuration and the `--no-verify-tls` flag (exit code 3).
- Plain `http://` URLs require an explicit `allow_insecure_http: true` opt-in.
- Redirects are never followed; an unexpected redirect is a typed error.
- Custom CA bundles and mutual TLS are supported per server.
- Proxies are explicit per-server configuration.
- Response bodies are size-limited (`max_response_bytes`, 50 MB default).

```yaml
security:
  forbid_insecure_tls: true
```

Health checks report the real certificate expiry: for HTTPS servers the peer
certificate is inspected with the same trust settings used for requests, and
`certificate_expiry` is populated from its `notAfter` field.

## Secrets

- Configuration stores credential *references*, never values.
- The state database never stores API keys.
- Plans, audit records, logs, exceptions and debug excerpts are redacted.
- `config show` redacts credential blocks.

## Local security

- `config init` and `add-server` write the config file with mode `0600`.
- The SQLite state database is created with mode `0600`.
- Exported plans exclude secrets by construction.

### Attachments

Attachment handling (`mispfleet attribute get --download DIR`, and the
`mispfleet.attachments` helpers) applies four rules:

- Remote filenames are sanitized: directory separators, `..`, control
  characters and Windows reserved names cannot escape or shadow anything.
- Payloads are written through `mkstemp` inside the destination directory and
  renamed into place with mode `0600`; an existing file is never overwritten.
- Archive extraction resolves every member against the destination root and
  refuses anything that escapes it (path traversal).
- Archive members flagged as symlinks are rejected outright.

Violations raise `AttachmentSecurityError`, which the CLI maps to exit code
`13`.

## Retry safety

Only idempotent requests are retried (429/502/503/504, connection resets,
timeouts). Mutating requests are attempted exactly once because independent
MISP servers offer no idempotency guarantee — there is no cross-server
transaction and MispFleet never pretends otherwise.

## Supply chain

CI runs `black`, `ruff`, `mypy`, `pytest` (100% coverage), `bandit`,
`pip-audit`, CodeQL and gitleaks secret scanning, installing from the pinned
`requirements.lock` so builds are reproducible. Releases are published to PyPI
via GitHub Actions Trusted Publishing (OIDC, no long-lived tokens) with build
provenance attestations, after a TestPyPI validation run. Dependabot keeps
dependencies current.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/seifreed/MispFleet/blob/main/SECURITY.md)
for the private reporting channel and disclosure policy.
