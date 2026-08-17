# Credential security

API keys are never stored in the configuration file, state database, plans,
logs or exceptions. Configuration only holds *references*:

```yaml
credential:
  provider: env        # env | keyring | prompt | memory | op
  key: MISPFLEET_PRODUCTION_API_KEY
```

## Providers

- **env** — the key names a user-defined environment variable.
- **keyring** — the key names an OS keyring entry under service `mispfleet`
  (requires the `keyring` extra).
- **prompt** — the key is requested interactively once per process; disabled
  with `--non-interactive`.
- **memory** — secrets injected programmatically through the Python API.
- **op** — the key is a 1Password secret reference resolved through the
  locally installed and signed-in [`op` CLI](https://developer.1password.com/docs/cli/):

  ```yaml
  credential:
    provider: op
    key: op://vault/misp-production/api-key
  ```

  No Python dependency is required; the secret only ever travels through the
  pipe between `op read` and MispFleet.

```python
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider

resolver = CredentialResolver({"memory": MemoryCredentialProvider({"production": "..."})})
fleet = MispFleet(servers, resolver=resolver)
```

## Redaction guarantees

Secret redaction covers `Authorization`, `X-API-Key`, cookies, URL userinfo,
known secret-like fields (`api_key`, `password`, `token`, ...) and
user-configured sensitive fields. Redaction applies to logs, exception
context, safe response excerpts, `config show` output and generated plans.
