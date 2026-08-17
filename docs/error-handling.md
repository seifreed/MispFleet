# Error handling

MispFleet never turns a failure into a silent success. Errors are typed
exceptions in Python, structured data in machine output, and documented exit
codes in the CLI.

## Exception hierarchy

Every error derives from `MispFleetError`, which carries a `message` and an
`ErrorContext` (server, endpoint, request id, status code, retryability, and a
redacted response excerpt).

```
MispFleetError
├── ConfigurationError
│   ├── InvalidConfigurationError
│   └── CredentialResolutionError
├── TransportError
│   ├── ConnectionError
│   ├── TLSVerificationError
│   ├── RequestTimeoutError
│   ├── ResponseTooLargeError
│   └── InvalidResponseError
├── APIError
│   ├── AuthenticationError
│   ├── PermissionDeniedError
│   ├── NotFoundError
│   ├── ConflictError
│   ├── RateLimitError
│   ├── ValidationError
│   └── MispServerError
├── CapabilityError
├── PolicyError
│   ├── PolicyViolationError
│   └── PolicyConfigurationError
├── PlanError
│   ├── StalePlanError
│   └── UnsafePlanError
├── StateError
├── AttachmentSecurityError
└── PartialFleetError
```

`mispfleet.exceptions.ConnectionError` shadows the Python builtin, so the
library also exports `ConnectionFailedError` as an alias of the same class and
uses that name internally. Catching either works:

```python
from mispfleet.exceptions import ConnectionFailedError, TransportError

try:
    await fleet.health()
except ConnectionFailedError:      # same class as mispfleet.exceptions.ConnectionError
    ...
except TransportError:             # or catch the whole transport family
    ...
```

## Exception to exit code

| Exception | Exit code |
| --------- | --------- |
| `TLSVerificationError`, `AttachmentSecurityError` | 13 (security validation) |
| `AuthenticationError` | 4 |
| `ConfigurationError`, `PolicyConfigurationError` | 3 |
| `ConflictError` | 9 |
| `PolicyError` | 7 |
| `PlanError` | 8 |
| `CapabilityError` | 10 |
| `TransportError` | 5 |
| `PartialFleetError` | 6 |
| any other `MispFleetError` | 1 |

Two exit codes are produced by the command layer rather than by an exception:
`11` when a search or lookup finds nothing, and `12` when the user interrupts
the run. Usage mistakes (unknown option, missing `--server`, unsupported
`--format`) exit `2`. The full list lives in the
[CLI reference](cli.md#exit-codes).

## Partial fleet failures

Fleet-wide operations do not abort when one server misbehaves. Each result
envelope reports what happened everywhere:

```python
result = await fleet.search(SearchQuery(value="evil.example"))
if result.partial:
    for name in result.failed_servers:
        error = result.errors[name]
        print(name, error.kind, error.message, error.retryable)
```

`complete` means every requested server answered; `partial` means at least one
failed while others succeeded. The CLI exits `6` for a partial result and
still writes a complete, valid document — structured output stays parseable
even when the exit code is non-zero.

The behavior is selected by the failure policy:

| Policy | Meaning |
| ------ | ------- |
| `continue` (default) | collect every outcome, succeed with partial data |
| `fail-fast` | cancel outstanding requests on the first failure |
| `require-all` | raise `PartialFleetError` unless every server succeeded |
| `require-any` | raise `PartialFleetError` only if every server failed |

```python
from mispfleet import ExecutionOptions, FailurePolicy

options = ExecutionOptions(failure_policy=FailurePolicy.REQUIRE_ALL, max_concurrency=4)
result = await fleet.search(query, execution=options)
```

## Retries

The transport retries only failures that are safe to retry: connection resets,
transient DNS failures, read timeouts on idempotent requests, and HTTP 429,
502, 503 and 504. Mutating requests are never retried, because MISP gives no
idempotency guarantee for writes.

Backoff defaults to 4 attempts, 0.5 s initial delay, multiplier 2, capped at
30 s, with jitter, honoring `Retry-After`. Tune it per server:

```yaml
servers:
  partner-circl:
    retry:
      max_attempts: 6
      initial_delay: 1.0
      max_delay: 60.0
      jitter: true
      respect_retry_after: true
```

Errors that are never retried: 400, 401, 403, 404, validation errors and
policy violations.

## Machine-readable errors

JSON and YAML output always include the operation envelope, so failures are
data rather than text on stderr:

```bash
mispfleet --format json search value evil.example --all | jq '.failed_servers, .errors'
```

Human-facing messages go to stderr; machine output goes to stdout or to the
path given by `--output`. Use `--trace` to get raw tracebacks while debugging;
without it the CLI prints one redacted error line.

## Secrets in errors

API keys never appear in messages, contexts, logs or plan files. Response
excerpts attached to `InvalidResponseError` are truncated and redacted before
they reach a log record or an exception message.
