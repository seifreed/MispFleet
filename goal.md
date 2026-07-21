He interpretado SCC como el documento maestro de Scope, Context & Constraints que servirá como contrato técnico para implementar el repositorio con Codex/Claude y evitar desviaciones.

MispFleet — Scope, Context & Constraints

Document status: Draft for implementation
Project name: MispFleet
Package name: mispfleet
CLI command: mispfleet
Target runtime: Python 3.14
Distribution: PyPI
License: Apache-2.0
Project type: Open-source Python library and command-line interface
Primary domain: MISP federation, multi-instance management and automation

⸻

1. Project vision

MispFleet is an asynchronous Python library and CLI for operating multiple MISP instances as a coordinated fleet.

The project must allow security analysts, threat intelligence teams and automation platforms to:

* Configure and manage multiple MISP instances.
* Query several MISP servers concurrently.
* Aggregate and normalize results.
* Identify duplicated or conflicting intelligence.
* Compare events across instances.
* Copy events safely between servers.
* Apply transformation and sharing policies.
* Run repeatable synchronization jobs.
* Export results in machine-readable formats.
* Integrate the same functionality into Python applications.

MispFleet is not intended to be another thin wrapper around a single MISP REST API.

Its differentiator is the orchestration layer:

Query, compare, govern and synchronize multiple MISP instances through one consistent asynchronous interface.

⸻

2. Product principles

The implementation must follow these principles:

1. Library first
    Every meaningful operation must be implemented in the Python library. The CLI must be a presentation and interaction layer over the public library API.
2. Async by default
    All network operations must be asynchronous.
3. Multiserver by design
    A server collection is a first-class abstraction, not a loop added around a single-server client.
4. Safe by default
    Read operations may run directly. Mutating, destructive or cross-server operations must support planning and dry-run modes.
5. Deterministic behavior
    Identical configuration and inputs must produce equivalent plans and normalized outputs.
6. Partial failure tolerance
    One unavailable MISP instance must not necessarily invalidate an operation against all other servers.
7. Typed interfaces
    Public APIs, models and exceptions must be fully typed.
8. Automation friendly
    Every CLI operation must support non-interactive execution and structured output.
9. Observable
    Requests, retries, failures, durations and server-level outcomes must be inspectable without exposing secrets.
10. Extensible
    Authentication, policies, exporters, state backends and enrichment behavior must support plugins.

⸻

3. Target users

3.1 Threat intelligence analyst

Needs to search indicators across several MISP instances and understand where each result originates.

3.2 MISP administrator

Needs to validate fleet health, compare instance versions, inspect templates and move controlled content between environments.

3.3 SOC or CERT engineer

Needs to automate ingestion, enrichment, deduplication and export workflows.

3.4 Security platform engineer

Needs a typed Python library that can be embedded into a SOAR, ingestion service, worker or API.

3.5 Managed security provider

Needs to manage separate MISP instances for multiple customers without mixing credentials, policies or datasets.

⸻

4. Scope

4.1 MVP scope

The first stable release must include:

* Multi-instance configuration.
* Asynchronous MISP HTTP client.
* Concurrent fleet-wide execution.
* Federated searches.
* Automatic pagination.
* Structured results preserving source provenance.
* Health and capability checks.
* Event retrieval.
* Event comparison.
* Event copy with dry-run.
* Server groups.
* Retry, timeout and concurrency controls.
* JSON, JSONL, YAML and terminal-table output.
* Secure credential resolution.
* Local SQLite state.
* CLI and Python API.
* PyPI packaging.
* Documentation and runnable examples.
* Unit, integration and contract tests.

4.2 Post-MVP scope

Later releases may include:

* Declarative synchronization jobs.
* Scheduled execution through an external scheduler.
* Bidirectional synchronization.
* Similarity-based duplicate detection.
* Conflict-resolution strategies.
* Policy plugins.
* PostgreSQL state backend.
* OpenTelemetry support.
* Prometheus metrics.
* STIX/TAXII export.
* OpenCTI integration.
* Neo4j export.
* Server-side daemon or API.
* Web interface.

4.3 Explicit non-goals for MVP

The MVP must not:

* Replace the MISP server.
* Reimplement the MISP web interface.
* Require a central MispFleet server.
* Automatically merge semantically similar events.
* Perform uncontrolled bidirectional synchronization.
* Store API keys in plaintext by default.
* Promise transactional rollback across independent MISP servers.
* Support every historical MISP version.
* Wrap every MISP endpoint before the core workflows are stable.
* Include a graphical interface.
* Include an internal task scheduler.

⸻

5. Technology constraints

5.1 Python

The project must target:

requires-python = ">=3.14,<3.15"

Python 3.14 must be treated as the only supported runtime for the first major version.

Structured concurrency should use asyncio.TaskGroup, which provides coordinated task lifetime and failure handling for related asynchronous operations. (⁠Python documentation)

5.2 Required technology choices

* HTTP client: httpx
* CLI framework: typer
* Terminal rendering: rich
* Data validation: pydantic
* Settings: pydantic-settings
* YAML: ruamel.yaml
* Retry policies: tenacity or an internal typed retry implementation
* Local async database: aiosqlite
* Testing: pytest
* Async testing: pytest-asyncio
* HTTP mocking: respx
* Property testing: hypothesis
* Static typing: mypy
* Linting and formatting: ruff
* Packaging: hatchling
* Documentation: mkdocs-material
* Security scanning: pip-audit
* Build frontend: python -m build

The packaging layout must use pyproject.toml and modern PyPA build and publishing practices. The Python Packaging User Guide explicitly covers pyproject.toml, CLI packaging, TestPyPI and GitHub Actions publishing. (⁠Python Packaging)

5.3 Dependencies to avoid

The core package must not depend on:

* Django.
* Flask.
* FastAPI.
* Celery.
* Redis.
* PostgreSQL.
* PyMISP as a mandatory runtime dependency.
* A running MispFleet backend.
* Docker.

Optional integrations may introduce additional dependencies through extras.

⸻

6. Naming and package layout

The repository should use a src layout:

mispfleet/
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── mkdocs.yml
├── src/
│   └── mispfleet/
│       ├── __init__.py
│       ├── py.typed
│       ├── client/
│       │   ├── client.py
│       │   ├── transport.py
│       │   ├── pagination.py
│       │   └── capabilities.py
│       ├── fleet/
│       │   ├── fleet.py
│       │   ├── executor.py
│       │   ├── registry.py
│       │   └── selector.py
│       ├── models/
│       │   ├── common.py
│       │   ├── server.py
│       │   ├── event.py
│       │   ├── attribute.py
│       │   ├── query.py
│       │   ├── result.py
│       │   └── plan.py
│       ├── services/
│       │   ├── search.py
│       │   ├── health.py
│       │   ├── diff.py
│       │   ├── copy.py
│       │   └── sync.py
│       ├── policies/
│       │   ├── base.py
│       │   ├── engine.py
│       │   └── builtins.py
│       ├── state/
│       │   ├── base.py
│       │   ├── memory.py
│       │   └── sqlite.py
│       ├── credentials/
│       │   ├── base.py
│       │   ├── environment.py
│       │   └── keyring.py
│       ├── plugins/
│       │   ├── protocol.py
│       │   └── loader.py
│       ├── output/
│       │   ├── serializers.py
│       │   └── renderers.py
│       ├── cli/
│       │   ├── app.py
│       │   ├── context.py
│       │   └── commands/
│       ├── exceptions.py
│       ├── logging.py
│       └── settings.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── fixtures/
│   └── snapshots/
├── examples/
├── docs/
└── .github/
    └── workflows/

⸻

7. Core domain model

7.1 Server identifier

Every configured server must have a stable local identifier:

ServerName = NewType("ServerName", str)

Examples:

* production
* research
* partner-cert
* customer-acme

The configured server name must be used in results, logs, state records and CLI output.

URLs must not be used as user-facing identifiers.

7.2 Server configuration

class ServerConfig(BaseModel):
    name: str
    url: AnyHttpUrl
    credential: CredentialReference
    enabled: bool = True
    read_only: bool = False
    verify_tls: bool = True
    ca_bundle: Path | None = None
    client_certificate: Path | None = None
    client_key: Path | None = None
    tags: set[str] = set()
    groups: set[str] = set()
    role: ServerRole = ServerRole.GENERAL
    request_timeout: float = 30.0
    connect_timeout: float = 10.0
    concurrency: int = 5
    rate_limit: float | None = None
    retry: RetryConfig = RetryConfig()

7.3 Fleet

class MispFleet:
    @classmethod
    async def from_file(cls, path: Path) -> "MispFleet": ...
    async def search(self, query: SearchQuery) -> FederatedSearchResult: ...
    async def health(
        self,
        selector: ServerSelector | None = None,
    ) -> FleetHealthResult: ...
    async def get_event(
        self,
        event_id: EventIdentifier,
        selector: ServerSelector,
    ) -> MultiServerResult[MISPEvent]: ...
    async def compare_event(
        self,
        event_id: EventIdentifier,
        left: ServerName,
        right: ServerName,
    ) -> EventDiff: ...
    async def plan_copy(
        self,
        event_id: EventIdentifier,
        source: ServerName,
        destination: ServerName,
        policy: str | None = None,
    ) -> CopyPlan: ...
    async def apply(self, plan: OperationPlan) -> ApplyResult: ...
    async def aclose(self) -> None: ...

The fleet object must implement the asynchronous context-manager protocol:

async with MispFleet.from_file(path) as fleet:
    result = await fleet.search(query)

⸻

8. Single-server client

The public single-server client must be usable independently:

from mispfleet import MispClient, ServerConfig
async with MispClient(config) as client:
    event = await client.events.get("event-uuid")

Required service namespaces:

client.events
client.attributes
client.objects
client.tags
client.taxonomies
client.galaxies
client.warninglists
client.templates
client.organisations
client.servers
client.system

The first stable release does not need every possible endpoint, but the namespace design must permit extension without breaking the public API.

⸻

9. Asynchronous execution model

9.1 Concurrency

Fleet-wide operations must:

* Run eligible server requests concurrently.
* Respect global concurrency.
* Respect per-server concurrency.
* Support cancellation.
* Record individual server outcomes.
* Avoid uncontrolled task creation.
* Use bounded concurrency.

Example:

result = await fleet.search(
    SearchQuery(value="example.org"),
    selector=ServerSelector.group("partners"),
    execution=ExecutionOptions(
        max_concurrency=20,
        failure_policy=FailurePolicy.CONTINUE,
    ),
)

9.2 Failure policies

class FailurePolicy(StrEnum):
    CONTINUE = "continue"
    FAIL_FAST = "fail-fast"
    REQUIRE_ALL = "require-all"
    REQUIRE_ANY = "require-any"

Default behavior:

* Read-only fleet operations: CONTINUE.
* Planning operations: CONTINUE.
* Mutation application: FAIL_FAST within each destination.
* Explicit atomic-all-server behavior must not be offered because independent MISP servers cannot provide a shared transaction.

9.3 Result envelope

All multiserver operations must return an envelope:

class MultiServerResult[T](BaseModel):
    operation_id: UUID
    started_at: datetime
    completed_at: datetime
    duration_ms: float
    requested_servers: list[str]
    successful_servers: list[str]
    failed_servers: list[str]
    results: dict[str, T]
    errors: dict[str, ServerError]
    warnings: list[OperationWarning]
    @property
    def complete(self) -> bool: ...
    @property
    def partial(self) -> bool: ...

A partial result must not be represented as a total success.

⸻

10. Configuration

10.1 Default paths

Linux:

~/.config/mispfleet/config.yml
~/.local/state/mispfleet/state.db

macOS:

~/Library/Application Support/MispFleet/config.yml
~/Library/Application Support/MispFleet/state.db

Windows:

%APPDATA%\MispFleet\config.yml
%LOCALAPPDATA%\MispFleet\state.db

The implementation should use platformdirs.

10.2 Configuration format

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
    groups:
      - internal
      - all
  research:
    url: https://misp-research.company.example
    credential:
      provider: keyring
      key: research
    role: research
    groups:
      - internal
      - all
  partner-cert:
    url: https://misp.partner.example
    credential:
      provider: env
      key: MISPFLEET_PARTNER_CERT_API_KEY
    role: partner
    read_only: true
    groups:
      - partners
      - all
policies:
  production-import:
    maximum_distribution: connected-communities
    remove_tags:
      - internal-only
      - do-not-share
    add_tags:
      - imported-by:mispfleet
    reject_if:
      tags:
        - tlp:red

10.3 Configuration precedence

Highest priority first:

1. Explicit method or CLI arguments.
2. Environment variables.
3. Selected configuration profile.
4. Main configuration file.
5. Built-in defaults.

10.4 Environment variables

MISPFLEET_CONFIG
MISPFLEET_PROFILE
MISPFLEET_OUTPUT
MISPFLEET_LOG_LEVEL
MISPFLEET_NO_COLOR
MISPFLEET_STATE_PATH

API keys must use user-defined environment-variable names referenced from configuration.

⸻

11. Credential handling

11.1 Supported providers

MVP:

* Environment variables.
* OS keyring.
* Interactive prompt.
* Direct in-memory injection through the Python API.

Post-MVP:

* HashiCorp Vault.
* AWS Secrets Manager.
* Azure Key Vault.
* Google Secret Manager.
* 1Password CLI.

11.2 Security requirements

The project must never:

* Print API keys.
* Include API keys in exceptions.
* Include authorization headers in debug output.
* Persist interactively entered keys without explicit action.
* Include secrets in telemetry.
* Include secrets in generated plans.

Secret redaction must cover:

* Authorization.
* X-API-Key.
* Cookies.
* URL credentials.
* Known key fields.
* User-configured sensitive fields.

⸻

12. Server selection

Every fleet operation must accept a selector.

Supported selection mechanisms:

--server production
--server production --server research
--group partners
--tag customer:acme
--role research
--all
--exclude-server legacy

Python:

ServerSelector.names("production", "research")
ServerSelector.group("partners")
ServerSelector.role(ServerRole.RESEARCH)
ServerSelector.all().exclude("legacy")

At least one explicit selector must be required for destructive operations unless the operation is based on a previously generated plan containing exact destinations.

⸻

13. Federated search

13.1 Search capabilities

The search API must support:

* Indicator value.
* Attribute UUID.
* Event UUID or numeric ID.
* Event information text.
* Attribute type.
* Category.
* Tags.
* Organisations.
* Published status.
* Date range.
* Timestamp range.
* Distribution.
* Threat level.
* Analysis level.
* Object name.
* Deleted attributes.
* Warning-list enforcement.
* Metadata-only mode.

13.2 Query model

class SearchQuery(BaseModel):
    value: str | list[str] | None = None
    event_info: str | None = None
    event_uuid: UUID | None = None
    attribute_uuid: UUID | None = None
    attribute_types: set[str] = set()
    categories: set[str] = set()
    tags: set[str] = set()
    excluded_tags: set[str] = set()
    published: bool | None = None
    date_from: date | datetime | None = None
    date_to: date | datetime | None = None
    metadata_only: bool = False
    include_deleted: bool = False
    enforce_warninglists: bool = False
    limit_per_server: int | None = None

13.3 Search response

class FederatedMatch(BaseModel):
    server: str
    event_uuid: UUID | None
    attribute_uuid: UUID | None
    value: str | None
    attribute_type: str | None
    category: str | None
    event_info: str | None
    tags: set[str]
    raw: dict[str, Any] | None
class FederatedSearchResult(MultiServerResult[list[FederatedMatch]]):
    matches: list[FederatedMatch]
    groups: list[MatchGroup]
    total_matches: int
    unique_values: int

13.4 Provenance

Every returned item must preserve:

* Source server name.
* Source MISP URL internally.
* Source event ID.
* Source event UUID.
* Source attribute ID.
* Source attribute UUID.
* Fetch timestamp.
* Query operation ID.

Normalized and deduplicated output must never erase provenance.

⸻

14. Pagination and streaming

14.1 Iterator interface

async for attribute in client.attributes.iter_search(
    SearchQuery(attribute_types={"sha256"}),
    page_size=1_000,
):
    await process(attribute)

Fleet-level streaming:

async for match in fleet.iter_search(
    query,
    selector=ServerSelector.group("partners"),
):
    await process(match)

14.2 Pagination behavior

The pagination layer must:

* Hide ordinary page management.
* Detect final pages.
* Enforce optional maximum records.
* Support checkpointing.
* Avoid loading all results into memory.
* Preserve stable ordering when possible.
* Detect repeated pages.
* Detect non-advancing cursors or page numbers.
* Emit warnings when the remote dataset changes during traversal.
* Support JSONL streaming directly to stdout or a file.

14.3 Checkpoints

Checkpoint state must contain:

* Operation type.
* Query fingerprint.
* Server name.
* Current page or cursor.
* Last known entity UUID.
* Record count.
* Creation and update timestamps.
* Client and server versions.

A checkpoint must only be resumed when its query fingerprint and target server match.

⸻

15. Health and capability discovery

CLI:

mispfleet health --all
mispfleet servers capabilities --group partners
mispfleet servers versions --all

Each server health result must include:

class ServerHealth(BaseModel):
    server: str
    reachable: bool
    authenticated: bool
    read_only: bool
    latency_ms: float | None
    misp_version: str | None
    api_version: str | None
    tls_valid: bool | None
    certificate_expiry: datetime | None
    capabilities: set[str]
    warnings: list[str]
    error: ServerError | None

Health checks must distinguish:

* DNS failure.
* TCP failure.
* TLS failure.
* Authentication failure.
* Permission failure.
* Unsupported endpoint.
* Invalid response.
* MISP application failure.
* Timeout.

⸻

16. Event comparison

CLI:

mispfleet event diff EVENT_UUID \
  --left production \
  --right research

The diff engine must compare normalized representations.

Required dimensions:

* Event metadata.
* Publication state.
* Distribution.
* Threat level.
* Analysis level.
* Organisations.
* Tags.
* Attributes.
* Objects.
* Object attributes.
* Object references.
* Galaxies.
* Sightings.
* Proposals where accessible.

Output:

class EventDiff(BaseModel):
    event_identifier: str
    left_server: str
    right_server: str
    equivalent: bool
    differences: list[Difference]
    summary: DiffSummary

Difference operations:

class DiffOperation(StrEnum):
    ADD = "add"
    REMOVE = "remove"
    CHANGE = "change"
    CONFLICT = "conflict"

The CLI must support:

--format table
--format json
--format yaml
--format patch

⸻

17. Copy planning and application

17.1 Mandatory two-stage model

Cross-server copy must support:

1. Plan.
2. Apply.

mispfleet event copy EVENT_UUID \
  --from research \
  --to production \
  --policy production-import \
  --dry-run

Or:

mispfleet event copy plan EVENT_UUID \
  --from research \
  --to production \
  --output copy-plan.json
mispfleet apply copy-plan.json

17.2 Copy plan

class CopyPlan(OperationPlan):
    source_server: str
    destination_server: str
    source_event_uuid: UUID
    source_fingerprint: str
    generated_at: datetime
    expires_at: datetime | None
    transformations: list[Transformation]
    validations: list[ValidationResult]
    warnings: list[OperationWarning]
    blocking_errors: list[PlanError]
    proposed_event: MISPEvent

17.3 Plan safety

Before applying, the system must verify:

* The source event has not changed unexpectedly.
* Source and destination servers match the plan.
* The destination remains writable.
* The policy still exists and has not changed unexpectedly.
* Required object templates are available.
* Distribution is allowed.
* Blocking validations remain satisfied.

Plan files must not include credentials.

17.4 Existing destination event

If the destination already contains the UUID, the default action must be:

abort

Other explicitly selected options:

* skip
* update
* create-new-uuid

No implicit overwrite is permitted.

⸻

18. Policy engine

18.1 Policy operations

Policies may:

* Add tags.
* Remove tags.
* Rename tags.
* Reject events by tag.
* Reject attributes by type.
* Redact selected values.
* Remove attributes.
* Set publication state.
* Restrict distribution.
* Map sharing groups.
* Map organisations.
* Remove internal comments.
* Set to_ids.
* Enforce required tags.
* Reject unsupported objects.
* Limit attachment sizes.

18.2 Policy contract

class Policy(Protocol):
    name: str
    async def evaluate(
        self,
        context: PolicyContext,
        event: MISPEvent,
    ) -> PolicyResult: ...
class PolicyResult(BaseModel):
    accepted: bool
    transformed_event: MISPEvent | None
    transformations: list[Transformation]
    warnings: list[PolicyWarning]
    violations: list[PolicyViolation]

Policies must be deterministic unless clearly marked otherwise.

⸻

19. Deduplication model

The MVP must perform deterministic grouping but not automatic semantic merging.

Supported match levels:

class MatchLevel(StrEnum):
    SAME_UUID = "same-uuid"
    SAME_CANONICAL_CONTENT = "same-canonical-content"
    SAME_VALUE_AND_TYPE = "same-value-and-type"
    SHARED_INDICATORS = "shared-indicators"
    POSSIBLE_MATCH = "possible-match"

MVP requirements:

* Group attributes with identical normalized value and type.
* Group events with the same UUID.
* Compute canonical content fingerprints.
* Preserve all source records.
* Never automatically merge events based only on similarity.

Advanced semantic similarity is post-MVP.

⸻

20. CLI specification

20.1 Root interface

mispfleet
├── config
├── servers
├── search
├── event
├── attribute
├── sync
├── policy
├── state
├── plugins
├── apply
├── completion
└── version

20.2 Global options

--config PATH
--profile NAME
--server NAME
--group NAME
--all
--exclude-server NAME
--format table|json|jsonl|yaml
--output PATH
--log-level debug|info|warning|error
--no-color
--quiet
--verbose
--timeout FLOAT
--concurrency INTEGER
--non-interactive
--trace
--version
--help

20.3 Configuration commands

mispfleet config init
mispfleet config show
mispfleet config validate
mispfleet config path
mispfleet config add-server
mispfleet config remove-server NAME

config show must redact credentials.

20.4 Server commands

mispfleet servers list
mispfleet servers show NAME
mispfleet servers test NAME
mispfleet servers health --all
mispfleet servers versions --all
mispfleet servers capabilities --all
mispfleet servers templates diff --left A --right B

20.5 Search commands

mispfleet search value evil.example --all
mispfleet search value HASH --group partners
mispfleet search events --info ransomware --since 30d
mispfleet search attributes --type sha256 --tag tlp:green

Examples:

mispfleet search value evil.example \
  --group partners \
  --format json
mispfleet search attributes \
  --type sha256 \
  --since 7d \
  --all \
  --format jsonl \
  --output hashes.jsonl

20.6 Event commands

mispfleet event get EVENT --server production
mispfleet event find EVENT --all
mispfleet event diff EVENT --left A --right B
mispfleet event copy EVENT --from A --to B --dry-run
mispfleet event export EVENT --server A --format json
mispfleet event validate FILE

20.7 Policy commands

mispfleet policy list
mispfleet policy show NAME
mispfleet policy validate NAME
mispfleet policy test NAME EVENT_FILE

20.8 State commands

mispfleet state info
mispfleet state checkpoints
mispfleet state checkpoint show ID
mispfleet state checkpoint delete ID
mispfleet state operations
mispfleet state prune --older-than 30d

20.9 Exit codes

0   Success
1   Generic execution error
2   CLI usage or validation error
3   Configuration error
4   Authentication error
5   Connectivity error
6   Partial fleet failure
7   Policy rejection
8   Plan validation failure
9   Conflict detected
10  Unsupported server capability
11  No matching records
12  User-cancelled operation
13  Security validation failure

Structured outputs must remain valid even when the exit code is non-zero.

⸻

21. Output behavior

21.1 Human output

Interactive terminal output should use:

* Rich tables.
* Progress bars.
* Clear server-level statuses.
* Warnings separated from failures.
* Color only when terminal capabilities permit.
* No animation in non-interactive mode.

21.2 Machine output

Supported formats:

* JSON.
* JSONL.
* YAML.

Rules:

* Machine output goes to stdout.
* Logs and warnings go to stderr.
* No progress bars in structured mode.
* Timestamps use ISO 8601 UTC.
* UUIDs are serialized as strings.
* Output must include a schema version.
* Ordering must be deterministic where possible.

Example:

{
  "schema_version": "1.0",
  "operation": "federated-search",
  "operation_id": "e7449349-a803-46ca-9f86-13d99ab822c5",
  "partial": true,
  "matches": [],
  "servers": {
    "production": {
      "status": "success"
    },
    "partner-cert": {
      "status": "timeout"
    }
  }
}

⸻

22. HTTP transport

22.1 Required behavior

The transport layer must support:

* Connection pooling.
* Configurable TLS verification.
* Custom CA bundle.
* Mutual TLS.
* Proxy configuration.
* Configurable timeouts.
* Per-server concurrency limits.
* Retry policies.
* Keepalive configuration where supported.
* Request correlation identifiers.
* Response-size protection.
* Safe response previews on errors.
* Optional HTTP/2 where compatible.

22.2 Retryable conditions

Default retryable failures:

* Connection reset.
* Temporary DNS resolution failure.
* Read timeout for idempotent requests.
* HTTP 429.
* HTTP 502.
* HTTP 503.
* HTTP 504.

Default non-retryable failures:

* HTTP 400.
* HTTP 401.
* HTTP 403.
* HTTP 404, except eventual-consistency workflows.
* Validation errors.
* Policy violations.

22.3 Backoff

Default:

maximum attempts: 4
initial delay: 0.5 seconds
multiplier: 2
maximum delay: 30 seconds
jitter: enabled
respect Retry-After: yes

Mutating requests must only retry when their idempotency behavior is known to be safe.

⸻

23. Exception hierarchy

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
└── PartialFleetError

Every operational exception must provide:

class ErrorContext(BaseModel):
    operation_id: UUID | None
    server: str | None
    endpoint: str | None
    status_code: int | None
    retryable: bool
    request_id: str | None
    safe_response_excerpt: str | None

⸻

24. State management

24.1 SQLite state

The default state backend must use SQLite.

Stored information:

* Operation metadata.
* Checkpoints.
* Cached server capabilities.
* Cached server versions.
* Plan metadata.
* Query fingerprints.
* Non-sensitive audit records.
* Plugin metadata.

The state database must not store API keys.

24.2 State backend protocol

class StateBackend(Protocol):
    async def initialize(self) -> None: ...
    async def save_checkpoint(self, checkpoint: Checkpoint) -> None: ...
    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint: ...
    async def save_operation(self, operation: OperationRecord) -> None: ...
    async def close(self) -> None: ...

In-memory state must be available for tests and ephemeral use.

⸻

25. Plugin system

Plugins must be discovered through Python entry points:

[project.entry-points."mispfleet.plugins"]
my_plugin = "package.module:Plugin"

Plugin categories:

* Credential provider.
* Policy.
* Transformer.
* Validator.
* Exporter.
* State backend.
* Conflict resolver.
* Enrichment provider.

Plugin requirements:

* Typed protocol.
* Plugin metadata and version.
* Compatibility declaration.
* Explicit activation.
* Failure isolation.
* No arbitrary plugin auto-activation merely because a package is installed.

⸻

26. Public Python API

The top-level package should expose:

from mispfleet import (
    MispClient,
    MispFleet,
    SearchQuery,
    ServerConfig,
    ServerSelector,
    ExecutionOptions,
    FederatedSearchResult,
    EventDiff,
    CopyPlan,
    MispFleetError,
)

26.1 Example: federated search

import asyncio
from pathlib import Path
from mispfleet import MispFleet, SearchQuery, ServerSelector
async def main() -> None:
    async with await MispFleet.from_file(
        Path("mispfleet.yml")
    ) as fleet:
        result = await fleet.search(
            SearchQuery(
                value="evil.example",
                metadata_only=True,
            ),
            selector=ServerSelector.group("all"),
        )
        for match in result.matches:
            print(match.server, match.event_uuid)
if __name__ == "__main__":
    asyncio.run(main())

26.2 Example: partial failure

result = await fleet.health(ServerSelector.all())
for server, health in result.results.items():
    print(server, health.reachable)
for server, error in result.errors.items():
    print(f"{server}: {error.message}")

Ordinary partial failures should be representable as data. Callers may request exception-based behavior using execution options.

⸻

27. Logging and observability

27.1 Logging

The library must:

* Never configure the root logger.
* Use the mispfleet logger hierarchy.
* Support structured log fields.
* Attach operation and server context.
* Redact secrets.
* Avoid logging full event content by default.

CLI logs must support:

text
json

27.2 Metrics

MVP metrics may be exposed through callbacks but need not run an HTTP metrics server.

Metric concepts:

* Request count.
* Request duration.
* Retry count.
* Error count.
* Records fetched.
* Pages fetched.
* Server availability.
* Copy-plan validation failures.
* Policy rejections.

OpenTelemetry integration is post-MVP but internal instrumentation boundaries must permit it.

⸻

28. Security requirements

28.1 Network security

* TLS verification enabled by default.
* --no-verify-tls must produce a visible warning.
* Configuration may prohibit disabling TLS verification.
* Redirects to a different host must be rejected by default.
* URL schemes other than HTTPS must require explicit insecure configuration.
* Proxy usage must be explicit and inspectable.
* Response bodies must have configurable size limits.

28.2 Local security

* Configuration files should be created with restrictive permissions.
* State files must use restrictive permissions.
* Exported plans must exclude secrets.
* Temporary attachment files must be securely created.
* Filenames from remote servers must be sanitized.
* Archive extraction must prevent path traversal.
* Symlink behavior must be controlled.

28.3 Supply-chain security

The repository must include:

* Dependabot or Renovate.
* pip-audit.
* Secret scanning.
* CodeQL.
* Signed PyPI publication through Trusted Publishing.
* Build provenance where supported.
* Locked development dependencies.
* Reproducible source and wheel builds where practical.

28.4 Security policy

SECURITY.md must define:

* Supported versions.
* Private vulnerability reporting channel.
* Expected acknowledgement process.
* Disclosure policy.
* Scope exclusions.

⸻

29. Testing strategy

29.1 Unit tests

Required for:

* Configuration.
* Credential resolution.
* Selectors.
* Query serialization.
* Pagination.
* Retry decisions.
* Normalization.
* Fingerprinting.
* Diff generation.
* Policy transformations.
* Secret redaction.
* Exception mapping.
* Output serialization.

29.2 Integration tests

Must exercise:

* HTTP interactions through mocked MISP APIs.
* Multiple servers with mixed outcomes.
* Pagination across servers.
* Timeouts and retries.
* Event copy planning.
* Plan application.
* SQLite state.
* CLI invocation.

29.3 Contract tests

A Docker-based test environment should validate against supported MISP releases.

The contract test matrix must document:

* Oldest supported MISP version.
* Latest tested MISP version.
* Known API differences.
* Unsupported functionality.

29.4 Property-based tests

Use Hypothesis for:

* Query round trips.
* Model serialization.
* Fingerprint stability.
* Secret-redaction invariants.
* Diff symmetry where applicable.
* Pagination termination.
* Configuration merge precedence.

29.5 Coverage

Minimum initial requirement:

Overall line coverage: 85%
Core transport, policy and planning modules: 95%

Coverage alone does not determine release readiness.

⸻

30. Quality gates

Every pull request must pass:

ruff check .
ruff format --check .
mypy src
pytest
python -m build
twine check dist/*
pip-audit

Additional checks:

* Documentation build.
* CLI smoke tests.
* Wheel installation test.
* Source-distribution installation test.
* Python 3.14 on Linux, macOS and Windows.
* Secret scanning.
* CodeQL.

No release may be published if the main branch is failing.

⸻

31. Packaging and PyPI

31.1 Distribution

PyPI package:

mispfleet

Console script:

[project.scripts]
mispfleet = "mispfleet.cli.app:main"

31.2 Optional extras

[project.optional-dependencies]
keyring = ["keyring>=..."]
yaml = ["ruamel.yaml>=..."]
telemetry = ["opentelemetry-api>=...", "opentelemetry-sdk>=..."]
postgres = ["asyncpg>=..."]
all = [
    "keyring>=...",
    "opentelemetry-api>=...",
    "opentelemetry-sdk>=...",
]
dev = [...]
docs = [...]
test = [...]

YAML is core if configuration requires it; in that case it must not be optional.

31.3 Versioning

Use semantic versioning:

0.x     Active development
1.0.0   Stable public API and MVP completion

Version source must have a single authority.

Recommended:

dynamic = ["version"]

with VCS-derived versions or a dedicated _version.py.

31.4 Publishing

Publishing must use:

* GitHub release tags.
* GitHub Actions.
* PyPI Trusted Publishing.
* TestPyPI validation before the first production release.
* Generated changelog or manually curated release notes.
* Source distribution and universal Python wheel.

⸻

32. Documentation requirements

Required documentation sections:

1. Installation.
2. Quick start.
3. Configuration.
4. Credential security.
5. Server groups.
6. Federated search.
7. Pagination and streaming.
8. Health checks.
9. Event diff.
10. Copy planning.
11. Policies.
12. Python API.
13. CLI reference.
14. Exit codes.
15. Error handling.
16. Plugin development.
17. MISP compatibility.
18. Security model.
19. Migration and upgrades.
20. Troubleshooting.

Every public class and function must have docstrings.

Examples must be tested where practical.

⸻

33. Performance requirements

Initial performance targets under mocked or controlled network conditions:

* Configuration load: under 100 ms for 100 servers.
* Fleet selector evaluation: under 10 ms for 1,000 servers.
* JSON serialization: at least 10,000 normalized attributes per second.
* Memory-safe streaming of at least 5 million attributes.
* No full-dataset materialization during streaming export.
* Fleet search overhead, excluding remote response time: below 10% compared with direct parallel requests.
* Default maximum in-flight requests must remain bounded.

Performance tests must avoid hard-coded assumptions about MISP server throughput.

⸻

34. Compatibility strategy

34.1 Capability-driven behavior

Features must be selected by discovered server capabilities, not only by version strings.

capabilities = await client.system.capabilities()

Capabilities may include:

* Search endpoint variants.
* Supported return formats.
* Object-template versions.
* Pagination features.
* Warning-list support.
* Server metadata availability.
* Supported mutation behavior.

34.2 Compatibility cache

Capability results may be cached with:

* Server identity.
* MISP version.
* Fetch timestamp.
* Expiry.
* Explicit invalidation.

34.3 Unsupported features

When a server lacks a feature:

* Do not silently approximate unsafe behavior.
* Return CapabilityError.
* Identify the affected server.
* Explain the missing capability.
* Continue on other servers if permitted by the failure policy.

⸻

35. Auditability

Every mutating operation must record:

* Operation ID.
* Timestamp.
* Source server.
* Destination server.
* Event identifier.
* Plan fingerprint.
* Policy name.
* Result.
* Error if any.
* Local actor context where supplied.

Audit records must not contain:

* API keys.
* Full authorization headers.
* Unredacted sensitive event content by default.

MispFleet audit records are operational records, not a replacement for MISP server audit logs.

⸻

36. MVP use cases and acceptance criteria

UC-001 — Configure multiple servers

Given a valid YAML configuration with three MISP servers,
when the user runs:

mispfleet config validate

then:

* The configuration is validated.
* Credential references are checked without exposing values.
* Duplicate names are rejected.
* Invalid groups are reported.
* Exit code is 0 for valid configuration.

UC-002 — Search all servers

When the user runs:

mispfleet search value evil.example --all --format json

then:

* All enabled servers are queried concurrently.
* Results retain source provenance.
* Duplicate matches are grouped.
* Failed servers are represented explicitly.
* Output is valid JSON.
* API keys do not appear in stdout or stderr.

UC-003 — Tolerate one unavailable server

Given three configured servers and one timeout,
when a read-only fleet search uses the default failure policy,
then:

* Results from the two available servers are returned.
* The response is marked partial.
* The failed server includes a typed timeout error.
* CLI exit code is 6.

UC-004 — Stream a large search

When a caller iterates through a large attribute query,
then:

* Results are yielded incrementally.
* Memory usage does not grow linearly with total records.
* Pagination terminates correctly.
* A resumable checkpoint can be created.

UC-005 — Compare an event

When the same event UUID exists on two servers,
then:

* Metadata and content are normalized.
* Differences are classified.
* Added, removed and changed entities are distinguishable.
* Machine-readable and human-readable output are available.

UC-006 — Plan a safe copy

When the user plans an event copy,
then:

* No destination mutation occurs.
* Policies are applied to a proposed copy.
* Transformations and violations are listed.
* A deterministic plan fingerprint is produced.
* Credentials are absent from the plan.

UC-007 — Apply a valid plan

Given a non-expired plan whose source fingerprint still matches,
when the user runs:

mispfleet apply plan.json

then:

* The destination is validated again.
* The mutation is executed once.
* The outcome is recorded.
* A structured result is returned.

UC-008 — Reject stale plan

Given a source event changed after plan generation,
when the plan is applied,
then:

* The mutation is rejected.
* StalePlanError is returned.
* No destination write occurs.

UC-009 — Protect secrets

Given debug logging and a failed authenticated request,
then:

* The API key is redacted.
* Authorization headers are redacted.
* The exception retains safe diagnostic context.
* Secret-redaction tests pass.

UC-010 — Install from PyPI

When a user runs:

python3.14 -m pip install mispfleet

then:

* The package installs without development dependencies.
* mispfleet --version works.
* The Python package is importable.
* Type information is included through py.typed.

⸻

37. Delivery phases

Phase 0 — Foundation

* Repository structure.
* pyproject.toml.
* CI.
* Formatting, linting and typing.
* Base models.
* Exception hierarchy.
* Configuration.
* Secret redaction.
* Initial documentation.

Phase 1 — Async single-server client

* Transport.
* Authentication.
* Server information.
* Event retrieval.
* Search.
* Pagination.
* Retry behavior.
* Unit and mocked integration tests.

Phase 2 — Fleet execution

* Registry.
* Selectors.
* Server groups.
* Concurrent executor.
* Partial-result model.
* Health checks.
* Federated search.
* CLI output.

Phase 3 — Diff and copy planning

* Canonical normalization.
* Fingerprinting.
* Event diff.
* Policy engine.
* Copy plan.
* Plan validation.
* Dry-run CLI.

Phase 4 — Safe mutation

* Plan application.
* Destination conflict handling.
* Audit records.
* SQLite state.
* Idempotency safeguards.
* End-to-end tests.

Phase 5 — Release readiness

* Complete documentation.
* Contract tests against MISP.
* Performance testing.
* Security review.
* TestPyPI release.
* PyPI Trusted Publishing.
* Version 1.0.0.

⸻

38. Definition of done for version 1.0

MispFleet 1.0 is complete when:

* All MVP functionality is implemented.
* The documented public API is stable.
* CLI and library use the same service layer.
* Python 3.14 works on Linux, macOS and Windows.
* Fleet-wide operations handle partial failures correctly.
* Streaming search is memory-safe.
* Event diff and copy planning are deterministic.
* Mutations require explicit intent.
* Secrets are reliably redacted.
* Contract tests pass against supported MISP versions.
* Documentation contains complete examples.
* Source and wheel packages install cleanly.
* PyPI publication is automated and secured.
* No critical or high-severity known vulnerability remains open.
* CI and quality gates pass.
* A real multiserver deployment has completed an acceptance test.

⸻

39. Initial implementation rule

The first implementation must prioritize this vertical slice:

Configuration
    ↓
Credential resolution
    ↓
Async MISP transport
    ↓
Single-server search
    ↓
Fleet concurrent search
    ↓
Normalized federated result
    ↓
CLI table and JSON output

Do not start synchronization, plugins, semantic deduplication or GUI work before this vertical slice is fully tested and usable.

⸻

40. Product statement

MispFleet is an async Python library and CLI for federated search, health monitoring, comparison, policy enforcement and controlled synchronization across multiple MISP instances.

The project succeeds when an analyst can treat several independent MISP servers as a manageable fleet without losing source provenance, security boundaries or operational control.

Este SCC ya está preparado para entregárselo directamente a un agente de programación como especificación de construcción. El siguiente paso natural sería convertirlo en un plan de implementación por issues y milestones, empezando por el vertical slice hasta mispfleet search value --all.
