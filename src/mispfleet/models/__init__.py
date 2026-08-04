"""Typed domain models shared by the library and the CLI."""

from mispfleet.models.attribute import MISPAttribute, MISPObject, ObjectReference
from mispfleet.models.common import (
    EventIdentifier,
    ExecutionOptions,
    FailurePolicy,
    OperationWarning,
    ServerError,
    ServerName,
    ServerRole,
)
from mispfleet.models.diff import Difference, DiffOperation, DiffSummary, EventDiff
from mispfleet.models.event import Galaxy, MISPEvent, Proposal, Sighting
from mispfleet.models.plan import (
    ApplyResult,
    ConflictAction,
    CopyPlan,
    OperationPlan,
    PlanIssue,
    Transformation,
    ValidationResult,
)
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import (
    FederatedMatch,
    FederatedSearchResult,
    FleetHealthResult,
    MatchGroup,
    MatchLevel,
    MultiServerResult,
    ServerHealth,
)
from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig

__all__ = [
    "ApplyResult",
    "ConflictAction",
    "CopyPlan",
    "CredentialReference",
    "DiffOperation",
    "DiffSummary",
    "Difference",
    "EventDiff",
    "EventIdentifier",
    "ExecutionOptions",
    "FailurePolicy",
    "FederatedMatch",
    "FederatedSearchResult",
    "FleetHealthResult",
    "Galaxy",
    "MISPAttribute",
    "MISPEvent",
    "MISPObject",
    "MatchGroup",
    "MatchLevel",
    "MultiServerResult",
    "ObjectReference",
    "OperationPlan",
    "OperationWarning",
    "PlanIssue",
    "Proposal",
    "RetryConfig",
    "SearchQuery",
    "ServerConfig",
    "ServerError",
    "ServerHealth",
    "ServerName",
    "ServerRole",
    "Sighting",
    "Transformation",
    "ValidationResult",
]
