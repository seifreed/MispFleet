"""Operation planning models for safe cross-server mutations."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from mispfleet.models.common import OperationWarning
from mispfleet.models.event import MISPEvent

PLAN_SCHEMA_VERSION = "1.0"


class ConflictAction(StrEnum):
    """What to do when the destination already contains the event UUID."""

    ABORT = "abort"
    SKIP = "skip"
    UPDATE = "update"
    CREATE_NEW_UUID = "create-new-uuid"
    MERGE = "merge"


class Transformation(BaseModel):
    """A policy-driven change applied to the proposed event."""

    action: str
    target: str
    detail: str = ""


class ValidationResult(BaseModel):
    """Outcome of one pre-application safety validation."""

    name: str
    passed: bool
    message: str = ""


class PlanIssue(BaseModel):
    """A blocking problem that prevents a plan from being applied."""

    code: str
    message: str


class OperationPlan(BaseModel):
    """Base class for reviewable, credential-free operation plans."""

    schema_version: str = PLAN_SCHEMA_VERSION
    plan_id: UUID
    kind: str


class CopyPlan(OperationPlan):
    """A reviewed proposal to copy one event between two servers."""

    kind: str = "copy"
    source_server: str
    destination_server: str
    source_event_uuid: UUID
    source_fingerprint: str
    # Set only when the destination already holds the event and the plan will
    # rewrite it: apply refuses if that side changed after the review.
    destination_fingerprint: str | None = None
    generated_at: datetime
    expires_at: datetime | None = None
    policy: str | None = None
    on_conflict: ConflictAction = ConflictAction.ABORT
    transformations: list[Transformation] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)
    warnings: list[OperationWarning] = Field(default_factory=list)
    blocking_errors: list[PlanIssue] = Field(default_factory=list)
    proposed_event: MISPEvent

    def fingerprint(self) -> str:
        """Deterministic fingerprint of the plan's decision-relevant content.

        Identifiers and timestamps are excluded so regenerating an identical
        plan yields an identical fingerprint.
        """
        canonical = {
            "kind": self.kind,
            "source_server": self.source_server,
            "destination_server": self.destination_server,
            "source_event_uuid": str(self.source_event_uuid),
            "source_fingerprint": self.source_fingerprint,
            "destination_fingerprint": self.destination_fingerprint,
            "policy": self.policy,
            "on_conflict": self.on_conflict.value,
            "proposed_event": self.proposed_event.canonical_fingerprint(),
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApplyResult(BaseModel):
    """Outcome of applying an operation plan."""

    operation_id: UUID
    plan_id: UUID
    applied: bool
    destination_server: str
    destination_event_uuid: UUID | None = None
    messages: list[str] = Field(default_factory=list)
