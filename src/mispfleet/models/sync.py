"""Declarative synchronization jobs and their plans."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from mispfleet.models.plan import ApplyResult, CopyPlan


class SyncDirection(StrEnum):
    """Which way events may flow between the two servers of a job."""

    PUSH = "push"
    PULL = "pull"
    BOTH = "both"


class SyncConflictStrategy(StrEnum):
    """How to resolve events that exist on both sides with different content."""

    SKIP = "skip"
    NEWER_WINS = "newer-wins"
    PREFER_LEFT = "prefer-left"
    PREFER_RIGHT = "prefer-right"


class SyncJobSpec(BaseModel):
    """A declarative, repeatable synchronization job between two servers."""

    model_config = ConfigDict(extra="forbid")

    left: str
    right: str
    direction: SyncDirection = SyncDirection.BOTH
    filter_tags: set[str] = Field(default_factory=set)
    policy_left_to_right: str | None = None
    policy_right_to_left: str | None = None
    on_conflict: SyncConflictStrategy = SyncConflictStrategy.SKIP


class SyncConflict(BaseModel):
    """An event present on both sides with diverging content."""

    event_uuid: str
    left_timestamp: str | None = None
    right_timestamp: str | None = None
    resolution: str


class SyncPlan(BaseModel):
    """Reviewable outcome of planning one synchronization job."""

    plan_id: UUID
    job: str
    left_server: str
    right_server: str
    generated_at: datetime
    copies_left_to_right: list[CopyPlan] = Field(default_factory=list)
    copies_right_to_left: list[CopyPlan] = Field(default_factory=list)
    conflicts: list[SyncConflict] = Field(default_factory=list)
    in_sync: int = 0

    @property
    def total_copies(self) -> int:
        """Number of copy operations the plan proposes."""
        return len(self.copies_left_to_right) + len(self.copies_right_to_left)

    @property
    def blocked(self) -> bool:
        """True when at least one proposed copy has blocking errors."""
        return any(
            copy.blocking_errors for copy in self.copies_left_to_right + self.copies_right_to_left
        )


class SyncResult(BaseModel):
    """Outcome of applying a synchronization plan."""

    plan_id: UUID
    applied: list[ApplyResult] = Field(default_factory=list)
    failures: dict[str, str] = Field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """True when no proposed copy failed."""
        return not self.failures
