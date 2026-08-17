"""Event comparison models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DiffOperation(StrEnum):
    """Classification of a single difference between two event versions."""

    ADD = "add"
    REMOVE = "remove"
    CHANGE = "change"
    CONFLICT = "conflict"


class Difference(BaseModel):
    """One normalized difference between the left and right event."""

    operation: DiffOperation
    path: str
    left: Any = None
    right: Any = None


class DiffSummary(BaseModel):
    """Aggregate counts per difference operation."""

    added: int = 0
    removed: int = 0
    changed: int = 0
    conflicts: int = 0


class EventDiff(BaseModel):
    """Outcome of comparing one event across two servers."""

    event_identifier: str
    left_server: str
    right_server: str
    equivalent: bool
    similarity: float = 1.0
    differences: list[Difference] = Field(default_factory=list)
    summary: DiffSummary = Field(default_factory=DiffSummary)
