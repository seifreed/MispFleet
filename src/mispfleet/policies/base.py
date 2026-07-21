"""Policy contracts and declarative policy specifications."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import Transformation


class RejectRules(BaseModel):
    """Conditions that make a policy reject an event outright."""

    model_config = ConfigDict(extra="forbid")

    tags: set[str] = Field(default_factory=set)
    attribute_types: set[str] = Field(default_factory=set)


class PolicySpec(BaseModel):
    """Declarative policy definition loaded from configuration."""

    model_config = ConfigDict(extra="forbid")

    maximum_distribution: str | None = None
    add_tags: set[str] = Field(default_factory=set)
    remove_tags: set[str] = Field(default_factory=set)
    rename_tags: dict[str, str] = Field(default_factory=dict)
    required_tags: set[str] = Field(default_factory=set)
    remove_attribute_types: set[str] = Field(default_factory=set)
    remove_comments: bool = False
    set_published: bool | None = None
    reject_if: RejectRules = Field(default_factory=RejectRules)


class PolicyContext(BaseModel):
    """Where and why a policy is being evaluated."""

    policy_name: str
    source_server: str
    destination_server: str


class PolicyViolation(BaseModel):
    """A rule that caused the event to be rejected."""

    rule: str
    message: str


class PolicyWarning(BaseModel):
    """A non-fatal observation made during policy evaluation."""

    message: str


class PolicyResult(BaseModel):
    """Outcome of evaluating one policy against one event."""

    accepted: bool
    transformed_event: MISPEvent | None = None
    transformations: list[Transformation] = Field(default_factory=list)
    warnings: list[PolicyWarning] = Field(default_factory=list)
    violations: list[PolicyViolation] = Field(default_factory=list)


@runtime_checkable
class Policy(Protocol):
    """Deterministic transformation and validation applied before mutation."""

    name: str

    async def evaluate(self, context: PolicyContext, event: MISPEvent) -> PolicyResult:
        """Evaluate the policy against a copy of the event."""
        ...
