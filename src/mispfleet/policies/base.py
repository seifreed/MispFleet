"""Policy contracts and declarative policy specifications."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


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
