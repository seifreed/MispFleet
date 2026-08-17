"""Fleet configuration-consistency audit models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from mispfleet.models.result import MultiServerResult


class AuditSnapshot(BaseModel):
    """One server's auditable configuration surface.

    Every dimension maps a stable key (namespace, list name, feed name…) to a
    short comparable description such as ``enabled v9`` or ``https://feed/ on``.
    """

    server: str
    misp_version: str | None = None
    taxonomies: dict[str, str] = Field(default_factory=dict)
    warninglists: dict[str, str] = Field(default_factory=dict)
    galaxies: dict[str, str] = Field(default_factory=dict)
    feeds: dict[str, str] = Field(default_factory=dict)
    templates: dict[str, str] = Field(default_factory=dict)

    def dimension(self, name: str) -> dict[str, str]:
        """Return one named dimension mapping."""
        value: dict[str, str] = getattr(self, name)
        return value


class AuditFindingKind(StrEnum):
    """How a fleet audit entry diverges."""

    MISSING = "missing"
    MISMATCH = "mismatch"


class AuditFinding(BaseModel):
    """One divergence between servers for a single audited key."""

    dimension: str
    key: str
    kind: AuditFindingKind
    values: dict[str, str | None]


class FleetAuditResult(MultiServerResult[AuditSnapshot]):
    """Fleet-wide configuration audit outcome."""

    findings: list[AuditFinding] = Field(default_factory=list)

    @property
    def consistent(self) -> bool:
        """True when no divergence was found among the successful servers."""
        return not self.findings
