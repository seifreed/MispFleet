"""Server selection for fleet operations."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mispfleet.models.common import ServerRole
from mispfleet.models.server import ServerConfig


class ServerSelector(BaseModel):
    """Declarative selection of fleet servers.

    Criteria are additive (a server matching any criterion is selected);
    exclusions always win.
    """

    server_names: set[str] = Field(default_factory=set)
    groups: set[str] = Field(default_factory=set)
    tags: set[str] = Field(default_factory=set)
    roles: set[ServerRole] = Field(default_factory=set)
    excluded: set[str] = Field(default_factory=set)
    select_all: bool = False

    @classmethod
    def names(cls, *names: str) -> ServerSelector:
        """Select servers by configured name."""
        return cls(server_names=set(names))

    @classmethod
    def group(cls, *groups: str) -> ServerSelector:
        """Select servers by group membership."""
        return cls(groups=set(groups))

    @classmethod
    def tag(cls, *tags: str) -> ServerSelector:
        """Select servers by configuration tag."""
        return cls(tags=set(tags))

    @classmethod
    def role(cls, *roles: ServerRole) -> ServerSelector:
        """Select servers by role."""
        return cls(roles=set(roles))

    @classmethod
    def all(cls) -> ServerSelector:
        """Select every enabled server."""
        return cls(select_all=True)

    def exclude(self, *names: str) -> ServerSelector:
        """Return a copy that additionally excludes the given servers."""
        return self.model_copy(update={"excluded": self.excluded | set(names)})

    @property
    def is_explicit(self) -> bool:
        """True when at least one selection criterion was provided."""
        return bool(self.select_all or self.server_names or self.groups or self.tags or self.roles)

    def matches(self, server: ServerConfig) -> bool:
        """Decide whether one enabled server satisfies this selector."""
        if server.name in self.excluded:
            return False
        if self.select_all:
            return True
        return (
            server.name in self.server_names
            or bool(self.groups & server.groups)
            or bool(self.tags & server.tags)
            or server.role in self.roles
        )

    def select(self, servers: list[ServerConfig]) -> list[ServerConfig]:
        """Filter enabled servers matching this selector, preserving order."""
        return [server for server in servers if server.enabled and self.matches(server)]
