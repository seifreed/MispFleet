"""Registry of configured servers."""

from __future__ import annotations

from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.models.server import ServerConfig


class ServerRegistry:
    """Holds the validated server collection and answers lookup queries."""

    def __init__(self, servers: dict[str, ServerConfig]) -> None:
        self._servers = dict(servers)

    def get(self, name: str) -> ServerConfig:
        """Return one server by its configured name."""
        try:
            return self._servers[name]
        except KeyError:
            raise InvalidConfigurationError(f"unknown server {name!r}") from None

    def names(self) -> list[str]:
        """All configured server names, in configuration order."""
        return list(self._servers)

    def all(self) -> list[ServerConfig]:
        """All configured servers, in configuration order."""
        return list(self._servers.values())

    def enabled(self) -> list[ServerConfig]:
        """Only the servers currently enabled."""
        return [server for server in self._servers.values() if server.enabled]

    def groups(self) -> set[str]:
        """Every group referenced by at least one server."""
        return {group for server in self._servers.values() for group in server.groups}
