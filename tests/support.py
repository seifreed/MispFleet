"""Assertion helpers that raise instead of using ``assert`` statements.

Bandit's B101 check forbids ``assert`` anywhere in the repository, so tests
use these helpers, which fail identically under pytest.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable


def refused_tcp_port() -> int:
    """A localhost TCP port with nothing listening, so a connect is refused.

    Binding then closing frees the port on every platform, so a subsequent
    connect gets a refused error (rather than the timeout Windows returns for
    a filtered port such as the classic discard port 9).
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def eq(actual: object, expected: object) -> None:
    """Fail unless ``actual == expected``."""
    if actual != expected:
        raise AssertionError(f"{actual!r} != {expected!r}")


def ne(actual: object, other: object) -> None:
    """Fail unless ``actual != other``."""
    if actual == other:
        raise AssertionError(f"{actual!r} == {other!r}")


def ok(condition: object, message: str = "condition is not truthy") -> None:
    """Fail unless ``condition`` is truthy."""
    if not condition:
        raise AssertionError(message)


def not_none[T](value: T | None, message: str = "value is unexpectedly None") -> T:
    """Fail unless ``value`` is set, returning it narrowed for the type checker."""
    if value is None:
        raise AssertionError(message)
    return value


def contains(haystack: Iterable[object] | str, needle: object) -> None:
    """Fail unless ``needle`` is contained in ``haystack``."""
    if isinstance(haystack, str):
        if str(needle) not in haystack:
            raise AssertionError(f"{needle!r} not found in {haystack!r}")
        return
    if needle not in list(haystack):
        raise AssertionError(f"{needle!r} not found in {haystack!r}")


def not_contains(haystack: Iterable[object] | str, needle: object) -> None:
    """Fail if ``needle`` is contained in ``haystack``."""
    if isinstance(haystack, str):
        if str(needle) in haystack:
            raise AssertionError(f"{needle!r} unexpectedly found in {haystack!r}")
        return
    if needle in list(haystack):
        raise AssertionError(f"{needle!r} unexpectedly found in {haystack!r}")
