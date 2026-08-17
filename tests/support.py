"""Assertion helpers that raise instead of using ``assert`` statements.

Bandit's B101 check forbids ``assert`` anywhere in the repository, so tests
use these helpers, which fail identically under pytest.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable

import pytest

# Marks tests that exercise POSIX-only behaviour (owner-only file modes,
# broken-pipe EPIPE semantics, connection-error mapping) which Windows does
# not share. They run on Linux and macOS; on Windows they are skipped.
skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32", reason="exercises POSIX-specific behaviour"
)


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
