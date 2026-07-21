"""Secret redaction utilities applied to logs, errors, plans and debug output."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***REDACTED***"

SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}
)

SENSITIVE_FIELDS = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authkey",
        "authorization",
        "credential",
        "password",
        "secret",
        "session_key",
        "token",
    }
)


def redact_headers(
    headers: Mapping[str, str],
    extra_sensitive: Iterable[str] = (),
) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive values replaced."""
    sensitive = SENSITIVE_HEADERS | {name.lower() for name in extra_sensitive}
    return {
        name: (REDACTED if name.lower() in sensitive else value) for name, value in headers.items()
    }


def redact_mapping(
    data: Mapping[str, Any],
    extra_sensitive: Iterable[str] = (),
) -> dict[str, Any]:
    """Recursively redact sensitive fields in a nested mapping."""
    sensitive = SENSITIVE_FIELDS | {name.lower() for name in extra_sensitive}
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in sensitive:
            redacted[key] = REDACTED
        elif isinstance(value, Mapping):
            redacted[key] = redact_mapping(value, extra_sensitive)
        elif isinstance(value, list):
            redacted[key] = [
                redact_mapping(item, extra_sensitive) if isinstance(item, Mapping) else item
                for item in value
            ]
        else:
            redacted[key] = value
    return redacted


def redact_url(url: str) -> str:
    """Strip userinfo credentials from a URL."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, f"{REDACTED}@{host}", parts.path, parts.query, parts.fragment))


def redact_text(text: str, secrets: Iterable[str]) -> str:
    """Replace every occurrence of each known secret value in ``text``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text
