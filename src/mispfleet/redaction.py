"""Secret redaction utilities applied to logs, errors, plans and debug output."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "***REDACTED***"

_SCHEME_SEPARATOR = "://"
_NETLOC_TERMINATORS = "/?#"
_AUTHORITY_PREFIX = "//"

SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}
)

SENSITIVE_FIELDS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authkey",
        "authorization",
        "credential",
        "id_token",
        "password",
        "private_key",
        "refresh_token",
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
    return _redact_mapping(data, sensitive)


def _redact_mapping(
    data: Mapping[Any, Any], sensitive: frozenset[str] | set[str]
) -> dict[Any, Any]:
    redacted: dict[Any, Any] = {}
    for key, value in data.items():
        # A non-string key cannot name a sensitive field, but its value still
        # travels: recurse into it rather than crash on ``key.lower()``.
        if isinstance(key, str) and key.lower() in sensitive:
            redacted[key] = REDACTED
        else:
            redacted[key] = _redact_value(value, sensitive)
    return redacted


def _redact_value(value: Any, sensitive: frozenset[str] | set[str]) -> Any:
    """Redact one value of any shape.

    Sequences are walked element by element: recursing only into mappings left
    a URL sitting in a list (``{"proxies": ["http://user:pass@host/"]}``)
    completely untouched.
    """
    if isinstance(value, Mapping):
        return _redact_mapping(value, sensitive)
    if isinstance(value, tuple):
        return tuple(_redact_value(item, sensitive) for item in value)
    if isinstance(value, list):
        return [_redact_value(item, sensitive) for item in value]
    if isinstance(value, str):
        # Credentials also travel inside URLs (proxy, dsn, url), which no
        # field-name match would ever catch.
        return redact_url(value, sensitive)
    return value


def _redact_parameters(text: str, sensitive: frozenset[str] | set[str]) -> str:
    """Redact sensitive parameters of a query string or fragment."""
    redacted = []
    for pair in text.split("&"):
        name, separator, _ = pair.partition("=")
        if separator and name.lower() in sensitive:
            redacted.append(f"{name}={REDACTED}")
        else:
            redacted.append(pair)
    return "&".join(redacted)


def _redact_tail(tail: str, sensitive: frozenset[str] | set[str]) -> str:
    """Redact sensitive parameters in a URL's query string and fragment."""
    head, separator, fragment = tail.partition("#")
    path, query_separator, query = head.partition("?")
    if query_separator:
        path = f"{path}?{_redact_parameters(query, sensitive)}"
    if separator:
        return f"{path}#{_redact_parameters(fragment, sensitive)}"
    return path


def redact_url(url: str, sensitive: frozenset[str] | set[str] = SENSITIVE_FIELDS) -> str:
    """Strip credentials from a URL's userinfo, query string and fragment.

    MISP feed URLs carry their key in the query (``?authkey=...``), so
    redacting only the userinfo left the secret in every log line.

    The netloc is located by hand rather than with ``urlsplit`` because
    ``redact_mapping`` feeds every string it meets through here, and
    ``urlsplit`` raises ``ValueError`` on unbalanced IPv6 brackets — a shape
    that reaches us both from MISP indicator values and from a mistyped
    server URL, and that may still carry userinfo credentials.
    """
    scheme, separator, remainder = url.partition(_SCHEME_SEPARATOR)
    if separator:
        prefix = scheme + separator
    elif url.startswith(_AUTHORITY_PREFIX):
        # Scheme-relative URLs ("//user:pass@host/path") carry userinfo too.
        prefix, remainder = _AUTHORITY_PREFIX, url[len(_AUTHORITY_PREFIX) :]
    else:
        return url
    boundaries = [remainder.find(char) for char in _NETLOC_TERMINATORS]
    netloc_end = min((index for index in boundaries if index != -1), default=len(remainder))
    netloc = remainder[:netloc_end]
    if "@" in netloc:
        netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"
    return f"{prefix}{netloc}{_redact_tail(remainder[netloc_end:], sensitive)}"


def redact_text(text: str, secrets: Iterable[str]) -> str:
    """Replace every occurrence of each known secret value in ``text``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text
