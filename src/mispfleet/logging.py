"""Logging helpers for the ``mispfleet`` logger hierarchy.

The library never configures the root logger; the CLI attaches handlers only
to the ``mispfleet`` hierarchy and always redacts known secrets.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterable
from typing import Literal, TextIO

from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.redaction import redact_text

LOGGER_NAME = "mispfleet"

LOG_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})

LogFormat = Literal["text", "json"]


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger inside the ``mispfleet`` hierarchy."""
    if name:
        return logging.getLogger(f"{LOGGER_NAME}.{name}")
    return logging.getLogger(LOGGER_NAME)


class SecretRedactingFilter(logging.Filter):
    """Removes known secret values from every log record."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._secrets = [secret for secret in secrets if secret]

    @property
    def secrets(self) -> list[str]:
        """Secret values registered so far."""
        return self._secrets

    def add_secret(self, secret: str) -> None:
        """Register an additional secret value to redact."""
        if secret:
            self._secrets.append(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # A malformed call must neither crash the caller nor reach
            # handleError with its args intact: handleError prints "Arguments:"
            # straight to stderr, past both formatters and so past the only
            # place redaction runs over the final line. Every failure counts —
            # "%(tkoen)s" raises KeyError, and a msg whose __str__ raises can
            # come back as anything at all.
            try:
                message = f"{record.msg} [unformattable log arguments dropped]"
            except Exception:
                message = "[unformattable log record dropped]"
        record.msg = redact_text(message, self._secrets)
        record.args = None
        return True


class RedactingFormatter(logging.Formatter):
    """Text formatter that redacts the whole line, traceback included.

    The record filter only reaches ``record.msg``; an exception carrying an
    API key in its message would otherwise reach stderr through ``exc_info``.
    """

    def __init__(self, fmt: str, redactor: SecretRedactingFilter) -> None:
        super().__init__(fmt)
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record), self._redactor.secrets)


class JsonLogFormatter(logging.Formatter):
    """Structured JSON log lines with operation and server context."""

    def __init__(self, redactor: SecretRedactingFilter) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        secrets = self._redactor.secrets
        payload: dict[str, object] = {
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact_text(record.getMessage(), secrets),
        }
        if record.exc_info is not None:
            # Dropping the traceback here loses the failure detail in exactly
            # the mode meant for machine ingestion.
            payload["exception"] = redact_text(self.formatException(record.exc_info), secrets)
        for field in ("operation_id", "server", "endpoint", "request_id"):
            value = getattr(record, field, None)
            if value is not None:
                # Redacted like the message: the text formatter sanitizes the
                # whole rendered line, so leaving these raw made the JSON mode
                # the only one that could publish a secret in an endpoint.
                payload[field] = redact_text(str(value), secrets)
        return json.dumps(payload, sort_keys=True)


def configure_cli_logging(
    level: str = "warning",
    log_format: LogFormat = "text",
    stream: TextIO | None = None,
    secrets: Iterable[str] = (),
) -> SecretRedactingFilter:
    """Attach a redacting stderr handler to the ``mispfleet`` logger.

    Returns the redacting filter so callers can register secrets discovered
    later (for example after credential resolution).
    """
    if level.lower() not in LOG_LEVELS:
        # Validate before touching the handlers: raising afterwards left the
        # hierarchy stripped of the handler it had.
        raise InvalidConfigurationError(
            f"unsupported log level {level!r}; expected one of {sorted(LOG_LEVELS)}"
        )
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    redacting_filter = SecretRedactingFilter(secrets)
    if log_format == "json":
        handler.setFormatter(JsonLogFormatter(redacting_filter))
    else:
        handler.setFormatter(
            RedactingFormatter("%(levelname)s %(name)s: %(message)s", redacting_filter)
        )
    handler.addFilter(redacting_filter)
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    return redacting_filter
