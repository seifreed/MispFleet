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

from mispfleet.redaction import redact_text

LOGGER_NAME = "mispfleet"

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

    def add_secret(self, secret: str) -> None:
        """Register an additional secret value to redact."""
        if secret:
            self._secrets.append(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage(), self._secrets)
        record.args = None
        return True


class JsonLogFormatter(logging.Formatter):
    """Structured JSON log lines with operation and server context."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("operation_id", "server", "endpoint", "request_id"):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = str(value)
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
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    if log_format == "json":
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    redacting_filter = SecretRedactingFilter(secrets)
    handler.addFilter(redacting_filter)
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    return redacting_filter
