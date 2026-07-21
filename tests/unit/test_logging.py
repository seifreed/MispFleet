"""Unit tests for the logging helpers."""

from __future__ import annotations

import io
import json
import logging

from mispfleet.logging import (
    LOGGER_NAME,
    JsonLogFormatter,
    SecretRedactingFilter,
    configure_cli_logging,
    get_logger,
)
from mispfleet.redaction import REDACTED
from tests.support import contains, eq, not_contains


def test_get_logger_stays_inside_the_mispfleet_hierarchy() -> None:
    eq(get_logger().name, LOGGER_NAME)
    eq(get_logger("client.transport").name, f"{LOGGER_NAME}.client.transport")


def test_configure_cli_logging_redacts_secrets_in_text_mode() -> None:
    stream = io.StringIO()
    redacting_filter = configure_cli_logging(level="info", stream=stream, secrets=["s3cret"])
    redacting_filter.add_secret("later-secret")
    redacting_filter.add_secret("")
    logger = get_logger("test")
    logger.info("key=s3cret later=later-secret")
    output = stream.getvalue()
    not_contains(output, "s3cret")
    not_contains(output, "later-secret")
    contains(output, REDACTED)
    logging.getLogger(LOGGER_NAME).handlers.clear()


def test_configure_cli_logging_json_mode_emits_structured_lines() -> None:
    stream = io.StringIO()
    configure_cli_logging(level="info", log_format="json", stream=stream)
    logger = get_logger("test")
    logger.info("hello %s", "world")
    record = json.loads(stream.getvalue())
    eq(record["message"], "hello world")
    eq(record["level"], "info")
    contains(record["logger"], LOGGER_NAME)
    logging.getLogger(LOGGER_NAME).handlers.clear()


def test_json_formatter_includes_context_fields() -> None:
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="mispfleet.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request finished",
        args=None,
        exc_info=None,
    )
    record.server = "production"
    record.operation_id = "op-1"
    payload = json.loads(formatter.format(record))
    eq(payload["server"], "production")
    eq(payload["operation_id"], "op-1")


def test_redacting_filter_handles_formatted_arguments() -> None:
    redacting_filter = SecretRedactingFilter(["secret-key"])
    record = logging.LogRecord(
        name="mispfleet.test",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=1,
        msg="auth header %s",
        args=("secret-key",),
        exc_info=None,
    )
    redacting_filter.filter(record)
    not_contains(record.getMessage(), "secret-key")
