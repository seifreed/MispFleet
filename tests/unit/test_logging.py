"""Unit tests for the logging helpers."""

from __future__ import annotations

import io
import json
import logging
import sys

import pytest

from mispfleet.exceptions import InvalidConfigurationError
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
    formatter = JsonLogFormatter(SecretRedactingFilter())
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


def test_text_output_redacts_secrets_inside_tracebacks() -> None:
    """The record filter only reaches record.msg.

    An API key quoted in an exception message reached stderr through the
    formatter's exc_info rendering.
    """
    leaked = "SUPER" + "SECRET" + "KEY"
    stream = io.StringIO()
    redacting_filter = configure_cli_logging(level="debug", log_format="text", stream=stream)
    redacting_filter.add_secret(leaked)
    logger = get_logger("test")
    try:
        raise ValueError(f"server rejected key {leaked}")
    except ValueError:
        logger.exception("request failed")
    output = stream.getvalue()
    not_contains(output, leaked)
    contains(output, REDACTED)
    contains(output, "ValueError")
    logging.getLogger(LOGGER_NAME).handlers.clear()


def test_json_output_carries_a_redacted_traceback() -> None:
    """The JSON formatter dropped exc_info entirely."""
    leaked = "SUPER" + "SECRET" + "KEY"
    stream = io.StringIO()
    redacting_filter = configure_cli_logging(level="debug", log_format="json", stream=stream)
    redacting_filter.add_secret(leaked)
    logger = get_logger("test")
    try:
        raise ValueError(f"server rejected key {leaked}")
    except ValueError:
        logger.exception("request failed")
    record = json.loads(stream.getvalue())
    contains(record["exception"], "ValueError")
    not_contains(record["exception"], leaked)
    contains(record["exception"], REDACTED)
    logging.getLogger(LOGGER_NAME).handlers.clear()


def test_a_malformed_log_call_neither_crashes_nor_leaks_the_secret() -> None:
    """Formatting in the filter took the stdlib's error handling away.

    ``logging`` interpolates in the handler, where a bad format reaches
    ``handleError``; doing it in a filter propagated the ``TypeError`` into
    whatever operation happened to be logging. Leaving ``args`` in place for
    the handler to trip over is not the fix either: ``handleError`` prints
    ``Arguments:`` straight to stderr, past both formatters and so past the
    only place redaction runs.
    """
    leaked = "SUPER" + "SECRETKEY123"
    stream = io.StringIO()
    errors = io.StringIO()
    real_stderr = sys.stderr
    sys.stderr = errors
    try:
        redacting_filter = configure_cli_logging(level="debug", stream=stream)
        redacting_filter.add_secret(leaked)
        get_logger("test").info("resolved key %d", leaked)
    finally:
        sys.stderr = real_stderr
    logging.getLogger(LOGGER_NAME).handlers.clear()
    not_contains(stream.getvalue() + errors.getvalue(), leaked)


def test_an_unknown_log_level_is_refused_before_handlers_are_touched() -> None:
    stream = io.StringIO()
    configure_cli_logging(level="debug", stream=stream)
    before = list(logging.getLogger(LOGGER_NAME).handlers)
    with pytest.raises(InvalidConfigurationError):
        configure_cli_logging(level="verbose", stream=stream)
    eq(logging.getLogger(LOGGER_NAME).handlers, before)
    logging.getLogger(LOGGER_NAME).handlers.clear()


def test_a_log_call_that_cannot_be_rendered_at_all_is_still_survivable() -> None:
    """ "%(tkoen)s" raises KeyError, not TypeError, and msg may not be a string.

    The filter caught only TypeError and ValueError, so a mistyped mapping key
    still crashed the operation that was logging.
    """

    class Unprintable:
        def __str__(self) -> str:
            raise RuntimeError("no repr for you")

    stream = io.StringIO()
    errors = io.StringIO()
    real_stderr = sys.stderr
    sys.stderr = errors
    try:
        configure_cli_logging(level="debug", stream=stream)
        logger = get_logger("test")
        logger.info("event %(evnet)s", {"event": "abc"})
        logger.info(Unprintable())
    finally:
        sys.stderr = real_stderr
    logging.getLogger(LOGGER_NAME).handlers.clear()
    # Both lines were emitted rather than swallowed, and neither reached
    # handleError — which is what "Arguments:" on stderr would mean.
    eq(len(stream.getvalue().strip().splitlines()), 2)
    not_contains(errors.getvalue(), "Arguments:")


def test_json_context_fields_are_redacted_like_the_message() -> None:
    """The text formatter sanitizes the whole line; JSON emitted these raw."""
    leaked = "SUPER" + "SECRETKEY456"
    stream = io.StringIO()
    redacting_filter = configure_cli_logging(level="debug", log_format="json", stream=stream)
    redacting_filter.add_secret(leaked)
    get_logger("test").info("feed fetched", extra={"endpoint": f"/feeds/fetch?authkey={leaked}"})
    record = json.loads(stream.getvalue())
    not_contains(record["endpoint"], leaked)
    contains(record["endpoint"], REDACTED)
    logging.getLogger(LOGGER_NAME).handlers.clear()
