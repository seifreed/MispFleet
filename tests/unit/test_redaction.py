"""Unit and property tests for secret redaction."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mispfleet.redaction import (
    REDACTED,
    redact_headers,
    redact_mapping,
    redact_text,
    redact_url,
)
from tests.support import contains, eq, not_contains


def test_redact_headers_masks_sensitive_names_case_insensitively() -> None:
    headers = {
        "Authorization": "secret-key",
        "X-API-KEY": "secret-key",
        "Cookie": "session=abc",
        "Accept": "application/json",
    }
    redacted = redact_headers(headers)
    eq(redacted["Authorization"], REDACTED)
    eq(redacted["X-API-KEY"], REDACTED)
    eq(redacted["Cookie"], REDACTED)
    eq(redacted["Accept"], "application/json")


def test_redact_headers_supports_user_configured_names() -> None:
    redacted = redact_headers({"X-Custom-Secret": "abc"}, extra_sensitive=["x-custom-secret"])
    eq(redacted["X-Custom-Secret"], REDACTED)


def test_redact_mapping_recurses_into_nested_structures() -> None:
    leaked_a, leaked_b, leaked_c = "secret-key", "hunter2", "abc"
    data = {
        "name": "production",
        "api_key": leaked_a,
        "nested": {"password": leaked_b, "url": "https://x"},
        "items": [{"token": leaked_c}, {"value": "keep"}, "plain"],
    }
    redacted = redact_mapping(data)
    eq(redacted["api_key"], REDACTED)
    eq(redacted["nested"]["password"], REDACTED)
    eq(redacted["nested"]["url"], "https://x")
    eq(redacted["items"][0]["token"], REDACTED)
    eq(redacted["items"][1]["value"], "keep")
    eq(redacted["items"][2], "plain")
    eq(redacted["name"], "production")


def test_redact_mapping_supports_user_configured_fields() -> None:
    redacted = redact_mapping({"internal_ref": "x"}, extra_sensitive=["internal_ref"])
    eq(redacted["internal_ref"], REDACTED)


def test_redact_url_strips_userinfo() -> None:
    eq(
        redact_url("https://user:pass@misp.example/path?q=1"),
        f"https://{REDACTED}@misp.example/path?q=1",
    )
    eq(redact_url("https://misp.example/path"), "https://misp.example/path")


def test_redact_text_replaces_all_known_secrets() -> None:
    text = "key=abc123 other=abc123 empty="
    eq(redact_text(text, ["abc123", ""]), f"key={REDACTED} other={REDACTED} empty=")


@given(
    secret=st.text(min_size=8, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"),
    prefix=st.text(max_size=20),
    suffix=st.text(max_size=20),
)
def test_redact_text_never_leaks_the_secret(secret: str, prefix: str, suffix: str) -> None:
    redacted = redact_text(prefix + secret + suffix, [secret])
    not_contains(redacted, secret)
    contains(redacted, REDACTED)


@given(
    key=st.sampled_from(["api_key", "password", "token", "authkey", "secret"]),
    value=st.text(min_size=1),
)
def test_redact_mapping_never_leaks_known_fields(key: str, value: str) -> None:
    eq(redact_mapping({key: value})[key], REDACTED)
