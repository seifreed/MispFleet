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


def test_redact_mapping_strips_credentials_embedded_in_urls() -> None:
    leaked = "Pr0xyPass"
    redacted = redact_mapping(
        {
            "proxy": f"http://svc:{leaked}@proxy.corp:8080",
            "dsn": f"mysql://fleet:{leaked}@db/mispfleet",
            "url": "https://misp.example/",
            "info": "reach us at team@example.com",
        }
    )
    not_contains(redacted["proxy"], leaked)
    not_contains(redacted["dsn"], leaked)
    contains(redacted["proxy"], REDACTED)
    eq(redacted["url"], "https://misp.example/")
    eq(redacted["info"], "reach us at team@example.com")


def test_redact_url_handles_netlocs_urlsplit_refuses_to_parse() -> None:
    # Unbalanced IPv6 brackets make urlsplit raise ValueError, and every string
    # in a config dump or a MISP indicator value reaches redact_url.
    eq(redact_url("http://[::1"), "http://[::1")
    eq(
        redact_url("https://misp.example/ioc?u=http://ex[ample"),
        "https://misp.example/ioc?u=http://ex[ample",
    )
    leaked = "s3cr3t"
    eq(redact_url(f"http://admin:{leaked}@[::1"), f"http://{REDACTED}@[::1")
    eq(redact_url(f"https://u:{leaked}@[fe80::1]:8443/x"), f"https://{REDACTED}@[fe80::1]:8443/x")


def test_redact_url_strips_userinfo_from_scheme_relative_urls() -> None:
    """ "//user:pass@host/path" is a well-formed URL and still carries userinfo."""
    leaked = "hunter2"
    redacted = redact_url(f"//svc:{leaked}@proxy.corp:8080/x")
    not_contains(redacted, leaked)
    contains(redacted, REDACTED)
    eq(redact_url("//host/path"), "//host/path")
    eq(redact_url("//"), "//")


def test_redact_mapping_survives_malformed_urls_in_values() -> None:
    leaked = "Pr0xyPass"
    redacted = redact_mapping({"value": "http://[::1", "proxy": f"http://svc:{leaked}@[::1"})
    eq(redacted["value"], "http://[::1")
    not_contains(redacted["proxy"], leaked)
    contains(redacted["proxy"], REDACTED)


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


def test_credentials_inside_sequences_are_redacted() -> None:
    """Recursing only into mappings left a URL in a list untouched."""
    leaked = "hun" + "ter2"
    payload = {
        "proxies": [f"http://user:{leaked}@proxy.example:8080/"],
        "nested": [[f"https://user:{leaked}@host/path"]],
        "pair": (f"https://user:{leaked}@host/",),
    }
    redacted = redact_mapping(payload)
    not_contains(str(redacted), leaked)
    contains(redacted["proxies"][0], REDACTED)
    contains(redacted["nested"][0][0], REDACTED)
    contains(redacted["pair"][0], REDACTED)
    eq(type(redacted["pair"]), tuple)


def test_non_string_keys_do_not_crash_the_redactor() -> None:
    """A YAML/API mapping with int keys used to raise AttributeError."""
    leaked = "hun" + "ter2"
    redacted = redact_mapping({"ports": {8080: f"https://u:{leaked}@host/", 443: "plain"}})
    not_contains(str(redacted), leaked)
    eq(redacted["ports"][443], "plain")


def test_secrets_in_query_strings_and_fragments_are_redacted() -> None:
    """MISP feed URLs carry their key in the query, not the userinfo."""
    leaked = "SECRET" + "KEY"
    redacted = redact_mapping(
        {
            "feed": f"https://misp.local/feed?authkey={leaked}&limit=10",
            "callback": f"https://misp.local/cb#access_token={leaked}",
        }
    )
    not_contains(str(redacted), leaked)
    contains(redacted["feed"], "limit=10")
    contains(redacted["callback"], REDACTED)


def test_redacting_a_url_twice_changes_nothing_more() -> None:
    url = "https://user:pw@host/feed?authkey=abc#token=def"
    eq(redact_url(redact_url(url)), redact_url(url))
