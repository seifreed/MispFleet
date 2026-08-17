"""Memory-safe pagination over MISP search endpoints."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

PageFetcher = Callable[[int, int], Awaitable[list[dict[str, Any]]]]
PageCallback = Callable[[int, int], None]
WarningCallback = Callable[[str], None]


def _page_fingerprint(items: list[dict[str, Any]]) -> str:
    payload = json.dumps(items, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def paginate(
    fetch_page: PageFetcher,
    page_size: int,
    max_records: int | None = None,
    start_page: int = 1,
    on_page: PageCallback | None = None,
    on_warning: WarningCallback | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """Yield records page by page without materializing the full dataset.

    Detects non-advancing pagination and stops with a warning instead of
    looping forever. Every page seen is remembered, not just the previous one:
    a server alternating two pages defeats a single-page comparison and
    streams duplicates without end. ``on_page`` receives
    ``(page_number, records_seen)`` once each page has been fetched, where
    ``records_seen`` counts the records retrieved from the server so far —
    not the ones the consumer went on to accept.
    """
    page = start_page
    yielded = 0
    if max_records is not None and max_records <= 0:
        return
    seen_fingerprints: set[str] = set()
    while True:
        items = await fetch_page(page, page_size)
        if not items:
            return
        fingerprint = _page_fingerprint(items)
        if fingerprint in seen_fingerprints:
            if on_warning is not None:
                on_warning(f"pagination is not advancing (page {page} repeated); stopping")
            return
        seen_fingerprints.add(fingerprint)
        # Reported as soon as the page is fetched: a consumer that stops
        # mid-page suspends this generator at the yield below, so a callback
        # placed after the loop never fired and checkpoints went missing.
        if on_page is not None:
            on_page(page, yielded + len(items))
        exhausted = False
        for item in items:
            yield item
            yielded += 1
            if max_records is not None and yielded >= max_records:
                exhausted = True
                break
        if exhausted or len(items) < page_size:
            return
        page += 1
