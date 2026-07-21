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

    Detects non-advancing pagination (a server returning the same page twice)
    and stops with a warning instead of looping forever. ``on_page`` receives
    ``(page_number, records_seen)`` after each page for checkpointing.
    """
    page = start_page
    yielded = 0
    previous_fingerprint: str | None = None
    while True:
        items = await fetch_page(page, page_size)
        if not items:
            return
        fingerprint = _page_fingerprint(items)
        if fingerprint == previous_fingerprint:
            if on_warning is not None:
                on_warning(f"pagination is not advancing (page {page} repeated); stopping")
            return
        previous_fingerprint = fingerprint
        for item in items:
            yield item
            yielded += 1
            if max_records is not None and yielded >= max_records:
                return
        if on_page is not None:
            on_page(page, yielded)
        if len(items) < page_size:
            return
        page += 1
