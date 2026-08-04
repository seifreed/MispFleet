"""Property-based tests for query round trips, fingerprints and pagination."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mispfleet.client.pagination import paginate
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent
from mispfleet.models.query import SearchQuery
from mispfleet.settings import FleetDefaults, _merge
from tests.support import eq, ok

TYPES = st.sets(st.sampled_from(["domain", "sha256", "ip-dst", "url"]), max_size=4)
TAGS = st.sets(st.sampled_from(["tlp:green", "tlp:amber", "approved"]), max_size=3)
ORGS = st.sets(st.sampled_from(["CIRCL", "ACME", "Partner"]), max_size=3)


@given(
    value=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    attribute_types=TYPES,
    tags=TAGS,
    organisations=ORGS,
    published=st.one_of(st.none(), st.booleans()),
    metadata_only=st.booleans(),
)
def test_search_query_round_trips_through_json(
    value: str | None,
    attribute_types: set[str],
    tags: set[str],
    organisations: set[str],
    published: bool | None,
    metadata_only: bool,
) -> None:
    query = SearchQuery(
        value=value,
        attribute_types=attribute_types,
        tags=tags,
        organisations=organisations,
        published=published,
        metadata_only=metadata_only,
    )
    rebuilt = SearchQuery.model_validate_json(query.model_dump_json())
    eq(rebuilt, query)
    eq(rebuilt.fingerprint(), query.fingerprint())


def build_set(values: list[str]) -> set[str]:
    """Build a set by inserting values one at a time in the given order."""
    result: set[str] = set()
    for value in values:
        result.add(value)
    return result


@given(attribute_types=TYPES, tags=TAGS, organisations=ORGS)
def test_query_fingerprint_ignores_set_ordering(
    attribute_types: set[str], tags: set[str], organisations: set[str]
) -> None:
    left = SearchQuery(
        attribute_types=build_set(sorted(attribute_types)),
        tags=build_set(sorted(tags)),
        organisations=build_set(sorted(organisations)),
    )
    right = SearchQuery(
        attribute_types=build_set(sorted(attribute_types, reverse=True)),
        tags=build_set(sorted(tags, reverse=True)),
        organisations=build_set(sorted(organisations, reverse=True)),
    )
    eq(left.fingerprint(), right.fingerprint())
    eq(left.to_misp_payload(), right.to_misp_payload())


@given(
    values=st.lists(st.text(min_size=1, max_size=8), min_size=1, max_size=6, unique=True),
    tags=TAGS,
)
def test_event_fingerprint_is_stable_under_reordering(values: list[str], tags: set[str]) -> None:
    attributes = [MISPAttribute(type="domain", value=value, tags=tags) for value in values]
    left = MISPEvent(uuid="9c5c1c2e-0000-4000-8000-00000000000e", attributes=attributes)
    right = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        attributes=list(reversed(attributes)),
    )
    eq(left.canonical_fingerprint(), right.canonical_fingerprint())


@given(
    total=st.integers(min_value=0, max_value=250),
    page_size=st.integers(min_value=1, max_value=50),
)
async def test_pagination_always_terminates_and_yields_every_record(
    total: int, page_size: int
) -> None:
    async def fetch(page: int, limit: int) -> list[dict[str, object]]:
        start = (page - 1) * limit
        if start >= total:
            return []
        return [{"id": str(index)} for index in range(start, min(start + limit, total))]

    seen = [record async for record in paginate(fetch, page_size=page_size)]
    eq(len(seen), total)
    eq([record["id"] for record in seen], [str(index) for index in range(total)])


@given(
    base_timeout=st.floats(min_value=1.0, max_value=100.0),
    override_timeout=st.floats(min_value=1.0, max_value=100.0),
    concurrency=st.integers(min_value=1, max_value=20),
)
def test_configuration_merge_precedence_prefers_the_override(
    base_timeout: float, override_timeout: float, concurrency: int
) -> None:
    base = {"defaults": {"request_timeout": base_timeout, "concurrency": 1}}
    override = {"defaults": {"request_timeout": override_timeout, "concurrency": concurrency}}
    merged = _merge(base, override)
    defaults = FleetDefaults.model_validate(merged["defaults"])
    eq(defaults.request_timeout, override_timeout)
    eq(defaults.concurrency, concurrency)
    ok(_merge(base, {}) == base)
