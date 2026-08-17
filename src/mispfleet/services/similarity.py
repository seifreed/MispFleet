"""Deterministic event-similarity scoring for grouping, diff and merge decisions.

Similarity never merges anything on its own (§19): it only produces a stable
score that grouping, ``event diff`` and conflict handling can surface.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from pydantic import BaseModel, Field

from mispfleet.models.event import MISPEvent, composite_key

ATTRIBUTE_WEIGHT = 0.5
TAG_WEIGHT = 0.2
INFO_WEIGHT = 0.3
SHARED_INDICATORS_MINIMUM = 2
POSSIBLE_MATCH_THRESHOLD = 0.7


class SimilarityScore(BaseModel):
    """Breakdown of how alike two events are, on a 0-1 scale."""

    score: float = Field(ge=0.0, le=1.0)
    shared_indicators: int
    attribute_overlap: float = Field(ge=0.0, le=1.0)
    tag_overlap: float = Field(ge=0.0, le=1.0)
    info_similarity: float = Field(ge=0.0, le=1.0)


def _jaccard(left: set[str], right: set[str]) -> float:
    # Two empty sets share no evidence of similarity. Scoring that as a perfect
    # 1.0 pushed every untagged pair over POSSIBLE_MATCH_THRESHOLD on its own.
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def similarity_from_parts(
    left_indicators: set[str],
    right_indicators: set[str],
    left_tags: set[str],
    right_tags: set[str],
    left_info: str,
    right_info: str,
) -> SimilarityScore:
    """Score two events from their indicator sets, tags and info strings."""
    attribute_overlap = _jaccard(left_indicators, right_indicators)
    # MISP tags are case-insensitive, so TLP:RED and tlp:red are one tag: fold
    # before scoring or two identically-tagged events look less alike than they
    # are and drop below POSSIBLE_MATCH_THRESHOLD.
    tag_overlap = _jaccard(
        {tag.casefold() for tag in left_tags}, {tag.casefold() for tag in right_tags}
    )
    # ponytail: SequenceMatcher.ratio() is order-sensitive; canonical ordering keeps it symmetric
    first, second = sorted((left_info, right_info))
    info_similarity = SequenceMatcher(None, first, second).ratio()
    score = (
        ATTRIBUTE_WEIGHT * attribute_overlap
        + TAG_WEIGHT * tag_overlap
        + INFO_WEIGHT * info_similarity
    )
    return SimilarityScore(
        score=round(score, 4),
        shared_indicators=len(left_indicators & right_indicators),
        attribute_overlap=round(attribute_overlap, 4),
        tag_overlap=round(tag_overlap, 4),
        info_similarity=round(info_similarity, 4),
    )


def indicator_set(event: MISPEvent) -> set[str]:
    """The event's comparable ``type|value`` indicator set, objects included."""
    plain = {composite_key(a.type, a.value) for a in event.attributes}
    nested = {composite_key(a.type, a.value) for obj in event.objects for a in obj.attributes}
    return plain | nested


def event_similarity(left: MISPEvent, right: MISPEvent) -> SimilarityScore:
    """Deterministic, symmetric similarity between two normalized events."""
    return similarity_from_parts(
        indicator_set(left),
        indicator_set(right),
        left.tags,
        right.tags,
        left.info,
        right.info,
    )
