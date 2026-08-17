"""Two-stage event copy: reviewable plan, then re-validated application."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from mispfleet.client import MispClient
from mispfleet.exceptions import (
    ConflictError,
    MispFleetError,
    NotFoundError,
    StalePlanError,
    UnsafePlanError,
)
from mispfleet.models.attribute import OBJECT_METADATA_FIELDS, MISPAttribute, MISPObject
from mispfleet.models.common import OperationWarning
from mispfleet.models.event import Galaxy, MISPEvent
from mispfleet.models.plan import (
    ApplyResult,
    ConflictAction,
    CopyPlan,
    PlanIssue,
    Transformation,
    ValidationResult,
)
from mispfleet.policies.base import PolicyContext
from mispfleet.policies.engine import PolicyEngine
from mispfleet.services.diff import attribute_sort_key as _attribute_sort_key
from mispfleet.services.diff import object_sort_key, proposal_key, sighting_key


async def _destination_event(destination: MispClient, event_uuid: str) -> MISPEvent | None:
    """The destination's copy of an event, or ``None`` when it has none."""
    try:
        return await destination.events.get(event_uuid)
    except NotFoundError:
        return None


_REWRITING_ACTIONS = (ConflictAction.UPDATE, ConflictAction.MERGE)


async def build_copy_plan(
    source: MispClient,
    destination: MispClient,
    event_id: str,
    engine: PolicyEngine,
    policy: str | None = None,
    on_conflict: ConflictAction = ConflictAction.ABORT,
    expires_in: timedelta | None = None,
) -> CopyPlan:
    """Build a credential-free copy plan without mutating the destination."""
    source_event = await source.events.get(event_id)
    context = PolicyContext(
        policy_name=policy or "",
        source_server=source.config.name,
        destination_server=destination.config.name,
    )
    policy_result = await engine.apply(policy, context, source_event)
    proposed = policy_result.transformed_event or source_event.model_copy(deep=True)
    transformations = list(policy_result.transformations)
    warnings = [OperationWarning(message=w.message) for w in policy_result.warnings]
    blocking: list[PlanIssue] = [
        PlanIssue(code="policy-violation", message=f"{v.rule}: {v.message}")
        for v in policy_result.violations
    ]
    validations: list[ValidationResult] = []

    writable = not destination.config.read_only
    validations.append(
        ValidationResult(
            name="destination-writable",
            passed=writable,
            message="" if writable else f"{destination.config.name} is read-only",
        )
    )
    if not writable:
        blocking.append(
            PlanIssue(
                code="destination-read-only",
                message=f"destination {destination.config.name} is configured read-only",
            )
        )
    try:
        await destination.system.version()
        validations.append(ValidationResult(name="destination-reachable", passed=True))
    except MispFleetError as error:
        validations.append(
            ValidationResult(name="destination-reachable", passed=False, message=error.message)
        )
        blocking.append(PlanIssue(code="destination-unreachable", message=error.message))
        existing = None
    else:
        existing = await _destination_event(destination, source_event.uuid)
    exists = existing is not None
    destination_fingerprint = (
        existing.canonical_fingerprint()
        if existing is not None and on_conflict in _REWRITING_ACTIONS
        else None
    )
    if exists:
        if on_conflict is ConflictAction.ABORT:
            blocking.append(
                PlanIssue(
                    code="destination-conflict",
                    message=(
                        f"event {source_event.uuid} already exists on "
                        f"{destination.config.name}; no implicit overwrite"
                    ),
                )
            )
        elif on_conflict is ConflictAction.SKIP:
            warnings.append(
                OperationWarning(message="destination already has the event; apply will skip")
            )
        elif on_conflict is ConflictAction.CREATE_NEW_UUID:
            renumber_event(proposed)
            transformations.append(
                Transformation(
                    action="new-uuid",
                    target=source_event.uuid,
                    detail=proposed.uuid,
                )
            )
    validations.append(
        ValidationResult(
            name="destination-conflict",
            passed=not exists or on_conflict is not ConflictAction.ABORT,
            message="destination already contains the event UUID" if exists else "",
        )
    )
    return CopyPlan(
        plan_id=uuid4(),
        source_server=source.config.name,
        destination_server=destination.config.name,
        source_event_uuid=UUID(source_event.uuid),
        source_fingerprint=source_event.canonical_fingerprint(),
        destination_fingerprint=destination_fingerprint,
        generated_at=datetime.now(tz=UTC),
        expires_at=datetime.now(tz=UTC) + expires_in if expires_in else None,
        policy=policy,
        on_conflict=on_conflict,
        transformations=transformations,
        validations=validations,
        warnings=warnings,
        blocking_errors=blocking,
        proposed_event=proposed,
    )


def renumber_event(event: MISPEvent) -> None:
    """Give the event and every child a fresh UUID, keeping references intact.

    MISP enforces server-wide uniqueness for attribute and object UUIDs, so a
    copy that renames only the event collides on every child: the destination
    stores an empty shell and reports success. Object references are rewritten
    through the same mapping so they still point inside the new event.
    """
    mapping: dict[str, str] = {}

    def fresh(previous: str | None) -> str:
        replacement = str(uuid4())
        if previous:
            mapping[previous] = replacement
        return replacement

    event.uuid = fresh(event.uuid)
    for attribute in event.attributes:
        attribute.uuid = fresh(attribute.uuid)
    for obj in event.objects:
        obj.uuid = fresh(obj.uuid)
        for attribute in obj.attributes:
            attribute.uuid = fresh(attribute.uuid)
        for reference in obj.references:
            reference.uuid = fresh(reference.uuid)
    for sighting in event.sightings:
        sighting.uuid = fresh(sighting.uuid)
    for proposal in event.proposals:
        proposal.uuid = fresh(proposal.uuid)
    for obj in event.objects:
        for reference in obj.references:
            if reference.object_uuid is not None:
                reference.object_uuid = mapping.get(reference.object_uuid, reference.object_uuid)
            reference.referenced_uuid = mapping.get(
                reference.referenced_uuid, reference.referenced_uuid
            )
    for sighting in event.sightings:
        # The original event is by definition still on the destination in this
        # path, so an un-remapped attribute_uuid attaches the sighting to that
        # event's attribute instead of the copy's.
        if sighting.attribute_uuid is not None:
            sighting.attribute_uuid = mapping.get(sighting.attribute_uuid, sighting.attribute_uuid)


def _uuid_safe(attribute: MISPAttribute, taken: set[str]) -> MISPAttribute:
    """A copy of ``attribute`` that cannot collide with an existing UUID.

    The union pairs attributes by ``(type, value)`` while the UUID travels
    unchanged from the source, so a policy that rewrote the value — any
    ``redact_values`` rule — offers the destination its own UUID attached to
    different content. MISP enforces server-wide uniqueness for attribute
    UUIDs and, as renumber_event notes, stores the colliding event as an empty
    shell while reporting success. Sending it without one lets the destination
    assign a fresh UUID instead.
    """
    if attribute.uuid is None or attribute.uuid not in taken:
        return attribute
    return attribute.model_copy(update={"uuid": None})


def _adoption_key(obj: MISPObject) -> tuple[str, str]:
    """Identity of an object for adoption, blind only to attribute UUIDs.

    Reservation may strip those UUIDs, and an identity that counted them made
    the stripped copy look like a different object on the next merge. Nothing
    else is ignored: an object differing only in its references or metadata is
    a different object and must still be adopted. Built through the canonical
    hash rather than a hand-rolled join, which "regkey" + "value|X" and
    "regkey|value" + "X" — one of MISP's composite types — collided in.
    """
    blind = obj.model_copy(deep=True)
    for attribute in blind.attributes:
        attribute.uuid = None
    return (obj.uuid or "", object_sort_key(blind))


def _reserve(attributes: list[MISPAttribute], taken: set[str]) -> list[MISPAttribute]:
    """Emit attributes, claiming each UUID so the next one cannot reuse it.

    A set built once from the destination missed duplicates originating inside
    the proposal itself: two proposed attributes carrying one UUID both passed
    the check and landed as a pair MISP cannot store.
    """
    emitted = []
    for attribute in attributes:
        safe = _uuid_safe(attribute, taken)
        if safe.uuid is not None:
            taken.add(safe.uuid)
        emitted.append(safe)
    return emitted


def _attribute_uuids(event: MISPEvent) -> set[str]:
    """Every attribute UUID the destination already stores."""
    return {
        attribute.uuid
        for attribute in (
            *event.attributes,
            *(inner for obj in event.objects for inner in obj.attributes),
        )
        if attribute.uuid
    }


def _merge_object(
    destination: MISPObject, proposed: MISPObject | None, taken: set[str] | None = None
) -> MISPObject:
    """Union one object's attributes and references with its proposed twin.

    Objects present on both sides used to keep the destination copy untouched,
    so enrichment added inside an existing object — a new hash, a new
    reference — was dropped while apply still reported success.
    """
    if proposed is None:
        # Copied, never aliased: the result used to be the destination's own
        # object, so a caller touching the merged event wrote straight back
        # into the event it had merged from.
        return destination.model_copy(deep=True)
    merged = destination.model_copy(deep=True)
    seen = {(attribute.type, attribute.value) for attribute in merged.attributes}
    reserved = taken if taken is not None else set()
    merged.attributes += _reserve(
        sorted(
            (
                attribute
                for attribute in proposed.attributes
                if (attribute.type, attribute.value) not in seen
            ),
            # The total key, as the event-level union uses: (type, value)
            # leaves two attributes alike but for their UUID tied, and the
            # stable sort then hands the order back to the source's storage.
            key=_attribute_sort_key,
        ),
        reserved,
    )
    for field in OBJECT_METADATA_FIELDS:
        # The destination's own value wins, but a field it never had must not
        # discard what the reviewed plan proposed: the resulting event then
        # diffed against the proposal forever, and no further merge closed it.
        if not getattr(merged, field) and getattr(proposed, field):
            setattr(merged, field, getattr(proposed, field))
    known = {
        (reference.referenced_uuid, reference.relationship_type) for reference in merged.references
    }
    merged.references += sorted(
        (
            reference
            for reference in proposed.references
            if (reference.referenced_uuid, reference.relationship_type) not in known
        ),
        key=lambda reference: (reference.referenced_uuid, reference.relationship_type),
    )
    return merged


def merge_events(destination: MISPEvent, proposed: MISPEvent) -> MISPEvent:
    """Deterministic union merge: destination metadata wins, content is united.

    Attributes are united by their ``(type, value)`` pair — the destination's
    copy is kept when both sides carry the same indicator — objects by UUID
    only, since a name alone cannot say which of several same-named objects a
    proposed one enriches; galaxies by UUID, because two of them can share a
    name; and tags are the plain set union. Nothing is ever removed from the
    destination, and everything the reviewed plan proposed is carried over:
    dropping objects and galaxies silently lost object-borne indicators the
    operator had approved.
    """
    taken = _attribute_uuids(destination)
    # Attributes reserve UUIDs into ``taken`` before objects merge, so an
    # adopted object cannot reuse one an attribute already claimed.
    merged_attributes = _merge_attributes(destination, proposed, taken)
    merged_objects = _merge_objects(destination, proposed, taken)
    return destination.model_copy(
        update={
            "attributes": merged_attributes,
            "objects": merged_objects,
            "galaxies": _merge_galaxies(destination, proposed),
            "tags": _merge_tags(destination.tags, proposed.tags),
            "sightings": _united(destination.sightings, proposed.sightings, sighting_key),
            "proposals": _united(destination.proposals, proposed.proposals, proposal_key),
        }
    )


def _merge_attributes(
    destination: MISPEvent, proposed: MISPEvent, taken: set[str]
) -> list[MISPAttribute]:
    """Unite attributes by ``(type, value)``; the destination's copy wins a tie."""
    seen = {(attribute.type, attribute.value) for attribute in destination.attributes}
    seen.update(
        (attribute.type, attribute.value)
        for obj in destination.objects
        for attribute in obj.attributes
    )
    return list(destination.attributes) + _reserve(
        sorted(
            (
                attribute
                for attribute in proposed.attributes
                if (attribute.type, attribute.value) not in seen
            ),
            key=_attribute_sort_key,
        ),
        taken,
    )


def _merge_objects(
    destination: MISPEvent, proposed: MISPEvent, taken: set[str]
) -> list[MISPObject]:
    """Unite objects by UUID; UUID-less proposals with no twin are adopted whole."""
    # Objects are merged by UUID alone. MISP enforces server-wide uniqueness
    # for object UUIDs, so two objects sharing one are the same object however
    # their template names read, and emitting both would be a payload the
    # destination cannot store. An object without a UUID has no unambiguous
    # identity at all: matching it by name would have to guess which of several
    # same-named objects a proposed one enriches, and guessing wrong moves
    # indicators onto the wrong object.
    twins: dict[str, MISPObject] = {}
    for obj in sorted(proposed.objects, key=object_sort_key):
        if not obj.uuid:
            continue
        existing = twins.get(obj.uuid)
        twins[obj.uuid] = (
            obj.model_copy(deep=True) if existing is None else _merge_object(existing, obj, taken)
        )
    # Uniting each UUID's proposals into one twin first leaves nothing to pair
    # ambiguously. The destination's own duplicates are its data and are left
    # alone; the twin goes to the canonically first of them, so neither
    # server's storage order decides which object receives the enrichment.
    positions: dict[str, list[int]] = {}
    for index, obj in enumerate(destination.objects):
        positions.setdefault(obj.uuid or "", []).append(index)
    resolved: dict[int, MISPObject] = {}
    for object_uuid, indexes in positions.items():
        twin = twins.pop(object_uuid, None) if object_uuid else None
        ordered = sorted(indexes, key=lambda i: object_sort_key(destination.objects[i]))
        for rank, index in enumerate(ordered):
            resolved[index] = _merge_object(
                destination.objects[index], twin if rank == 0 else None, taken
            )
    merged_objects = [resolved[index] for index in range(len(destination.objects))]
    # What is left has no destination counterpart. It is appended unless the
    # destination already holds the same object: appending unconditionally grew
    # the event on every repeated merge. The identity has to include the UUID,
    # or a proposed object would be suppressed by a UUID-less destination
    # object that merely looks alike.
    # Keyed on content that survives reservation: _reserve may strip an
    # adopted object's attribute UUIDs, and keying on the full sort hash then
    # stopped the stripped copy from matching its own proposal next time, so
    # every repeated merge adopted it again and the event grew without bound.
    stored = {_adoption_key(obj) for obj in merged_objects}
    leftovers = list(twins.values()) + [obj for obj in proposed.objects if not obj.uuid]
    # An object with no counterpart is copied whole, so its attributes never
    # passed the UUID check the paired ones go through: a proposal carrying one
    # UUID on a top-level attribute and on an attribute inside a brand-new
    # object emitted the pair MISP cannot store. Only these are reserved — the
    # destination's own attributes are in `taken` because they are already
    # stored under those UUIDs, and running them through it stripped the very
    # identities the destination is keyed on.
    adopted = [
        obj.model_copy(deep=True)
        for obj in sorted(
            (obj for obj in leftovers if _adoption_key(obj) not in stored),
            key=object_sort_key,
        )
    ]
    for obj in adopted:
        obj.attributes = _reserve(obj.attributes, taken)
    merged_objects += adopted
    return merged_objects


def _merge_galaxies(destination: MISPEvent, proposed: MISPEvent) -> list[Galaxy]:
    """Unite galaxies by UUID (name as fallback); the destination's clusters win.

    Galaxies are identified by UUID when they have one: stock MISP ships two
    distinct galaxies both named "Techniques" (mitre-ics and disarm), and
    keying on the name alone folded one into the other. The destination is
    seeded first so its own record wins, as it does for every other field;
    the proposal only contributes clusters and galaxies the destination lacks.
    """
    merged_galaxies: dict[str, Galaxy] = {}

    def unite(galaxy: Galaxy) -> None:
        identity = galaxy.uuid or f"name:{galaxy.name}"
        united = merged_galaxies.get(identity)
        if united is None:
            merged_galaxies[identity] = galaxy.model_copy(deep=True)
        else:
            united.clusters |= set(galaxy.clusters)

    # Canonical order on both sides so neither server's storage order decides
    # which of two entries sharing an identity is the one kept.
    for galaxy in sorted(destination.galaxies, key=lambda item: (item.name, item.uuid or "")):
        unite(galaxy)
    for galaxy in sorted(proposed.galaxies, key=lambda item: (item.name, item.uuid or "")):
        unite(galaxy)
    return [merged_galaxies[key] for key in sorted(merged_galaxies)]


def _merge_tags(destination: set[str], proposed: set[str]) -> set[str]:
    """Union two tag sets under MISP's case-insensitive collation.

    Destination wins, as for every other field: TLP:RED and tlp:red are one
    tag on the server, so a proposed tag that differs from a destination tag
    only in case must not be added as a phantom second copy (a plain set union
    kept both, and the merged event then fingerprinted with a duplicate tag no
    real server can hold). Each side is already case-unique per that same
    collation, so keeping the destination's exact spelling is enough.
    """
    seen = {tag.casefold() for tag in destination}
    return destination | {tag for tag in proposed if tag.casefold() not in seen}


def _united[T](
    destination: list[T], proposed: list[T], key: Callable[[T], tuple[str, ...]]
) -> list[T]:
    """Destination's entries plus the proposed ones it does not already carry.

    Both dimensions used to be left out of the merge entirely, so applying a
    reviewed plan with on_conflict=MERGE reported the copy merged while the
    sightings and proposals the operator had just approved never landed.
    Additions are sorted so neither side's storage order reaches the result.
    """
    united = list(destination)
    # Multiset, matching how the diff compares these dimensions: collapsing two
    # identical sightings into one made `event diff` report a difference
    # immediately after a successful merge.
    held = Counter(key(item) for item in destination)
    for item in sorted(proposed, key=key):
        if held[key(item)]:
            held[key(item)] -= 1
            continue
        united.append(item)
    return united


async def apply_copy_plan(
    source: MispClient,
    destination: MispClient,
    plan: CopyPlan,
) -> ApplyResult:
    """Re-validate and execute a copy plan exactly once."""
    if plan.blocking_errors:
        raise UnsafePlanError(
            "plan has blocking errors: "
            + "; ".join(issue.message for issue in plan.blocking_errors)
        )
    if plan.expires_at is not None and datetime.now(tz=UTC) > plan.expires_at:
        raise StalePlanError(f"plan expired at {plan.expires_at.isoformat()}")
    if source.config.name != plan.source_server:
        raise UnsafePlanError(
            f"plan source is {plan.source_server!r} but client targets " f"{source.config.name!r}"
        )
    if destination.config.name != plan.destination_server:
        raise UnsafePlanError(
            f"plan destination is {plan.destination_server!r} but client targets "
            f"{destination.config.name!r}"
        )
    if destination.config.read_only:
        raise UnsafePlanError(f"destination {destination.config.name} is read-only")
    current = await source.events.get(str(plan.source_event_uuid))
    if current.canonical_fingerprint() != plan.source_fingerprint:
        raise StalePlanError(
            "source event changed after the plan was generated; regenerate the plan"
        )
    operation_id = uuid4()
    destination_event = await _destination_event(destination, plan.proposed_event.uuid)
    exists = destination_event is not None
    if (
        destination_event is not None
        and plan.on_conflict in _REWRITING_ACTIONS
        and destination_event.canonical_fingerprint() != plan.destination_fingerprint
    ):
        # Only the source side was re-checked, so an analyst enriching the
        # destination between review and apply had their work overwritten by
        # older content -- with newer-wins reporting success.
        raise StalePlanError(
            "destination event changed after the plan was generated; regenerate the plan"
        )
    if exists:
        if plan.on_conflict is ConflictAction.SKIP:
            return ApplyResult(
                operation_id=operation_id,
                plan_id=plan.plan_id,
                applied=False,
                destination_server=plan.destination_server,
                messages=["destination already contains the event; skipped"],
            )
        if plan.on_conflict is ConflictAction.UPDATE:
            updated = await destination.events.update(plan.proposed_event)
            return ApplyResult(
                operation_id=operation_id,
                plan_id=plan.plan_id,
                applied=True,
                destination_server=plan.destination_server,
                destination_event_uuid=UUID(updated.uuid),
                messages=["existing destination event updated"],
            )
        if plan.on_conflict is ConflictAction.MERGE and destination_event is not None:
            # The copy the staleness check just approved, not a second fetch:
            # re-reading here reopened the window that check exists to close,
            # so an analyst's edit landing between the two GETs was merged
            # over without the StalePlanError firing.
            merged = merge_events(destination_event, plan.proposed_event)
            updated = await destination.events.update(merged)
            return ApplyResult(
                operation_id=operation_id,
                plan_id=plan.plan_id,
                applied=True,
                destination_server=plan.destination_server,
                destination_event_uuid=UUID(updated.uuid),
                messages=["existing destination event merged with the proposed copy"],
            )
        if plan.on_conflict is ConflictAction.CREATE_NEW_UUID:
            # The event was absent at planning time, so the new-uuid branch
            # never ran; honor the chosen resolution instead of refusing.
            renamed = plan.proposed_event.model_copy(deep=True)
            renumber_event(renamed)
            created = await destination.events.add(renamed)
            return ApplyResult(
                operation_id=operation_id,
                plan_id=plan.plan_id,
                applied=True,
                destination_server=plan.destination_server,
                destination_event_uuid=UUID(created.uuid),
                messages=["destination already had the event; created under a new UUID"],
            )
        raise ConflictError(
            f"event {plan.proposed_event.uuid} appeared on the destination after "
            "planning; no implicit overwrite"
        )
    created = await destination.events.add(plan.proposed_event)
    return ApplyResult(
        operation_id=operation_id,
        plan_id=plan.plan_id,
        applied=True,
        destination_server=plan.destination_server,
        destination_event_uuid=UUID(created.uuid),
        messages=["event created on destination"],
    )
