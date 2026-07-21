"""Two-stage event copy: reviewable plan, then re-validated application."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from mispfleet.client import MispClient
from mispfleet.exceptions import (
    MispFleetError,
    NotFoundError,
    StalePlanError,
    UnsafePlanError,
)
from mispfleet.models.common import OperationWarning
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


async def _destination_has_event(destination: MispClient, event_uuid: str) -> bool:
    try:
        await destination.events.get(event_uuid)
    except NotFoundError:
        return False
    return True


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
        exists = False
    else:
        exists = await _destination_has_event(destination, source_event.uuid)
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
            proposed.uuid = str(uuid4())
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
    exists = await _destination_has_event(destination, plan.proposed_event.uuid)
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
        raise UnsafePlanError(
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
