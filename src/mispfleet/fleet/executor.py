"""Bounded concurrent execution of one operation across many servers."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import uuid4

from mispfleet.exceptions import MispFleetError, PartialFleetError
from mispfleet.logging import get_logger
from mispfleet.models.common import ExecutionOptions, FailurePolicy, ServerError
from mispfleet.models.result import MultiServerResult

logger = get_logger("fleet.executor")


def server_error_from(server: str, error: MispFleetError) -> ServerError:
    """Convert a typed exception into its secret-free data representation."""
    return ServerError(
        server=server,
        kind=type(error).__name__,
        message=error.message,
        status_code=error.context.status_code,
        retryable=error.context.retryable,
    )


class FleetExecutor:
    """Runs one coroutine per server with bounded concurrency.

    Uses ``asyncio.TaskGroup`` for coordinated task lifetime: on fail-fast
    policies the first failure cancels every outstanding request.
    """

    async def run[T](
        self,
        servers: list[str],
        operation: Callable[[str], Awaitable[T]],
        options: ExecutionOptions | None = None,
    ) -> MultiServerResult[T]:
        """Execute ``operation`` against every server and build the envelope."""
        options = options or ExecutionOptions()
        results: dict[str, T] = {}
        errors: dict[str, ServerError] = {}
        semaphore = asyncio.Semaphore(options.max_concurrency)
        started_at = datetime.now(tz=UTC)
        loop = asyncio.get_running_loop()
        clock_start = loop.time()

        async def run_one(name: str) -> None:
            async with semaphore:
                try:
                    results[name] = await operation(name)
                except MispFleetError as error:
                    errors[name] = server_error_from(name, error)
                    logger.warning("server %s failed: %s", name, error.message)
                    if options.failure_policy is FailurePolicy.FAIL_FAST:
                        raise

        try:
            async with asyncio.TaskGroup() as group:
                for name in servers:
                    group.create_task(run_one(name))
        except* MispFleetError:
            pass
        envelope = MultiServerResult[T](
            operation_id=uuid4(),
            started_at=started_at,
            completed_at=datetime.now(tz=UTC),
            duration_ms=(loop.time() - clock_start) * 1000.0,
            requested_servers=list(servers),
            successful_servers=[name for name in servers if name in results],
            failed_servers=[name for name in servers if name in errors],
            results=results,
            errors=errors,
        )
        self._enforce_failure_policy(envelope, options.failure_policy)
        return envelope

    def _enforce_failure_policy[T](
        self,
        envelope: MultiServerResult[T],
        policy: FailurePolicy,
    ) -> None:
        failed = envelope.failed_servers
        if not failed:
            return
        if policy in (FailurePolicy.FAIL_FAST, FailurePolicy.REQUIRE_ALL):
            raise PartialFleetError(
                f"{len(failed)} of {len(envelope.requested_servers)} servers failed",
                failed_servers=failed,
            )
        if policy is FailurePolicy.REQUIRE_ANY and not envelope.successful_servers:
            raise PartialFleetError("every requested server failed", failed_servers=failed)
