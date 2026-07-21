"""Policy lookup and evaluation entry point."""

from __future__ import annotations

from mispfleet.exceptions import PolicyConfigurationError
from mispfleet.models.event import MISPEvent
from mispfleet.policies.base import PolicyContext, PolicyResult, PolicySpec
from mispfleet.policies.builtins import DISTRIBUTION_LEVELS, ConfigPolicy


class PolicyEngine:
    """Resolves policy names to implementations and evaluates them."""

    def __init__(self, specs: dict[str, PolicySpec]) -> None:
        self._specs = dict(specs)

    def names(self) -> list[str]:
        """All configured policy names."""
        return sorted(self._specs)

    def get(self, name: str) -> ConfigPolicy:
        """Return the policy registered under ``name``."""
        spec = self._specs.get(name)
        if spec is None:
            raise PolicyConfigurationError(f"unknown policy {name!r}")
        self.validate_spec(name, spec)
        return ConfigPolicy(name, spec)

    def validate_spec(self, name: str, spec: PolicySpec) -> None:
        """Reject specs referencing unknown distribution levels."""
        if (
            spec.maximum_distribution is not None
            and spec.maximum_distribution not in DISTRIBUTION_LEVELS
        ):
            raise PolicyConfigurationError(
                f"policy {name!r}: unknown distribution level "
                f"{spec.maximum_distribution!r}; expected one of "
                f"{sorted(DISTRIBUTION_LEVELS)}"
            )

    async def apply(
        self,
        name: str | None,
        context: PolicyContext,
        event: MISPEvent,
    ) -> PolicyResult:
        """Evaluate the named policy, or accept the event untouched."""
        if name is None:
            return PolicyResult(accepted=True, transformed_event=event.model_copy(deep=True))
        return await self.get(name).evaluate(context, event)
