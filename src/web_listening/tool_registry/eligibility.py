"""Deterministic minimum eligibility checks for registered metadata."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from dataclasses import dataclass

from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolManifest,
    ToolRegistryError,
    capability_is_valid,
)


def _nonnegative_int(value: int) -> bool:
    return type(value) is int and value >= 0


@dataclass(frozen=True, slots=True)
class EligibilityRequirements:
    """Only the facts needed for basic exclusion, never ranking."""

    category: ToolCategory
    capabilities: frozenset[str] = frozenset()
    input_bytes: int = 0
    output_bytes: int = 0
    runtime_seconds: int = 0

    def __post_init__(self) -> None:
        metadata_valid = (
            type(self.category) is ToolCategory and type(self.capabilities) is frozenset
        )
        capabilities_valid = metadata_valid and all(
            type(value) is str and capability_is_valid(value)
            for value in self.capabilities
        )
        limits_valid = all(
            _nonnegative_int(value)
            for value in (self.input_bytes, self.output_bytes, self.runtime_seconds)
        )
        if not capabilities_valid or not limits_valid:
            raise ToolRegistryError("eligibility.requirements_invalid")


@dataclass(frozen=True, slots=True)
class EligibilityDecision:
    """One observable eligibility result in deterministic reason order."""

    tool_id: str
    eligible: bool
    reasons: tuple[str, ...]


def evaluate_eligibility(
    manifest: ToolManifest, requirements: EligibilityRequirements
) -> EligibilityDecision:
    """Evaluate hard exclusions only; do not rank or choose a fallback."""
    requirements = _rebuild_requirements(requirements)
    if type(manifest) is not ToolManifest:
        raise ToolRegistryError("eligibility.requirements_invalid")
    reasons: list[str] = []
    if manifest.category is not requirements.category:
        reasons.append("eligibility.category_mismatch")
    if manifest.health is not HealthStatus.HEALTHY:
        reasons.append("eligibility.unhealthy")
    if manifest.qualification is not QualificationStatus.QUALIFIED:
        reasons.append("eligibility.unqualified")
    for capability in sorted(requirements.capabilities - manifest.capabilities):
        reasons.append(f"eligibility.capability_missing:{capability}")
    if requirements.input_bytes > manifest.limits.max_input_bytes:
        reasons.append("eligibility.input_limit")
    if requirements.output_bytes > manifest.limits.max_output_bytes:
        reasons.append("eligibility.output_limit")
    if requirements.runtime_seconds > manifest.limits.max_runtime_seconds:
        reasons.append("eligibility.runtime_limit")
    return EligibilityDecision(
        tool_id=manifest.tool_id,
        eligible=not reasons,
        reasons=tuple(reasons),
    )


def _rebuild_requirements(value: object) -> EligibilityRequirements:
    rebuilt = _contained_requirements(value)
    if rebuilt is None:
        raise ToolRegistryError("eligibility.requirements_invalid")
    return rebuilt


def _contained_requirements(value: object) -> EligibilityRequirements | None:
    try:
        if type(value) is not EligibilityRequirements:
            return None
        if type(value.category) is not ToolCategory:
            return None
        if type(value.capabilities) is not frozenset or any(
            type(item) is not str for item in value.capabilities
        ):
            return None
        limits = (value.input_bytes, value.output_bytes, value.runtime_seconds)
        if any(type(item) is not int for item in limits):
            return None
        return EligibilityRequirements(
            value.category,
            value.capabilities,
            value.input_bytes,
            value.output_bytes,
            value.runtime_seconds,
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return None
