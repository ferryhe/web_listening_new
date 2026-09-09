"""Deterministic minimum eligibility checks for registered metadata."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from dataclasses import dataclass, replace

from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolManifest,
    ToolRegistryError,
    capability_is_valid,
    validate_tool_id,
)

DEFAULT_ACQUISITION_ORDER = (
    "acquisition.web_http",
    "acquisition.playwright",
    "acquisition.cloakbrowser",
)


def _rank_key(manifest: ToolManifest) -> tuple[int, str, str]:
    order = DEFAULT_ACQUISITION_ORDER
    rank = order.index(manifest.tool_id) if manifest.tool_id in order else len(order)
    return rank, manifest.tool_id, manifest.version


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
class EligibilityFacts:
    """Request-bound facts not carried by immutable tool metadata."""

    installed_tool_ids: frozenset[str]
    policy_compliant_tool_ids: frozenset[str]
    remaining_requests: int
    remaining_bytes: int
    remaining_runtime_ms: int
    remaining_tool_attempts: int

    def __post_init__(self) -> None:
        identifiers = (self.installed_tool_ids, self.policy_compliant_tool_ids)
        valid_sets = all(type(values) is frozenset for values in identifiers)
        try:
            valid_ids = valid_sets and all(
                type(tool_id) is str and validate_tool_id(tool_id)
                for values in identifiers
                for tool_id in values
            )
        except ToolRegistryError:
            valid_ids = False
        limits = (
            self.remaining_requests,
            self.remaining_bytes,
            self.remaining_runtime_ms,
            self.remaining_tool_attempts,
        )
        if not valid_ids or not all(_nonnegative_int(value) for value in limits):
            raise ToolRegistryError("eligibility.facts_invalid")


@dataclass(frozen=True, slots=True)
class EligibilityDecision:
    """One observable eligibility result in deterministic reason order."""

    tool_id: str
    tool_version: str
    eligible: bool
    reasons: tuple[str, ...]
    checks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EligibilitySelection:
    """Complete decisions plus the minimum deterministic eligible ranking."""

    decisions: tuple[EligibilityDecision, ...]
    ranked: tuple[ToolManifest, ...]
    skipped: tuple[EligibilityDecision, ...]
    budget_exhausted: bool


def evaluate_eligibility(  # pylint: disable=too-many-branches
    manifest: ToolManifest,
    requirements: EligibilityRequirements,
    facts: EligibilityFacts | None = None,
) -> EligibilityDecision:
    """Evaluate the explicit registered-and-usable intersection for one tool."""
    requirements = _rebuild_requirements(requirements)
    if type(manifest) is not ToolManifest:
        raise ToolRegistryError("eligibility.requirements_invalid")
    if facts is not None:
        facts = _rebuild_facts(facts)
    reasons: list[str] = []
    if manifest.category is not requirements.category:
        reasons.append("eligibility.category_mismatch")
    installed = facts is None or manifest.tool_id in facts.installed_tool_ids
    if not installed:
        reasons.append("eligibility.not_installed")
    if manifest.health is not HealthStatus.HEALTHY:
        reasons.append("eligibility.unhealthy")
    if manifest.qualification is not QualificationStatus.QUALIFIED:
        reasons.append("eligibility.unqualified")
    missing_capabilities = requirements.capabilities - manifest.capabilities
    for capability in sorted(missing_capabilities):
        reasons.append(f"eligibility.capability_missing:{capability}")
    policy_compliant = (
        facts is None or manifest.tool_id in facts.policy_compliant_tool_ids
    )
    if not policy_compliant:
        reasons.append("eligibility.policy_noncompliant")
    limit_reasons: list[str] = []
    if requirements.input_bytes > manifest.limits.max_input_bytes:
        limit_reasons.append("eligibility.input_limit")
    if requirements.output_bytes > manifest.limits.max_output_bytes:
        limit_reasons.append("eligibility.output_limit")
    if requirements.runtime_seconds > manifest.limits.max_runtime_seconds:
        limit_reasons.append("eligibility.runtime_limit")
    reasons.extend(limit_reasons)
    budget_reasons = [] if facts is None else list(_budget_reasons(facts))
    reasons.extend(budget_reasons)
    checks = ["eligibility.registered"]
    if installed:
        checks.append("eligibility.installed")
    if manifest.qualification is QualificationStatus.QUALIFIED:
        checks.append("eligibility.qualified")
    if manifest.health is HealthStatus.HEALTHY:
        checks.append("eligibility.healthy")
    if manifest.category is requirements.category and not missing_capabilities:
        checks.append("eligibility.capability_compatible")
    if policy_compliant:
        checks.append("eligibility.policy_compliant")
    if not limit_reasons and not budget_reasons:
        checks.append("eligibility.within_budget")
    return EligibilityDecision(
        tool_id=manifest.tool_id,
        tool_version=manifest.version,
        eligible=not reasons,
        reasons=tuple(reasons),
        checks=tuple(checks),
    )


def rank_eligible_tools(  # pylint: disable=too-many-arguments,too-many-locals
    manifests: tuple[ToolManifest, ...],
    requirements: EligibilityRequirements,
    facts: EligibilityFacts,
    *,
    preferred_tool_id: str,
    include_alternates: bool,
    attempted_tool_ids: frozenset[str] = frozenset(),
    catalog_decisions: tuple[EligibilityDecision, ...] = (),
) -> EligibilitySelection:
    """Own the default Acquisition order, subject to eligibility and preference."""
    requirements = _rebuild_requirements(requirements)
    facts = _rebuild_facts(facts)
    if (
        type(manifests) is not tuple
        or any(type(manifest) is not ToolManifest for manifest in manifests)
        or type(preferred_tool_id) is not str
        or type(include_alternates) is not bool
        or type(attempted_tool_ids) is not frozenset
    ):
        raise ToolRegistryError("eligibility.selection_invalid")
    try:
        validate_tool_id(preferred_tool_id)
        for tool_id in attempted_tool_ids:
            if type(tool_id) is not str:
                raise ToolRegistryError("eligibility.selection_invalid")
            validate_tool_id(tool_id)
    except ToolRegistryError as exc:
        raise ToolRegistryError("eligibility.selection_invalid") from exc
    ordered = tuple(sorted(manifests, key=_rank_key))
    if len({manifest.tool_id for manifest in ordered}) != len(ordered):
        raise ToolRegistryError("eligibility.selection_invalid")
    remaining = tuple(
        manifest for manifest in ordered if manifest.tool_id not in attempted_tool_ids
    )
    if not include_alternates:
        remaining = tuple(
            manifest for manifest in remaining if manifest.tool_id == preferred_tool_id
        )
    decisions = tuple(
        evaluate_eligibility(manifest, requirements, facts) for manifest in remaining
    )
    exclusions = {item.tool_id: item for item in catalog_decisions if not item.eligible}
    decisions = tuple(
        (
            replace(
                item,
                eligible=False,
                reasons=tuple(
                    dict.fromkeys(exclusions[item.tool_id].reasons + item.reasons)
                ),
            )
            if item.tool_id in exclusions
            else item
        )
        for item in decisions
    )
    if include_alternates and requirements.category is ToolCategory.ACQUISITION:
        known_ids = {item.tool_id for item in decisions} | attempted_tool_ids
        decisions += tuple(
            item
            for item in catalog_decisions
            if not item.eligible
            and item.tool_id not in known_ids
            and item.tool_id in DEFAULT_ACQUISITION_ORDER
        )
    eligible_by_id = {decision.tool_id: decision.eligible for decision in decisions}
    eligible = tuple(
        manifest for manifest in remaining if eligible_by_id[manifest.tool_id]
    )
    preferred = tuple(
        manifest for manifest in eligible if manifest.tool_id == preferred_tool_id
    )
    if preferred_tool_id not in attempted_tool_ids and not preferred:
        ranked: tuple[ToolManifest, ...] = ()
    else:
        ranked = preferred + tuple(
            manifest for manifest in eligible if manifest.tool_id != preferred_tool_id
        )
    return EligibilitySelection(
        decisions=decisions,
        ranked=ranked,
        skipped=(
            ()
            if not include_alternates
            else tuple(decision for decision in decisions if not decision.eligible)
        ),
        budget_exhausted=bool(_budget_reasons(facts)),
    )


def _budget_reasons(facts: EligibilityFacts) -> tuple[str, ...]:
    return tuple(
        reason
        for exhausted, reason in (
            (facts.remaining_requests == 0, "eligibility.request_budget_exhausted"),
            (facts.remaining_bytes == 0, "eligibility.byte_budget_exhausted"),
            (
                facts.remaining_runtime_ms < 1_000,
                "eligibility.runtime_budget_exhausted",
            ),
            (
                facts.remaining_tool_attempts == 0,
                "eligibility.attempt_budget_exhausted",
            ),
        )
        if exhausted
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


def _rebuild_facts(value: object) -> EligibilityFacts:
    try:
        if type(value) is not EligibilityFacts:
            raise ToolRegistryError("eligibility.facts_invalid")
        identifiers = (value.installed_tool_ids, value.policy_compliant_tool_ids)
        if any(type(items) is not frozenset for items in identifiers) or any(
            type(item) is not str for items in identifiers for item in items
        ):
            raise ToolRegistryError("eligibility.facts_invalid")
        limits = (
            value.remaining_requests,
            value.remaining_bytes,
            value.remaining_runtime_ms,
            value.remaining_tool_attempts,
        )
        if any(type(item) is not int for item in limits):
            raise ToolRegistryError("eligibility.facts_invalid")
        return EligibilityFacts(*identifiers, *limits)
    except ToolRegistryError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        raise ToolRegistryError("eligibility.facts_invalid") from exc


_CONTINUABLE_ACQUISITION_FAILURES = frozenset(
    {
        "gateway.closed",
        "gateway.body_incomplete",
        "gateway.dns",
        "gateway.mime_invalid",
        "gateway.mime_missing",
        "gateway.timeout",
        "gateway.tls",
        "gateway.transport",
        "gateway.server_error",
        "runner.timeout",
        "web_http.failure",
        "browser.resource_failed",
        "browser.navigation_failed",
        "browser.navigation_timeout",
    }
)
_CONTINUABLE_QUALITY_FAILURES = frozenset(
    {
        "runtime.quality_mime_mismatch",
        "runtime.quality_minimum_words",
        "acquisition.empty",
        "acquisition.script_only",
        "acquisition.challenge",
        "acquisition.error_page",
    }
)


def acquisition_failure_is_operational(code: str) -> bool:
    """Separate broken execution infrastructure from expected target failures."""
    if code == "runner.timeout":
        return False
    if code.startswith(("runner.", "isolated_runtime.", "lifecycle.", "registry.")):
        return True
    if code.startswith("runtime."):
        return code not in _CONTINUABLE_QUALITY_FAILURES
    if code.startswith("browser."):
        return code not in {
            "browser.resource_failed",
            "browser.navigation_failed",
            "browser.navigation_timeout",
            "browser.html_required",
        }
    return False


def acquisition_failure_allows_switch(code: str, tool_id: str | None = None) -> bool:
    """Return whether a stable technical or quality failure permits switching."""
    if type(code) is not str:
        return False
    if acquisition_failure_is_operational(code):
        return False
    if code == "acquisition.cloudflare_blocked":
        return tool_id == "acquisition.web_http"
    return code in (_CONTINUABLE_ACQUISITION_FAILURES | _CONTINUABLE_QUALITY_FAILURES)


__all__ = [
    "EligibilityDecision",
    "EligibilityFacts",
    "EligibilityRequirements",
    "EligibilitySelection",
    "acquisition_failure_allows_switch",
    "acquisition_failure_is_operational",
    "evaluate_eligibility",
    "rank_eligible_tools",
]


def acquisition_followup_candidates(manifests, code, tool_id):
    """HTTP Cloudflare authorizes only an eligible ordinary browser follow-up."""
    if code == "acquisition.cloudflare_blocked" and tool_id == "acquisition.web_http":
        return tuple(m for m in manifests if m.tool_id == "acquisition.playwright")
    return manifests
