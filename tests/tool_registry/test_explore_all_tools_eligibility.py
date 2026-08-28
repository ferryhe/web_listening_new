"""Focused tests for controlled Acquisition eligibility and ranking."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-arguments

from __future__ import annotations

import inspect
from itertools import permutations

import pytest

import web_listening.tool_registry.eligibility as eligibility_module
from web_listening.tool_registry.eligibility import (
    EligibilityFacts,
    EligibilityRequirements,
    rank_eligible_tools,
)
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)


def _manifest(
    tool_id: str,
    *,
    capabilities: frozenset[str] = frozenset({"html"}),
    health: HealthStatus = HealthStatus.HEALTHY,
    qualification: QualificationStatus = QualificationStatus.QUALIFIED,
    limits: ToolLimits = ToolLimits(30, 4096, 4096),
) -> ToolManifest:
    return ToolManifest(
        tool_id,
        "1.0.0",
        ToolCategory.ACQUISITION,
        ToolDistribution.INSTALLED,
        capabilities,
        limits,
        health,
        qualification,
    )


def _facts(
    manifests: tuple[ToolManifest, ...],
    *,
    installed: frozenset[str] | None = None,
    compliant: frozenset[str] | None = None,
    requests: int = 4,
    bytes_remaining: int = 4096,
    runtime_ms: int = 30_000,
    attempts: int = 4,
) -> EligibilityFacts:
    tool_ids = frozenset(manifest.tool_id for manifest in manifests)
    return EligibilityFacts(
        installed_tool_ids=tool_ids if installed is None else installed,
        policy_compliant_tool_ids=tool_ids if compliant is None else compliant,
        remaining_requests=requests,
        remaining_bytes=bytes_remaining,
        remaining_runtime_ms=runtime_ms,
        remaining_tool_attempts=attempts,
    )


def _decision_map(selection):
    return {decision.tool_id: decision for decision in selection.decisions}


def test_selection_is_the_explicit_eligible_intersection_with_stable_reasons() -> None:
    eligible = _manifest("acquisition.eligible")
    disabled = _manifest("acquisition.disabled")
    unhealthy = _manifest("acquisition.unhealthy", health=HealthStatus.UNHEALTHY)
    unqualified = _manifest(
        "acquisition.unqualified",
        qualification=QualificationStatus.UNQUALIFIED,
    )
    incompatible = _manifest(
        "acquisition.incompatible", capabilities=frozenset({"browser"})
    )
    policy_blocked = _manifest("acquisition.policy-blocked")
    manifests = (
        policy_blocked,
        incompatible,
        eligible,
        unqualified,
        disabled,
        unhealthy,
    )

    selection = rank_eligible_tools(
        manifests,
        EligibilityRequirements(
            ToolCategory.ACQUISITION,
            capabilities=frozenset({"html"}),
            output_bytes=1024,
            runtime_seconds=10,
        ),
        _facts(
            manifests,
            installed=frozenset(
                manifest.tool_id for manifest in manifests if manifest is not disabled
            ),
            compliant=frozenset(
                manifest.tool_id
                for manifest in manifests
                if manifest is not policy_blocked
            ),
        ),
        preferred_tool_id=eligible.tool_id,
        include_alternates=True,
    )

    decisions = _decision_map(selection)
    assert selection.ranked == (eligible,)
    assert tuple(decision.tool_id for decision in selection.skipped) == (
        "acquisition.disabled",
        "acquisition.incompatible",
        "acquisition.policy-blocked",
        "acquisition.unhealthy",
        "acquisition.unqualified",
    )
    assert decisions[eligible.tool_id].reasons == ()
    assert decisions[eligible.tool_id].checks == (
        "eligibility.registered",
        "eligibility.installed",
        "eligibility.qualified",
        "eligibility.healthy",
        "eligibility.capability_compatible",
        "eligibility.policy_compliant",
        "eligibility.within_budget",
    )
    assert decisions[disabled.tool_id].reasons == ("eligibility.not_installed",)
    assert decisions[unqualified.tool_id].reasons == ("eligibility.unqualified",)
    assert decisions[unhealthy.tool_id].reasons == ("eligibility.unhealthy",)
    assert decisions[incompatible.tool_id].reasons == (
        "eligibility.capability_missing:html",
    )
    assert decisions[policy_blocked.tool_id].reasons == (
        "eligibility.policy_noncompliant",
    )


@pytest.mark.parametrize(
    ("remaining", "expected"),
    [
        ({"requests": 0}, "eligibility.request_budget_exhausted"),
        ({"bytes_remaining": 0}, "eligibility.byte_budget_exhausted"),
        ({"runtime_ms": 0}, "eligibility.runtime_budget_exhausted"),
        ({"attempts": 0}, "eligibility.attempt_budget_exhausted"),
    ],
)
def test_exhausted_request_budget_excludes_every_tool(
    remaining: dict[str, int], expected: str
) -> None:
    manifest = _manifest("acquisition.only")
    manifests = (manifest,)

    selection = rank_eligible_tools(
        manifests,
        EligibilityRequirements(ToolCategory.ACQUISITION),
        _facts(manifests, **remaining),
        preferred_tool_id=manifest.tool_id,
        include_alternates=True,
    )

    assert not selection.ranked
    assert selection.skipped[0].reasons == (expected,)
    assert "eligibility.within_budget" not in selection.skipped[0].checks


def test_minimum_rank_is_independent_of_registration_order() -> None:
    preferred = _manifest("acquisition.preferred")
    alpha = _manifest("acquisition.alpha")
    zulu = _manifest("acquisition.zulu")
    expected = (preferred.tool_id, alpha.tool_id, zulu.tool_id)

    for order in permutations((zulu, preferred, alpha)):
        selection = rank_eligible_tools(
            order,
            EligibilityRequirements(ToolCategory.ACQUISITION),
            _facts(order),
            preferred_tool_id=preferred.tool_id,
            include_alternates=True,
        )
        assert tuple(manifest.tool_id for manifest in selection.ranked) == expected
        after_preferred = rank_eligible_tools(
            order,
            EligibilityRequirements(ToolCategory.ACQUISITION),
            _facts(order),
            preferred_tool_id=preferred.tool_id,
            include_alternates=True,
            attempted_tool_ids=frozenset({preferred.tool_id}),
        )
        assert tuple(manifest.tool_id for manifest in after_preferred.ranked) == (
            alpha.tool_id,
            zulu.tool_id,
        )


def test_exploration_disabled_returns_only_the_preferred_tool_without_fake_skips() -> (
    None
):
    preferred = _manifest("acquisition.preferred")
    alternate = _manifest("acquisition.alternate")
    manifests = (alternate, preferred)

    selection = rank_eligible_tools(
        manifests,
        EligibilityRequirements(ToolCategory.ACQUISITION),
        _facts(manifests),
        preferred_tool_id=preferred.tool_id,
        include_alternates=False,
    )

    assert selection.ranked == (preferred,)
    assert not selection.skipped


def test_eligibility_module_is_pure_metadata_selection_without_tool_execution() -> None:
    source = inspect.getsource(eligibility_module).casefold()

    assert "registry.invoke" not in source
    assert ".acquire(" not in source
    assert "fallback_order" not in source
    assert "playwright" not in source
    assert "cloakbrowser" not in source
