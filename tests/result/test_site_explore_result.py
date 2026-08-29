"""Strict SiteExploreResult v2 contract and v1 migration tests."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.request.model import Budgets, ContentType, Scope
from web_listening.result.attempts import Attempt
from web_listening.result.errors import ResultValidationError, SafeError
from web_listening.result.manifest import Usage
from web_listening.result.site_explore import (
    SITE_EXPLORE_SCHEMA_VERSION,
    DiscoveryEvidence,
    SiteExploreResult,
    SiteSkillCandidateEvidence,
)
from web_listening.runtime.site_explore import site_explore_result_from_mapping
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import site_skill_to_mapping
from web_listening.tool_registry.manifest import ToolCategory

NOW = "2026-08-28T00:00:00Z"
FIXTURES = Path(__file__).parent / "fixtures"


def _candidate():
    scope = Scope(
        ("https://example.test/",),
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )
    return create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=scope,
        budgets=Budgets(4, 4096, 30, 1),
        tool=ToolReference(
            "acquisition.web_http",
            "1.0.0",
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=DiscoveryRecipe(
            ToolReference(
                "discovery.html_links",
                "1.0.0",
                ToolCategory.DISCOVERY,
                frozenset({"html_links"}),
            ),
            "https://example.test/",
        ),
    ).skill


def _attempt(order: int = 1) -> Attempt:
    return Attempt(
        order=order,
        attempt_id="explore-candidate-1",
        outcome="succeeded",
        tool_id="acquisition.web_http",
        tool_version="1.0.0",
        started_at=NOW,
        finished_at=NOW,
        requested_url="https://example.test/a",
        final_url="https://example.test/a",
        http_status=200,
        error=None,
        requests=1,
        bytes_received=5,
        runtime_ms=1,
    )


def _discovery_attempt() -> Attempt:
    return Attempt(
        order=0,
        attempt_id="explore-discovery-1",
        outcome="succeeded",
        tool_id="discovery.html_links",
        tool_version="1.0.0",
        started_at=NOW,
        finished_at=NOW,
        requested_url="https://example.test/",
        final_url=None,
        http_status=None,
        error=None,
        requests=0,
        bytes_received=0,
        runtime_ms=0,
    )


def _completed(coverage: str = "complete") -> SiteExploreResult:
    candidate = _candidate()
    discovery_recipe = candidate.discovery
    assert discovery_recipe is not None
    state = SiteState(
        "example.test",
        NOW,
        candidate.digest,
        True,
        (
            SiteStatePage(
                "https://example.test/a",
                "observation-" + "a" * 32,
                "artifact-" + "b" * 64,
                "sha256:" + "c" * 64,
            ),
        ),
    )
    discovery = DiscoveryEvidence(
        "discovery.html_links",
        "1.0.0",
        "https://example.test/",
        "succeeded",
        ("https://example.test/a",),
        ("https://example.test/",),
        coverage,
        None,
    )
    attempt = _attempt()
    return SiteExploreResult(
        status="completed",
        exploration_complete=True,
        site_state=state,
        site_skill_candidate=SiteSkillCandidateEvidence.from_validated_mapping(
            site_skill_to_mapping(candidate),
            digest=candidate.digest,
            discovery_key=(
                discovery_recipe.tool.tool_id,
                discovery_recipe.tool.version,
                discovery_recipe.source_url,
            ),
        ),
        site_skill_used=None,
        discovery=(discovery,),
        attempts=(_discovery_attempt(), attempt),
        usage=Usage(1, 5, 1, 2),
        stop_reason="source_exhausted",
        errors=(),
    )


def _partial(coverage: str = "complete") -> SiteExploreResult:
    result = _completed(coverage)
    return replace(
        result,
        status="partial",
        exploration_complete=False,
        site_state=replace(result.site_state, site_skill_digest=None, complete=False),
        site_skill_candidate=None,
        stop_reason="budget_exhausted",
        errors=(SafeError("budget.exhausted", "Exploration budget was exhausted."),),
    )


def test_site_explore_result_is_byte_stable_and_strictly_round_trips() -> None:
    result = _completed()

    rebuilt = site_explore_result_from_mapping(
        json.loads(result.canonical_json_bytes())
    )

    assert rebuilt == result
    assert rebuilt.canonical_json_bytes() == result.canonical_json_bytes()
    assert rebuilt.schema_version == "web-listening-site-explore.v2"
    assert rebuilt.discovery[0].coverage == "complete"


@pytest.mark.parametrize("coverage", ("complete", "truncated", "unknown"))
def test_site_explore_v2_discovery_coverage_strictly_round_trips(
    coverage: str,
) -> None:
    result = _completed(coverage)

    rebuilt = site_explore_result_from_mapping(result.to_dict())

    assert rebuilt.discovery[0].coverage == coverage


@pytest.mark.parametrize("coverage", (None, "", "partial", True, 1))
def test_site_explore_v2_rejects_missing_or_invalid_discovery_coverage(
    coverage: object,
) -> None:
    payload = _completed().to_dict()
    if coverage is None:
        payload["discovery"][0].pop("coverage")
    else:
        payload["discovery"][0]["coverage"] = coverage

    with pytest.raises(ResultValidationError):
        site_explore_result_from_mapping(payload)


def test_candidate_evidence_rejects_malformed_bytes_with_stable_error() -> None:
    with pytest.raises(ResultValidationError, match="site_explore.candidate_invalid"):
        SiteSkillCandidateEvidence(
            b"{",
            "sha256:" + "a" * 64,
            (
                "discovery.html_links",
                "1.0.0",
                "https://example.test/",
            ),
        )


def test_completed_result_requires_complete_state_and_verified_candidate() -> None:
    result = _completed()

    with pytest.raises(ResultValidationError, match="site_explore.completed_invalid"):
        replace(result, site_skill_candidate=None)
    with pytest.raises(ResultValidationError, match="site_explore.state_mismatch"):
        replace(result, site_state=replace(result.site_state, complete=False))


def test_partial_result_cannot_claim_candidate_or_completion() -> None:
    result = _completed()
    partial = _partial()

    assert SiteExploreResult.from_dict(partial.to_dict()) == partial
    with pytest.raises(ResultValidationError, match="site_explore.candidate_forbidden"):
        replace(partial, site_skill_candidate=result.site_skill_candidate)


def test_terminal_partial_result_can_have_complete_state_without_candidate() -> None:
    partial = _partial()

    completed_state = replace(
        partial,
        exploration_complete=True,
        site_state=replace(partial.site_state, complete=True),
        stop_reason="acquisition_failed",
        errors=(SafeError("scope.origin_not_allowed", "Candidate was rejected."),),
    )

    assert completed_state.exploration_complete is True
    assert completed_state.site_skill_candidate is None


@pytest.mark.parametrize(
    "code",
    (
        "budget.exhausted",
        "budget.requests",
        "budget.bytes",
        "budget.runtime",
        "eligibility.request_budget_exhausted",
        "eligibility.byte_budget_exhausted",
        "eligibility.runtime_budget_exhausted",
        "eligibility.attempt_budget_exhausted",
    ),
)
def test_budget_error_requires_budget_exhausted_stop_reason(code: str) -> None:
    partial = _partial()

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        replace(
            partial,
            stop_reason="acquisition_failed",
            errors=(SafeError(code, "Exploration budget was exhausted."),),
        )


def test_attempt_budget_error_requires_budget_exhausted_stop_reason() -> None:
    payload = json.loads(
        (FIXTURES / "site-explore-partial.v1.json").read_text(encoding="utf-8")
    )
    payload["stop_reason"] = "acquisition_failed"
    payload["errors"] = [
        SafeError("gateway.timeout", "Acquisition did not complete.").to_dict()
    ]
    payload["site_state"]["pages"] = []
    attempt = payload["attempts"][1]
    attempt["outcome"] = "failed"
    attempt["final_url"] = None
    attempt["http_status"] = None
    attempt["error"] = SafeError(
        "budget.requests", "Acquisition did not complete."
    ).to_dict()

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


def test_discovery_budget_error_requires_budget_exhausted_stop_reason() -> None:
    payload = json.loads(
        (FIXTURES / "site-explore-partial.v1.json").read_text(encoding="utf-8")
    )
    payload["stop_reason"] = "acquisition_failed"
    payload["errors"] = [
        SafeError("gateway.timeout", "Acquisition did not complete.").to_dict()
    ]
    error = SafeError("budget.runtime", "Discovery did not complete.").to_dict()
    discovery = payload["discovery"][0]
    discovery["outcome"] = "failed"
    discovery["candidates"] = []
    discovery["discovered_from"] = []
    discovery["error"] = error
    attempt = payload["attempts"][0]
    attempt["outcome"] = "failed"
    attempt["error"] = error

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


def test_budget_exhausted_stop_reason_requires_partial_status() -> None:
    payload = json.loads(
        (FIXTURES / "site-explore-partial.v1.json").read_text(encoding="utf-8")
    )
    payload["status"] = "failed"

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


def test_discovery_evidence_requires_one_matching_local_attempt() -> None:
    result = _completed()
    acquisition = replace(result.attempts[1], order=0)

    with pytest.raises(
        ResultValidationError, match="site_explore.discovery_evidence_mismatch"
    ):
        replace(
            result,
            attempts=(acquisition,),
            usage=Usage(1, 5, 1, 1),
        )


def test_duplicate_discovery_identity_is_rejected() -> None:
    result = _completed()

    with pytest.raises(ResultValidationError, match="site_explore.discovery_duplicate"):
        replace(result, discovery=result.discovery + result.discovery)


def test_frozen_discovery_provenance_must_match_invocation_source() -> None:
    payload = json.loads(
        (FIXTURES / "site-explore-completed.v1.json").read_text(encoding="utf-8")
    )
    payload["discovery"][0]["discovered_from"] = ["https://unrelated.test/"]

    with pytest.raises(ResultValidationError, match="site_explore.discovery_invalid"):
        site_explore_result_from_mapping(payload)


@pytest.mark.parametrize(
    "case",
    (
        "source_exhausted_without_completion",
        "cancelled_without_evidence",
        "budget_exhausted_with_complete_state",
        "discovery_failed_without_evidence",
        "rejected_stop_with_partial_status",
        "rejected_status_without_rejected_stop",
    ),
)
def test_stop_reason_conflicts_in_frozen_partial_payload_are_rejected(
    case: str,
) -> None:
    payload = json.loads(
        (FIXTURES / "site-explore-partial.v1.json").read_text(encoding="utf-8")
    )
    if case == "source_exhausted_without_completion":
        payload["stop_reason"] = "source_exhausted"
    elif case == "cancelled_without_evidence":
        payload["stop_reason"] = "cancelled"
    elif case == "budget_exhausted_with_complete_state":
        payload["exploration_complete"] = True
        payload["site_state"]["complete"] = True
    elif case == "discovery_failed_without_evidence":
        payload["stop_reason"] = "discovery_failed"
    elif case == "rejected_stop_with_partial_status":
        payload["stop_reason"] = "rejected"
    else:
        payload["status"] = "rejected"
        payload["stop_reason"] = "acquisition_failed"

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("site-explore-completed.v2.json", _completed),
        ("site-explore-partial.v2.json", _partial),
    ],
)
def test_frozen_site_explore_v2_fixtures(name: str, expected) -> None:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    result = site_explore_result_from_mapping(payload)

    assert result == expected()
    assert result.canonical_json_bytes() == expected().canonical_json_bytes()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("site-explore-completed.v1.json", _completed),
        ("site-explore-partial.v1.json", _partial),
    ],
)
def test_frozen_site_explore_v1_migrates_coverage_to_unknown(
    name: str, expected
) -> None:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    result = site_explore_result_from_mapping(payload)

    assert result == expected("unknown")
    assert result.schema_version == SITE_EXPLORE_SCHEMA_VERSION
    assert result.discovery[0].coverage == "unknown"


def test_unknown_result_or_discovery_fields_are_rejected() -> None:
    payload = _completed().to_dict()
    payload["private"] = "not allowed"
    with pytest.raises(ResultValidationError, match="schema.unknown_fields"):
        site_explore_result_from_mapping(payload)

    payload = _completed().to_dict()
    payload["discovery"][0]["private"] = True
    with pytest.raises(ResultValidationError, match="schema.unknown_fields"):
        site_explore_result_from_mapping(payload)


def test_candidate_mapping_is_parsed_by_authoritative_site_skill_validator() -> None:
    payload = _completed().to_dict()
    candidate = payload["site_skill_candidate"]
    assert isinstance(candidate, dict)
    scope = candidate["scope"]
    assert isinstance(scope, dict)
    scope["allowed_origins"] = ["https://outside.test"]
    unsigned = dict(candidate)
    unsigned.pop("digest")
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    candidate["digest"] = f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    with pytest.raises(SiteSkillError, match="scope.origin_not_allowed"):
        site_explore_result_from_mapping(payload)
