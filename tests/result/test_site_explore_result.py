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
from web_listening.result.model import Result
from web_listening.result.site_explore import (
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


def _target_result(run_id: str, url: str, marker: str) -> Result:
    payload = json.loads((FIXTURES / "completed.v1.json").read_text(encoding="utf-8"))
    payload["site_skill_used"] = None
    manifest = payload["manifest"]
    manifest["run_id"] = run_id
    manifest["requested_url"] = url
    manifest["current_url"] = url
    manifest["final_url"] = url
    manifest["redirects"] = []
    manifest["site_skill"] = None
    attempt = payload["attempts"][0]
    attempt["attempt_id"] = run_id
    attempt["requested_url"] = url
    attempt["final_url"] = url
    manifest["attempts"] = [dict(attempt)]
    for artifact in payload["artifacts"]:
        artifact["observation_id"] = "observation-" + marker * 32
        artifact["source_url"] = url
    manifest["artifacts"] = [dict(item) for item in payload["artifacts"]]
    return Result.from_dict(payload)


def _discovery_attempt() -> Attempt:
    return Attempt(
        order=1,
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
    seed = _target_result("explore-seed", "https://example.test/", "1")
    acquired = _target_result("explore-candidate-1", "https://example.test/a", "2")
    source_artifacts = tuple(item.artifacts[0] for item in (seed, acquired))
    state = SiteState(
        "example.test",
        NOW,
        candidate.digest,
        True,
        tuple(
            SiteStatePage(
                artifact.source_url,
                artifact.observation_id,
                artifact.artifact_id,
                f"sha256:{artifact.sha256}",
            )
            for artifact in source_artifacts
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
    attempts = (
        replace(seed.attempts[0], order=0),
        _discovery_attempt(),
        replace(acquired.attempts[0], order=2),
    )
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
        target_results=(seed, acquired),
        attempts=attempts,
        usage=Usage(4, 124, 260, 3),
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

    assert "target_results" in result.to_dict()

    rebuilt = site_explore_result_from_mapping(
        json.loads(result.canonical_json_bytes())
    )

    assert rebuilt == result
    assert rebuilt.canonical_json_bytes() == result.canonical_json_bytes()
    assert rebuilt.schema_version == "web-listening-site-explore.v3"
    assert rebuilt.discovery[0].coverage == "complete"


@pytest.mark.parametrize("case", ("omitted", "duplicate", "reordered", "forged"))
def test_target_results_reject_omission_duplicate_reordering_and_forgery(
    case: str,
) -> None:
    result = _completed()
    seed, candidate = result.target_results
    if case == "omitted":
        targets = (seed,)
    elif case == "duplicate":
        targets = (seed, candidate, candidate)
    elif case == "reordered":
        targets = (candidate, seed)
    else:
        targets = (
            seed,
            replace(
                candidate,
                manifest=replace(
                    candidate.manifest,
                    run_id="explore-candidate-2",
                ),
            ),
        )

    with pytest.raises(ResultValidationError, match="site_explore.target_results"):
        replace(result, target_results=targets)


def test_target_results_are_required_by_the_strict_payload() -> None:
    payload = _completed().to_dict()
    payload.pop("target_results")

    with pytest.raises(ResultValidationError, match="schema.missing_fields"):
        site_explore_result_from_mapping(payload)


def test_target_result_roundtrip_preserves_html_markdown_lineage() -> None:
    payload = json.loads((FIXTURES / "partial.v1.json").read_text(encoding="utf-8"))
    payload["site_skill_used"] = None
    payload["manifest"]["site_skill"] = None
    payload["manifest"]["run_id"] = "lineage-seed"
    for index, attempt in enumerate(payload["attempts"]):
        attempt["attempt_id"] = (
            "lineage-seed" if index == 0 else f"lineage-seed-acquisition-{index}"
        )
    payload["manifest"]["attempts"] = [dict(item) for item in payload["attempts"]]
    target = Result.from_dict(payload)
    source = next(item for item in target.artifacts if item.role == "source")
    result = SiteExploreResult(
        status="partial",
        exploration_complete=False,
        site_state=SiteState(
            "www.casact.org",
            NOW,
            None,
            False,
            (
                SiteStatePage(
                    source.source_url,
                    source.observation_id,
                    source.artifact_id,
                    f"sha256:{source.sha256}",
                ),
            ),
        ),
        site_skill_candidate=None,
        site_skill_used=None,
        discovery=(),
        target_results=(target,),
        attempts=target.attempts,
        usage=target.usage,
        stop_reason="acquisition_failed",
        errors=target.errors,
    )

    rebuilt = site_explore_result_from_mapping(result.to_dict())
    derived = next(
        item for item in rebuilt.target_results[0].artifacts if item.role == "derived"
    )

    assert derived.mime_type == "text/markdown"
    assert len(derived.lineage) == 1
    assert derived.lineage[0].source_artifact_id == source.artifact_id


@pytest.mark.parametrize("coverage", ("complete", "truncated", "unknown"))
def test_site_explore_v3_discovery_coverage_strictly_round_trips(
    coverage: str,
) -> None:
    result = _completed(coverage)

    rebuilt = site_explore_result_from_mapping(result.to_dict())

    assert rebuilt.discovery[0].coverage == coverage


@pytest.mark.parametrize("coverage", (None, "", "partial", True, 1))
def test_site_explore_v3_rejects_missing_or_invalid_discovery_coverage(
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
        errors=(
            SafeError(
                "runtime.site_identity_mismatch",
                "Candidate was rejected.",
            ),
        ),
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
    payload = _partial().to_dict()
    payload["stop_reason"] = "acquisition_failed"
    payload["errors"] = [
        SafeError(
            "eligibility.attempt_budget_exhausted",
            "Acquisition did not complete.",
        ).to_dict()
    ]

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


def test_discovery_budget_error_requires_budget_exhausted_stop_reason() -> None:
    payload = _partial().to_dict()
    payload["stop_reason"] = "acquisition_failed"
    payload["errors"] = [
        SafeError("budget.runtime", "Discovery did not complete.").to_dict()
    ]

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


def test_budget_exhausted_stop_reason_requires_partial_status() -> None:
    payload = _partial().to_dict()
    payload["status"] = "failed"

    with pytest.raises(
        ResultValidationError, match="site_explore.stop_reason_inconsistent"
    ):
        site_explore_result_from_mapping(payload)


def test_discovery_evidence_requires_one_matching_local_attempt() -> None:
    result = _completed()
    acquisitions = tuple(
        replace(attempt, order=index)
        for index, attempt in enumerate(
            attempt for target in result.target_results for attempt in target.attempts
        )
    )

    with pytest.raises(
        ResultValidationError, match="site_explore.discovery_evidence_mismatch"
    ):
        replace(
            result,
            attempts=acquisitions,
            usage=Usage(4, 124, 260, 2),
        )


def test_duplicate_discovery_identity_is_rejected() -> None:
    result = _completed()

    with pytest.raises(ResultValidationError, match="site_explore.discovery_duplicate"):
        replace(result, discovery=result.discovery + result.discovery)


def test_frozen_discovery_provenance_must_match_invocation_source() -> None:
    payload = _completed().to_dict()
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
    payload = _partial().to_dict()
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
    "name",
    [
        "site-explore-completed.v1.json",
        "site-explore-partial.v1.json",
        "site-explore-completed.v2.json",
        "site-explore-partial.v2.json",
    ],
)
def test_legacy_site_explore_payload_without_target_results_is_rejected(
    name: str,
) -> None:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    with pytest.raises(ResultValidationError):
        site_explore_result_from_mapping(payload)


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
