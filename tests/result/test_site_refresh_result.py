"""Strict deterministic SiteRefreshResult and change-set tests."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

import pytest

from web_listening.artifact.identity import artifact_id
from web_listening.artifact.model import ArtifactRole
from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.request.model import Budgets, ContentType, Scope
from web_listening.result.attempts import Attempt
from web_listening.result.errors import ResultValidationError, SafeError
from web_listening.result.manifest import SiteSkillEvidence, Usage
from web_listening.result.model import Result, ResultStatus
from web_listening.result.site_explore import SiteSkillCandidateEvidence
from web_listening.result.site_refresh import (
    ChangeEvidence,
    SiteChange,
    SiteRefreshResult,
    SiteSkillUpdate,
)
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import site_skill_to_mapping
from web_listening.tool_registry.manifest import ToolCategory

NOW = "2026-08-28T00:00:00Z"
FIXTURES = Path(__file__).with_name("fixtures")
SKILL_SHA = "e" * 64


def _page(url: str, marker: str, digest: str | None = None) -> SiteStatePage:
    content_sha = marker * 64 if digest is None else digest * 64
    return SiteStatePage(
        url,
        "observation-" + marker * 32,
        artifact_id(content_sha, "text/html", ArtifactRole.SOURCE),
        "sha256:" + content_sha,
    )


def _state(*pages: SiteStatePage, complete: bool = True) -> SiteState:
    return SiteState(
        "example.test",
        NOW,
        "sha256:" + SKILL_SHA,
        complete,
        tuple(sorted(pages, key=lambda page: page.canonical_url)),
    )


def _evidence(page: SiteStatePage) -> ChangeEvidence:
    return ChangeEvidence(page.artifact_id, page.content_digest)


def _success_target(
    run_id: str, page: SiteStatePage, skill: SiteSkillEvidence
) -> Result:
    payload = json.loads((FIXTURES / "completed.v1.json").read_text(encoding="utf-8"))
    payload["site_skill_used"] = skill.to_dict()
    manifest = payload["manifest"]
    manifest["run_id"] = run_id
    manifest["requested_url"] = page.canonical_url
    manifest["current_url"] = page.canonical_url
    manifest["final_url"] = page.canonical_url
    manifest["redirects"] = []
    manifest["site_skill"] = skill.to_dict()
    attempt = payload["attempts"][0]
    attempt["attempt_id"] = run_id
    attempt["requested_url"] = page.canonical_url
    attempt["final_url"] = page.canonical_url
    manifest["attempts"] = [dict(attempt)]
    for artifact in payload["artifacts"]:
        artifact["artifact_id"] = page.artifact_id
        artifact["observation_id"] = page.observation_id
        artifact["source_url"] = page.canonical_url
        artifact["sha256"] = page.content_digest.removeprefix("sha256:")
    manifest["mime_type"] = "text/html"
    manifest["sha256"] = page.content_digest.removeprefix("sha256:")
    manifest["artifacts"] = [dict(item) for item in payload["artifacts"]]
    return Result.from_dict(payload)


def _failed_target(run_id: str, url: str, skill: SiteSkillEvidence) -> Result:
    payload = json.loads((FIXTURES / "failed.v1.json").read_text(encoding="utf-8"))
    payload["site_skill_used"] = skill.to_dict()
    manifest = payload["manifest"]
    manifest["run_id"] = run_id
    manifest["requested_url"] = url
    manifest["current_url"] = url
    manifest["site_skill"] = skill.to_dict()
    attempt = payload["attempts"][0]
    attempt["attempt_id"] = run_id
    attempt["requested_url"] = url
    manifest["attempts"] = [dict(attempt)]
    return Result.from_dict(payload)


def _discovery_attempt() -> Attempt:
    return Attempt(
        1,
        "refresh-discovery",
        "succeeded",
        "discovery.html_links",
        "1.0.0",
        NOW,
        NOW,
        "https://example.test/a",
        None,
        None,
        None,
        0,
        0,
        0,
    )


def _completed() -> SiteRefreshResult:
    previous = _state(
        _page("https://example.test/a", "a"),
        _page("https://example.test/b", "b"),
        _page("https://example.test/c", "c"),
        _page("https://example.test/missing", "d"),
    )
    current = _state(
        _page("https://example.test/a", "1", "a"),
        _page("https://example.test/b", "2", "f"),
        _page("https://example.test/c", "3", "c"),
        _page("https://example.test/new", "4"),
    )
    previous_by_url = {page.canonical_url: page for page in previous.pages}
    current_by_url = {page.canonical_url: page for page in current.pages}
    skill_evidence = SiteSkillEvidence("1", SKILL_SHA)
    target_results = tuple(
        _success_target(
            "refresh-source" if index == 0 else f"refresh-candidate-{index}",
            page,
            skill_evidence,
        )
        for index, page in enumerate(current.pages)
    )
    attempts = (
        replace(target_results[0].attempts[0], order=0),
        _discovery_attempt(),
        *(
            replace(target.attempts[0], order=index + 1)
            for index, target in enumerate(target_results[1:], start=1)
        ),
    )
    return SiteRefreshResult(
        status=ResultStatus.COMPLETED,
        refresh_complete=True,
        added=(
            SiteChange(
                "https://example.test/new",
                "added",
                None,
                _evidence(current_by_url["https://example.test/new"]),
            ),
        ),
        changed=(
            SiteChange(
                "https://example.test/b",
                "changed",
                _evidence(previous_by_url["https://example.test/b"]),
                _evidence(current_by_url["https://example.test/b"]),
            ),
        ),
        unchanged=tuple(
            SiteChange(
                url,
                "unchanged",
                _evidence(previous_by_url[url]),
                _evidence(current_by_url[url]),
            )
            for url in ("https://example.test/a", "https://example.test/c")
        ),
        missing=(
            SiteChange(
                "https://example.test/missing",
                "missing",
                _evidence(previous_by_url["https://example.test/missing"]),
                None,
            ),
        ),
        failed=(),
        unresolved=(),
        previous_state=previous,
        current_state=current,
        site_skill_used=skill_evidence,
        site_skill_update=None,
        target_results=target_results,
        attempts=attempts,
        usage=Usage(8, 248, 520, 5),
        stop_reason="source_exhausted",
        errors=(),
    )


def _partial() -> SiteRefreshResult:
    previous = _state(
        _page("https://example.test/a", "a"),
        _page("https://example.test/b", "b"),
    )
    current_page = _page("https://example.test/a", "1", "a")
    current = _state(current_page, complete=False)
    failed_page = previous.pages[1]
    skill_evidence = SiteSkillEvidence("1", SKILL_SHA)
    succeeded = _success_target("refresh-source", current_page, skill_evidence)
    failed_target = _failed_target(
        "refresh-candidate-1", failed_page.canonical_url, skill_evidence
    )
    attempts = (
        replace(succeeded.attempts[0], order=0),
        _discovery_attempt(),
        replace(failed_target.attempts[0], order=2),
    )
    return SiteRefreshResult(
        status=ResultStatus.PARTIAL,
        refresh_complete=False,
        added=(),
        changed=(),
        unchanged=(
            SiteChange(
                current_page.canonical_url,
                "unchanged",
                _evidence(previous.pages[0]),
                _evidence(current_page),
            ),
        ),
        missing=(),
        failed=(
            SiteChange(
                failed_page.canonical_url,
                "failed",
                _evidence(failed_page),
                None,
                (attempts[2].attempt_id,),
                ("gateway.timeout",),
            ),
        ),
        unresolved=(),
        previous_state=previous,
        current_state=current,
        site_skill_used=skill_evidence,
        site_skill_update=None,
        target_results=(succeeded, failed_target),
        attempts=attempts,
        usage=Usage(3, 62, 1080, 3),
        stop_reason="acquisition_failed",
        errors=failed_target.errors,
    )


def test_site_refresh_result_is_byte_stable_and_strictly_round_trips() -> None:
    result = _completed()

    assert "target_results" in result.to_dict()

    rebuilt = SiteRefreshResult.from_dict(json.loads(result.canonical_json_bytes()))

    assert rebuilt == result
    assert rebuilt.canonical_json_bytes() == result.canonical_json_bytes()
    assert [item.url for item in rebuilt.added] == ["https://example.test/new"]
    assert [item.url for item in rebuilt.changed] == ["https://example.test/b"]
    assert [item.url for item in rebuilt.unchanged] == [
        "https://example.test/a",
        "https://example.test/c",
    ]
    assert rebuilt.schema_version == "web-listening-site-refresh.v2"


@pytest.mark.parametrize("case", ("omitted", "duplicate", "reordered", "forged"))
def test_target_results_reject_omission_duplicate_reordering_and_forgery(
    case: str,
) -> None:
    result = _completed()
    source, *candidates = result.target_results
    if case == "omitted":
        targets = (source, *candidates[:-1])
    elif case == "duplicate":
        targets = (*result.target_results, candidates[-1])
    elif case == "reordered":
        targets = (source, candidates[1], candidates[0], *candidates[2:])
    else:
        first = candidates[0]
        targets = (
            source,
            replace(
                first,
                manifest=replace(first.manifest, run_id="refresh-candidate-9"),
            ),
            *candidates[1:],
        )

    with pytest.raises(ResultValidationError, match="site_refresh.target_results"):
        replace(result, target_results=targets)


def test_target_results_are_required_by_the_strict_payload() -> None:
    payload = _completed().to_dict()
    payload.pop("target_results")

    with pytest.raises(ResultValidationError, match="schema.missing_fields"):
        SiteRefreshResult.from_dict(payload)


def test_failed_target_result_keeps_manifest_error_without_artifact() -> None:
    result = _partial()
    failed = result.target_results[-1]

    assert failed.status is ResultStatus.FAILED
    assert failed.manifest.run_id == "refresh-candidate-1"
    assert failed.manifest.requested_url == result.failed[0].url
    assert failed.artifacts == failed.manifest.artifacts == ()
    assert failed.errors[0].code == "gateway.timeout"
    assert SiteRefreshResult.from_dict(result.to_dict()) == result


def test_target_result_errors_are_reconciled_as_a_multiset() -> None:
    result = _partial()
    failed = result.target_results[-1]
    error = failed.errors[0]
    duplicated_error_result = replace(failed, errors=(error, error))
    with_duplicate_errors = replace(
        result,
        target_results=(result.target_results[0], duplicated_error_result),
        errors=(error, error),
    )

    with pytest.raises(
        ResultValidationError, match="site_refresh.target_results_mismatch"
    ):
        replace(with_duplicate_errors, errors=(error,))


def test_discovery_attempt_error_must_be_preserved_in_aggregate() -> None:
    result = _partial()
    discovery_error = SafeError(
        "runtime.discovery_recipe_unavailable", "Discovery recipe unavailable."
    )
    discovery = replace(result.attempts[1], outcome="failed", error=discovery_error)
    with_discovery_error = replace(
        result,
        attempts=(result.attempts[0], discovery, result.attempts[2]),
        errors=(*result.errors, discovery_error),
    )

    with pytest.raises(
        ResultValidationError, match="site_refresh.target_results_mismatch"
    ):
        replace(with_discovery_error, errors=result.errors)


def test_result_rejects_overlapping_or_duplicate_urls() -> None:
    result = _completed()

    with pytest.raises(ResultValidationError, match="site_refresh.change_overlap"):
        replace(result, changed=result.changed + result.changed)


def test_result_rejects_change_evidence_that_disagrees_with_state() -> None:
    result = _completed()
    wrong = replace(
        result.changed[0],
        current=replace(result.changed[0].current, digest="sha256:" + "0" * 64),
    )

    with pytest.raises(ResultValidationError, match="site_refresh.evidence_mismatch"):
        replace(result, changed=(wrong,))


def test_incomplete_refresh_forbids_authoritative_missing() -> None:
    result = _partial()
    previous = result.previous_state.pages[1]

    with pytest.raises(ResultValidationError, match="site_refresh.missing_forbidden"):
        replace(
            result,
            missing=(
                SiteChange(
                    previous.canonical_url,
                    "missing",
                    _evidence(previous),
                    None,
                ),
            ),
            failed=(),
        )


def test_completed_fixture_forbids_unresolved_history() -> None:
    payload = _completed().to_dict()
    unresolved = payload["missing"].pop()
    unresolved["change_type"] = "unresolved"
    payload["unresolved"] = [unresolved]

    with pytest.raises(
        ResultValidationError, match="site_refresh.unresolved_forbidden"
    ):
        SiteRefreshResult.from_dict(payload)


def test_failed_change_requires_matching_attempt_and_safe_error() -> None:
    result = _partial()
    failed = replace(result.failed[0], attempt_ids=("unknown-attempt",))

    with pytest.raises(ResultValidationError, match="site_refresh.failed_evidence"):
        replace(result, failed=(failed,))


def test_current_state_pages_require_this_refresh_success_attempt() -> None:
    result = _completed()
    attempts = result.attempts[:-1]

    with pytest.raises(
        ResultValidationError, match="site_refresh.current_state_evidence"
    ):
        replace(
            result,
            attempts=attempts,
            usage=Usage(6, 186, 390, 4),
        )


def test_current_state_rejects_reused_previous_observation() -> None:
    payload = _completed().to_dict()
    payload["current_state"]["pages"][0]["observation_id"] = payload["previous_state"][
        "pages"
    ][0]["observation_id"]

    with pytest.raises(ResultValidationError, match="site_refresh.observation_reused"):
        SiteRefreshResult.from_dict(payload)


def test_usage_must_equal_attempt_evidence() -> None:
    with pytest.raises(ResultValidationError, match="usage.requests_mismatch"):
        replace(_completed(), usage=Usage(99, 40, 4, 4))


def test_site_skill_update_is_an_inactive_validated_candidate() -> None:
    scope = Scope(
        ("https://example.test/",),
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )
    acquisition = ToolReference(
        "acquisition.web_http",
        "1.0.0",
        ToolCategory.ACQUISITION,
        frozenset({"http_get"}),
    )
    discovery = DiscoveryRecipe(
        ToolReference(
            "discovery.html_links",
            "1.0.0",
            ToolCategory.DISCOVERY,
            frozenset({"html_links"}),
        ),
        "https://example.test/",
    )
    active = create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=scope,
        budgets=Budgets(4, 4096, 30, 4),
        tool=acquisition,
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=discovery,
    ).skill
    candidate = create_candidate(
        site_key="example.test",
        version=2,
        previous=active,
        scope=scope,
        budgets=active.budgets,
        tool=replace(acquisition, tool_id="acquisition.alternate"),
        success_checks=active.success_checks,
        verified_at=NOW,
        discovery=discovery,
    ).skill
    evidence = SiteSkillCandidateEvidence.from_validated_mapping(
        site_skill_to_mapping(candidate),
        digest=candidate.digest,
        discovery_key=(
            discovery.tool.tool_id,
            discovery.tool.version,
            discovery.source_url,
        ),
    )
    update = SiteSkillUpdate(
        "preferred_tool_changed",
        SiteSkillEvidence(str(active.version), active.digest.removeprefix("sha256:")),
        evidence,
    )

    assert update.candidate.digest == candidate.digest
    assert update.to_dict()["candidate"]["previous_digest"] == active.digest
    assert SiteSkillUpdate.from_dict(update.to_dict(), candidate=evidence) == update
    with pytest.raises(
        ResultValidationError, match="site_refresh.skill_update_invalid"
    ):
        SiteSkillUpdate.from_dict(update.to_dict())


@pytest.mark.parametrize(
    "name",
    ("site-refresh-completed.v1.json", "site-refresh-partial.v1.json"),
)
def test_legacy_site_refresh_payload_without_target_results_is_rejected(
    name: str,
) -> None:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    with pytest.raises(ResultValidationError):
        SiteRefreshResult.from_dict(payload)


def test_unknown_result_or_change_fields_are_rejected() -> None:
    payload = _completed().to_dict()
    payload["unknown"] = True
    with pytest.raises(ResultValidationError, match="schema.unknown_fields"):
        SiteRefreshResult.from_dict(payload)


@pytest.mark.parametrize(
    "url",
    (
        "https://example.test/?token=private",
        "https://example.test/?%2574oken=private",
    ),
)
def test_change_urls_reject_secret_bearing_query_evidence(url: str) -> None:
    with pytest.raises(ResultValidationError, match="result.sensitive_data"):
        SiteChange(
            url,
            "failed",
            None,
            None,
            ("refresh-1",),
            ("gateway.timeout",),
        )

    payload = _completed().to_dict()
    added = payload["added"]
    assert isinstance(added, list) and isinstance(added[0], dict)
    added[0]["unknown"] = True
    with pytest.raises(ResultValidationError, match="schema.unknown_fields"):
        SiteRefreshResult.from_dict(payload)


def test_site_change_accepts_public_natural_language_slug_roundtrip() -> None:
    public_url = (
        "https://www.ipcc.ch/2026/06/25/"
        "keynote-address-ipcc-chair-jim-skea-world-climate-investment-summit/"
    )
    change = SiteChange(
        public_url,
        "failed",
        None,
        None,
        ("refresh-1",),
        ("gateway.timeout",),
    )

    assert SiteChange.from_dict(change.to_dict()) == change


@pytest.mark.parametrize(
    "change_type", ("added", "changed", "unchanged", "missing", "failed", "unresolved")
)
def test_change_url_absolute_path_keeps_frozen_result_error(
    change_type: str,
) -> None:
    encoded = quote("".join(chr(item) for item in (67, 58, 47, 112)), safe="")
    url = f"https://example.test/a?next={encoded}"

    with pytest.raises(ResultValidationError, match="^result.absolute_path$"):
        SiteChange(
            url,
            change_type,
            None,
            None,
        )

    with pytest.raises(ResultValidationError, match="^result.absolute_path$"):
        SiteChange.from_dict(
            {
                "url": url,
                "change_type": change_type,
                "previous": None,
                "current": None,
                "attempt_ids": [],
                "error_codes": [],
            }
        )
