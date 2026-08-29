"""Strict deterministic SiteRefreshResult and change-set tests."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

import pytest

from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.request.model import Budgets, ContentType, Scope
from web_listening.result.attempts import Attempt
from web_listening.result.errors import ResultValidationError, SafeError
from web_listening.result.manifest import SiteSkillEvidence, Usage
from web_listening.result.model import ResultStatus
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
    return SiteStatePage(
        url,
        "observation-" + marker * 32,
        "artifact-" + marker * 64,
        "sha256:" + (marker * 64 if digest is None else digest * 64),
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


def _attempt(
    order: int,
    url: str,
    *,
    outcome: str = "succeeded",
    code: str = "gateway.timeout",
) -> Attempt:
    return Attempt(
        order,
        f"refresh-{order}",
        outcome,
        "acquisition.web_http",
        "1.0.0",
        NOW,
        NOW,
        url,
        url if outcome == "succeeded" else None,
        200 if outcome == "succeeded" else None,
        None if outcome == "succeeded" else SafeError(code, "Acquisition failed."),
        1,
        10,
        1,
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
    attempts = tuple(
        _attempt(index, page.canonical_url) for index, page in enumerate(current.pages)
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
        site_skill_used=SiteSkillEvidence("1", SKILL_SHA),
        site_skill_update=None,
        attempts=attempts,
        usage=Usage(4, 40, 4, 4),
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
    attempts = (
        _attempt(0, current_page.canonical_url),
        _attempt(1, failed_page.canonical_url, outcome="failed"),
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
                (attempts[1].attempt_id,),
                ("gateway.timeout",),
            ),
        ),
        unresolved=(),
        previous_state=previous,
        current_state=current,
        site_skill_used=SiteSkillEvidence("1", SKILL_SHA),
        site_skill_update=None,
        attempts=attempts,
        usage=Usage(2, 20, 2, 2),
        stop_reason="acquisition_failed",
        errors=(SafeError("gateway.timeout", "Acquisition failed."),),
    )


def test_site_refresh_result_is_byte_stable_and_strictly_round_trips() -> None:
    result = _completed()

    rebuilt = SiteRefreshResult.from_dict(json.loads(result.canonical_json_bytes()))

    assert rebuilt == result
    assert rebuilt.canonical_json_bytes() == result.canonical_json_bytes()
    assert [item.url for item in rebuilt.added] == ["https://example.test/new"]
    assert [item.url for item in rebuilt.changed] == ["https://example.test/b"]
    assert [item.url for item in rebuilt.unchanged] == [
        "https://example.test/a",
        "https://example.test/c",
    ]


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
    payload = json.loads(
        (FIXTURES / "site-refresh-completed.v1.json").read_text(encoding="utf-8")
    )
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
            usage=Usage(3, 30, 3, 3),
        )


def test_current_state_rejects_reused_previous_observation() -> None:
    payload = json.loads(
        (FIXTURES / "site-refresh-completed.v1.json").read_text(encoding="utf-8")
    )
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
    ("name", "factory"),
    [
        ("site-refresh-completed.v1.json", _completed),
        ("site-refresh-partial.v1.json", _partial),
    ],
)
def test_frozen_site_refresh_fixtures(name: str, factory) -> None:
    expected = factory()
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    assert SiteRefreshResult.from_dict(payload) == expected


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
