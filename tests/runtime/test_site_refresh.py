"""Deterministic governed incremental site-refresh orchestration tests."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-lines
# pylint: disable=too-few-public-methods

from __future__ import annotations

import hashlib
import json
from asyncio import CancelledError
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

import pytest

from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.result.model import ResultStatus
from web_listening.runtime.site_refresh import (
    run_site_refresh,
    site_refresh_result_from_mapping,
)
from web_listening.runtime.workflow import (
    prior_target_attempts,
    run_single_target_bounded,
)
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_FILE_LINKS_MANIFEST,
    HTML_LINKS_MANIFEST,
    HtmlFileLinksDiscoveryTool,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.discovery.builtins.rss import RSS_MANIFEST
from web_listening.tool_registry.discovery.builtins.sitemap import SITEMAP_MANIFEST
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryFailure,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import TransformInput
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

NOW = "2026-08-28T00:00:00Z"
ROOT = "https://example.test/"
ACQUISITION_MANIFEST = ToolManifest(
    "acquisition.web_http",
    "1.0.0",
    ToolCategory.ACQUISITION,
    ToolDistribution.BUILTIN,
    frozenset({"http_get"}),
    ToolLimits(30, 16384, 16384),
    HealthStatus.HEALTHY,
    QualificationStatus.QUALIFIED,
)


@dataclass
class _Acquisition:  # pylint: disable=too-many-instance-attributes
    outcomes: dict[str, bytes | AcquisitionFailure | list[bytes | AcquisitionFailure]]
    manifest: ToolManifest = ACQUISITION_MANIFEST
    final_urls: dict[str, str] | None = None
    requests_by_url: dict[str, int] | None = None
    bytes_by_url: dict[str, int] | None = None
    runtime_ms_by_url: dict[str, int] | None = None
    mime_types_by_url: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self.targets: list[str] = []
        self.budgets: list[Budgets] = []

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.targets.append(tool_input.target_url)
        self.budgets.append(tool_input.request.budgets)
        outcome = self.outcomes[tool_input.target_url]
        if isinstance(outcome, list):
            outcome = outcome.pop(0)
        if isinstance(outcome, AcquisitionFailure):
            return outcome
        final_url = (self.final_urls or {}).get(
            tool_input.target_url, tool_input.target_url
        )
        redirects = (
            ()
            if final_url == tool_input.target_url
            else (AcquisitionRedirect(tool_input.target_url, final_url, 302),)
        )
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            final_url,
            200,
            (self.mime_types_by_url or {}).get(tool_input.target_url, "text/html"),
            outcome,
            hashlib.sha256(outcome).hexdigest(),
            redirects,
            (self.runtime_ms_by_url or {}).get(tool_input.target_url, 1),
            (self.requests_by_url or {}).get(tool_input.target_url, len(redirects) + 1),
            (self.bytes_by_url or {}).get(tool_input.target_url, len(outcome)),
        )


@dataclass
class _DiscoverySpy:
    manifest: ToolManifest = HTML_LINKS_MANIFEST

    def __post_init__(self) -> None:
        self.calls = 0
        self._tool = HtmlLinksDiscoveryTool()

    def discover(self, tool_input):
        self.calls += 1
        return self._tool.discover(tool_input)


@dataclass
class _StaticDiscoverySpy:
    candidates: tuple[str, ...]
    manifest: ToolManifest
    coverage: DiscoveryCoverage = DiscoveryCoverage.COMPLETE

    def __post_init__(self) -> None:
        self.calls = 0
        self.inputs = []

    def discover(self, tool_input) -> DiscoveryOutput:
        self.calls += 1
        self.inputs.append(tool_input)
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            self.candidates,
            (tool_input.source_url,) * len(self.candidates),
            self.coverage,
        )


@dataclass
class _FailingDiscovery:
    manifest: ToolManifest
    code: str = "registry.tool_exception"

    def discover(self, _tool_input) -> DiscoveryFailure:
        return DiscoveryFailure(
            self.manifest.tool_id,
            self.manifest.version,
            self.code,
        )


@dataclass
class _CancellingDiscovery:
    manifest: ToolManifest = HTML_LINKS_MANIFEST

    def __post_init__(self) -> None:
        self.calls = 0

    def discover(self, _tool_input):
        self.calls += 1
        raise CancelledError


class _CancellingTransform:
    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    def __init__(self) -> None:
        self.calls = 0

    def transform(self, _tool_input: TransformInput):
        self.calls += 1
        raise CancelledError


class _TransformSpy:
    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    def __init__(self) -> None:
        self.calls = 0
        self._tool = SimpleHtmlMarkdownTransform()

    def transform(self, tool_input: TransformInput):
        self.calls += 1
        return self._tool.transform(tool_input)


def _scope(seed: str = ROOT) -> Scope:
    return Scope(
        (seed,),
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )


def _skill(
    budgets: Budgets,
    *,
    discovery_manifest: ToolManifest = HTML_LINKS_MANIFEST,
    discovery_source_url: str | None = None,
    scope: Scope | None = None,
    success_mime_types: tuple[str, ...] = ("text/html",),
):
    selected_scope = scope or _scope()
    return create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=selected_scope,
        budgets=budgets,
        tool=ToolReference(
            ACQUISITION_MANIFEST.tool_id,
            ACQUISITION_MANIFEST.version,
            ACQUISITION_MANIFEST.category,
            ACQUISITION_MANIFEST.capabilities,
        ),
        success_checks=SuccessChecks(success_mime_types, 1),
        verified_at=NOW,
        discovery=DiscoveryRecipe(
            ToolReference(
                discovery_manifest.tool_id,
                discovery_manifest.version,
                discovery_manifest.category,
                discovery_manifest.capabilities,
            ),
            discovery_source_url or selected_scope.seeds[0],
        ),
    ).skill


def _previous(skill, bodies: dict[str, bytes]) -> SiteState:
    markers = "abcdef0123456789"
    pages = tuple(
        SiteStatePage(
            url,
            "observation-" + markers[index] * 32,
            "artifact-" + markers[index] * 64,
            "sha256:" + hashlib.sha256(body).hexdigest(),
        )
        for index, (url, body) in enumerate(sorted(bodies.items()))
    )
    return SiteState("example.test", NOW, skill.digest, True, pages)


def _request(
    skill,
    previous: SiteState,
    *,
    explore_all_tools: bool = False,
    budgets: Budgets | None = None,
) -> SiteRefreshRequest:
    limits = budgets or skill.budgets
    return SiteRefreshRequest(skill.scope, skill, previous, explore_all_tools, limits)


def _normal_bodies() -> tuple[dict[str, bytes], dict[str, bytes]]:
    root = b"<a href='/a'>a</a><a href='/b'>b</a><a href='/c'>c</a><a href='/d'>d</a>"
    previous = {
        ROOT: root,
        "https://example.test/a": b"page a",
        "https://example.test/b": b"page b old",
        "https://example.test/c": b"page c",
    }
    current = {
        ROOT: root,
        "https://example.test/a": b"page a",
        "https://example.test/b": b"page b new",
        "https://example.test/c": b"page c",
        "https://example.test/d": b"page d",
    }
    return previous, current


def _encoded_absolute_path_url() -> str:
    encoded = quote("".join(chr(item) for item in (67, 58, 47, 112)), safe="")
    return f"https://example.test/a?next={encoded}"


def _encoded_explicit_token_url() -> str:
    prefix = "".join(chr(item) for item in (0xFF53, 0xFF4B, 0xFF0D))
    encoded = quote(prefix + "x" * 16, safe="")
    return f"https://example.test/evidence/{encoded}"


def test_sensitive_previous_state_is_rejected_before_any_runtime_io(
    tmp_path: Path,
) -> None:
    root = b"<a href='/a'>a</a>"
    candidate = "https://example.test/a"
    limits = Budgets(4, 16384, 30, 4)
    skill = _skill(limits)
    request = _request(skill, _previous(skill, {ROOT: root, candidate: b"old a"}))
    object.__setattr__(
        request.previous_state.pages[1],
        "canonical_url",
        "https://example.test/a?token=placeholder-value",
    )
    acquisition = _Acquisition({ROOT: root, candidate: b"new a"})
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    with pytest.raises(
        RequestValidationError, match="^site_state.sensitive_data$"
    ) as caught:
        run_site_refresh(
            request,
            registry,
            store,
            run_id="refresh",
            clock=lambda: NOW,
        )

    assert not acquisition.targets
    assert discovery.calls == 0
    assert "placeholder-value" not in str(caught.value)
    store.close()


@pytest.mark.parametrize(
    ("unsafe_url", "expected_code"),
    (
        (_encoded_absolute_path_url(), "site_state.absolute_path"),
        (_encoded_explicit_token_url(), "site_state.sensitive_data"),
    ),
    ids=("absolute-path", "explicit-token"),
)
# pylint: disable-next=too-many-locals
def test_unsafe_previous_state_is_rejected_before_all_runtime_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_url: str,
    expected_code: str,
) -> None:
    root = b"<a href='/a'>a</a>"
    candidate = "https://example.test/a"
    limits = Budgets(4, 16384, 30, 4)
    skill = _skill(limits)
    request = _request(skill, _previous(skill, {ROOT: root, candidate: b"old a"}))
    object.__setattr__(
        request.previous_state.pages[1],
        "canonical_url",
        unsafe_url,
    )
    acquisition = _Acquisition({ROOT: root, candidate: b"new a"})
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)
    calls = {"clock": 0, "registry": 0, "artifact_store": 0}

    def counted_clock() -> str:
        calls["clock"] += 1
        return NOW

    for method_name in ("query", "eligibility", "eligible", "invoke"):
        original = getattr(registry, method_name)

        def counted_registry(*args, _original=original, **kwargs):
            calls["registry"] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(registry, method_name, counted_registry)
    for method_name in ("commit_observation", "read_artifact"):
        original = getattr(store, method_name)

        def counted_store(*args, _original=original, **kwargs):
            calls["artifact_store"] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(store, method_name, counted_store)

    try:
        with pytest.raises(
            RequestValidationError, match=f"^{expected_code}$"
        ) as caught:
            run_site_refresh(
                request,
                registry,
                store,
                run_id="refresh",
                clock=counted_clock,
            )

        assert caught.value.args == (expected_code,)
        assert calls == {"clock": 0, "registry": 0, "artifact_store": 0}
        assert not acquisition.targets
        assert discovery.calls == 0
    finally:
        store.close()


def test_public_natural_language_slug_refreshes_as_current_evidence(
    tmp_path: Path,
) -> None:
    public_url = (
        "https://example.test/"
        "skilled-professionals-and-scientists-in-climate-assessment"
    )
    root = (
        b"<a href='/skilled-professionals-and-scientists-in-climate-assessment'>p</a>"
    )
    limits = Budgets(4, 16384, 30, 4)
    skill = _skill(limits)
    previous = _previous(skill, {ROOT: root, public_url: b"public page"})
    acquisition = _Acquisition({ROOT: root, public_url: b"public page"})
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(skill, previous),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.refresh_complete is True
    assert [change.url for change in result.unchanged] == [ROOT, public_url]
    assert acquisition.targets == [ROOT, public_url]
    store.close()


def _runtime(
    tmp_path: Path,
    acquisition: _Acquisition,
    discovery: _DiscoverySpy | _StaticDiscoverySpy,
) -> tuple[Registry, ArtifactStore]:
    registry = Registry()
    registry.register(discovery.manifest, discovery)
    registry.register(acquisition.manifest, acquisition)
    return registry, ArtifactStore(tmp_path / "artifacts")


def test_normal_refresh_uses_stored_recipe_and_builds_six_exclusive_sets(
    tmp_path: Path,
) -> None:
    old, current = _normal_bodies()
    limits = Budgets(6, 16384, 30, 6)
    skill = _skill(limits)
    acquisition = _Acquisition(current)
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, old)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert [item.manifest.run_id for item in result.target_results] == [
        "refresh-source",
        "refresh-candidate-1",
        "refresh-candidate-2",
        "refresh-candidate-3",
        "refresh-candidate-4",
    ]

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.stop_reason == "source_exhausted"
    assert [item.url for item in result.added] == ["https://example.test/d"]
    assert [item.url for item in result.changed] == ["https://example.test/b"]
    assert [item.url for item in result.unchanged] == [
        ROOT,
        "https://example.test/a",
        "https://example.test/c",
    ]
    assert result.missing == result.failed == result.unresolved == ()
    assert discovery.calls == 1
    assert acquisition.targets == [ROOT, *(sorted(current)[1:])]
    assert [budget.max_requests for budget in acquisition.budgets] == [6, 5, 4, 3, 2]
    assert [budget.max_tool_attempts_per_target for budget in acquisition.budgets] == [
        6,
        6,
        6,
        6,
        6,
    ]
    assert result.usage.requests == 5
    assert result.usage.tool_attempts == 6
    previous_ids = {
        page.canonical_url: page.observation_id for page in result.previous_state.pages
    }
    assert all(
        previous_ids.get(page.canonical_url) != page.observation_id
        for page in result.current_state.pages
    )
    store.close()


def test_site_refresh_target_results_run_existing_transform_for_source_and_candidate(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    root = (
        b"<main><p>Refresh source has enough visible words for markdown.</p>"
        b"<a href='/a'>Candidate page</a></main>"
    )
    current = {
        ROOT: root,
        candidate: b"<main><p>Refresh candidate has enough visible words now.</p></main>",
    }
    limits = Budgets(2, 16384, 30, 3)
    skill = _skill(limits, success_mime_types=("application/xhtml+xml",))
    acquisition = _Acquisition(
        current,
        mime_types_by_url={
            ROOT: "application/xhtml+xml",
            candidate: "application/xhtml+xml",
        },
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())
    registry.register(
        SIMPLE_HTML_MARKDOWN_MANIFEST,
        SimpleHtmlMarkdownTransform(),
    )

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root, candidate: b"old candidate page"}),
        ),
        registry,
        store,
        run_id="refresh-transform",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert [item.manifest.run_id for item in result.target_results] == [
        "refresh-transform-source",
        "refresh-transform-candidate-1",
    ]
    for target_result in result.target_results:
        source, derived = target_result.artifacts
        assert source.role == "source"
        assert source.mime_type == "application/xhtml+xml"
        assert source.lineage == ()
        assert derived.role == "derived"
        assert derived.mime_type == "text/markdown"
        assert len(derived.lineage) == 1
        assert derived.lineage[0].relation == "derived_from"
        assert derived.lineage[0].source_artifact_id == source.artifact_id
        assert derived.lineage[0].source_observation_id == source.observation_id
        assert target_result.manifest.artifacts == target_result.artifacts
        assert target_result.manifest.attempts == target_result.attempts
        assert target_result.manifest.usage == target_result.usage
        transform_attempt = target_result.attempts[-1]
        assert transform_attempt.tool_id == SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
        assert transform_attempt.outcome == "succeeded"
        assert transform_attempt.requests == transform_attempt.bytes_received == 0
        assert transform_attempt.attempt_id.startswith(target_result.manifest.run_id)
        stored_derived = store.get_observation(derived.observation_id)
        assert stored_derived.lineage == derived.lineage
        assert stored_derived.content
    assert [item.url for item in result.changed] == [candidate]
    assert [item.url for item in result.unchanged] == [ROOT]
    assert result.added == result.missing == result.failed == result.unresolved == ()
    assert result.usage.requests == len(result.target_results)
    assert result.usage.tool_attempts == sum(
        attempt.outcome != "skipped" for attempt in result.attempts
    )
    assert {
        (page.observation_id, page.artifact_id) for page in result.current_state.pages
    } == {
        (item.artifacts[0].observation_id, item.artifacts[0].artifact_id)
        for item in result.target_results
    }
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    assert acquisition.targets == [ROOT, candidate]
    store.close()


def test_site_refresh_transform_cancellation_is_audited_without_extra_acquisition(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    root = (
        b"<main><p>Refresh source has enough visible words for markdown.</p>"
        b"<a href='/a'>Candidate page</a></main>"
    )
    current = {
        ROOT: root,
        candidate: b"<main><p>Refresh candidate has enough visible words now.</p></main>",
    }
    limits = Budgets(2, 16384, 30, 3)
    skill = _skill(limits)
    acquisition = _Acquisition(current)
    transform = _CancellingTransform()
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)

    result = run_site_refresh(
        _request(skill, _previous(skill, current)),
        registry,
        store,
        run_id="refresh-transform-cancelled",
        clock=lambda: NOW,
    )

    assert acquisition.targets == [ROOT, candidate]
    assert transform.calls == 2
    assert all(
        [artifact.role for artifact in target.artifacts] == ["source"]
        for target in result.target_results
    )
    transform_attempts = tuple(
        attempt
        for attempt in result.attempts
        if attempt.tool_id == SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
    )
    assert len(transform_attempts) == 2
    assert all(attempt.outcome == "failed" for attempt in transform_attempts)
    assert all(
        attempt.error is not None and attempt.error.code == "runtime.cancelled"
        for attempt in transform_attempts
    )
    assert all(
        attempt.requests == attempt.bytes_received == 0
        for attempt in transform_attempts
    )
    assert [item.url for item in result.unchanged] == [ROOT, candidate]
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    store.close()


# pylint: disable-next=too-many-locals
def test_site_refresh_recovery_target_results_run_existing_transform(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    root = (
        b"<main><p>Recovery source has enough visible words for markdown.</p>"
        b"<a href='/a'>Candidate page</a></main>"
    )
    current = {
        ROOT: root,
        candidate: b"<main><p>Recovery candidate has enough visible words now.</p></main>",
    }
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(5, 65536, 30, 8)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(current)
    transform = _TransformSpy()
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root, candidate: b"old candidate page"}),
        ),
        registry,
        store,
        run_id="refresh-transform-recovery",
        clock=lambda: NOW,
    )

    assert [item.manifest.run_id for item in result.target_results] == [
        "refresh-transform-recovery-source",
        "refresh-transform-recovery-recovery-seed",
        "refresh-transform-recovery-recovery-candidate-1",
    ]
    assert transform.calls == 3
    assert acquisition.targets == [ROOT, ROOT, candidate]
    assert {
        url: sum(
            attempt.outcome != "skipped" and attempt.requested_url == url
            for attempt in result.attempts
        )
        for url in (ROOT, candidate)
    } == {ROOT: 6, candidate: 2}
    assert result.target_results[-1].usage.tool_attempts == 2
    for target_result in result.target_results:
        source, derived = target_result.artifacts
        assert source.role == "source"
        assert derived.role == "derived"
        assert derived.lineage[0].source_artifact_id == source.artifact_id
        assert derived.lineage[0].source_observation_id == source.observation_id
        assert target_result.attempts[-1].tool_id == (
            SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
        )
        assert target_result.attempts[-1].attempt_id.startswith(
            target_result.manifest.run_id
        )
    current_pairs = {
        (page.observation_id, page.artifact_id) for page in result.current_state.pages
    }
    source_pairs = {
        (target.artifacts[0].observation_id, target.artifacts[0].artifact_id)
        for target in result.target_results
    }
    derived_pairs = {
        (target.artifacts[1].observation_id, target.artifacts[1].artifact_id)
        for target in result.target_results
    }
    assert len(current_pairs) == 2
    assert current_pairs.issubset(source_pairs)
    assert current_pairs.isdisjoint(derived_pairs)
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    store.close()


def test_recovery_source_prior_attempts_prevent_over_budget_transform(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    root = (
        b"<main><p>Recovery source has enough visible words for markdown.</p>"
        b"<a href='/a'>Candidate page</a></main>"
    )
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition({ROOT: root, candidate: b"candidate page"})
    transform = _TransformSpy()
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="refresh-transform-recovery-budget",
        clock=lambda: NOW,
    )

    source_attempts = tuple(
        attempt for attempt in result.attempts if attempt.requested_url == ROOT
    )
    assert transform.calls == 1
    assert acquisition.targets == [ROOT, ROOT]
    assert len(source_attempts) == 4
    assert sum(attempt.outcome != "skipped" for attempt in source_attempts) == 4
    assert result.usage.tool_attempts == 4
    assert result.usage.tool_attempts == sum(
        attempt.outcome != "skipped" for attempt in result.attempts
    )
    assert result.stop_reason == "budget_exhausted"
    assert [item.manifest.run_id for item in result.target_results] == [
        "refresh-transform-recovery-budget-source",
        "refresh-transform-recovery-budget-recovery-seed",
    ]
    assert [artifact.role for artifact in result.target_results[-1].artifacts] == [
        "source"
    ]
    assert all(
        attempt.tool_id != SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
        for attempt in result.target_results[-1].attempts
    )
    assert result.target_results[-1].usage.tool_attempts == 1
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    store.close()


def test_site_refresh_skips_transform_for_non_html_source_and_candidate(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a.xml"
    limits = Budgets(2, 16384, 30, 3)
    scope = replace(_scope(), content_types=(ContentType.FILE,))
    skill = _skill(
        limits,
        discovery_manifest=RSS_MANIFEST,
        scope=scope,
        success_mime_types=("application/xml",),
    )
    acquisition = _Acquisition(
        {ROOT: b"<root/>", candidate: b"<candidate/>"},
        mime_types_by_url={
            ROOT: "application/xml",
            candidate: "application/xml",
        },
    )
    discovery = _StaticDiscoverySpy((candidate,), RSS_MANIFEST)
    transform = _TransformSpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: b"<old/>", candidate: b"<old-candidate/>"}),
        ),
        registry,
        store,
        run_id="refresh-xml",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert transform.calls == 0
    assert acquisition.targets == [ROOT, candidate]
    assert all(
        [artifact.mime_type for artifact in target.artifacts] == ["application/xml"]
        for target in result.target_results
    )
    assert all(
        attempt.tool_id != SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
        for attempt in result.attempts
    )
    store.close()


def test_site_refresh_attempt_limit_skips_transform_after_source_acquisition(
    tmp_path: Path,
) -> None:
    root = b"<main><p>Refresh source has enough visible words for markdown.</p></main>"
    limits = Budgets(2, 16384, 30, 1)
    skill = _skill(limits)
    acquisition = _Acquisition({ROOT: root})
    transform = _TransformSpy()
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="refresh-attempt-limit",
        clock=lambda: NOW,
    )

    assert result.stop_reason == "budget_exhausted"
    assert transform.calls == 0
    assert acquisition.targets == [ROOT]
    assert len(result.target_results) == 1
    assert [artifact.role for artifact in result.target_results[0].artifacts] == [
        "source"
    ]
    assert [attempt.tool_id for attempt in result.attempts] == [
        ACQUISITION_MANIFEST.tool_id
    ]
    store.close()


def test_per_target_attempt_limit_does_not_block_a_new_canonical_page(
    tmp_path: Path,
) -> None:
    root = b"<a href='/a'>a</a>"
    current = {ROOT: root, "https://example.test/a": b"page a"}
    limits = Budgets(2, 16384, 30, 2)
    skill = _skill(limits)
    acquisition = _Acquisition(current)
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, current)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert acquisition.targets == [ROOT, "https://example.test/a"]
    assert [budget.max_tool_attempts_per_target for budget in acquisition.budgets] == [
        2,
        2,
    ]
    assert result.usage.tool_attempts == 3
    assert all(
        [artifact.role for artifact in target.artifacts] == ["source"]
        for target in result.target_results
    )
    assert all(
        attempt.tool_id != SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
        for attempt in result.attempts
    )
    store.close()


def test_allowed_cross_site_candidate_redirect_is_incomplete_and_unresolved(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    redirected = "https://mirror.test/a"
    root = b"<a href='/a'>a</a>"
    limits = Budgets(3, 16384, 30, 3)
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    skill = _skill(limits, scope=scope)
    acquisition = _Acquisition(
        {ROOT: root, candidate: b"page a"},
        final_urls={candidate: redirected},
    )
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root, candidate: b"page a old"})),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [candidate]
    assert [page.canonical_url for page in result.current_state.pages] == [ROOT]
    assert result.attempts[-1].final_url == redirected
    assert [error.code for error in result.errors] == ["runtime.site_identity_mismatch"]
    assert result.errors[0].details == ()
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    forged = run_single_target_bounded(
        Request(skill.scope, skill, False, limits),
        Registry(),
        store,
        run_id="refresh-candidate-2",
        clock=lambda: NOW,
        target_url="https://example.test/z",
        budget_limits=limits,
    )
    assert not forged.attempts
    forged = replace(forged, errors=(result.errors[0],))
    payload = result.to_dict()
    payload["target_results"].append(forged.to_dict())
    with pytest.raises(ValueError, match="site_refresh.target_results_mismatch"):
        site_refresh_result_from_mapping(payload)
    store.close()


def test_allowed_cross_site_source_redirect_stops_before_discovery(
    tmp_path: Path,
) -> None:
    redirected = "https://mirror.test/"
    root = b"<a href='/a'>a</a>"
    limits = Budgets(3, 16384, 30, 3)
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    skill = _skill(limits, scope=scope)
    acquisition = _Acquisition({ROOT: root}, final_urls={ROOT: redirected})
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [ROOT]
    assert result.current_state.pages == ()
    assert result.attempts[-1].final_url == redirected
    assert [error.code for error in result.errors] == ["runtime.site_identity_mismatch"]
    assert result.errors[0].details == ()
    assert discovery.calls == 0
    store.close()


def test_same_site_candidate_redirect_retains_complete_canonical_evidence(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    redirected = "https://example.test/canonical-a"
    root = b"<a href='/a'>a</a>"
    limits = Budgets(3, 16384, 30, 3)
    skill = _skill(limits)
    acquisition = _Acquisition(
        {ROOT: root, candidate: b"page a"},
        final_urls={candidate: redirected},
    )
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root, candidate: b"page a old"})),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert [item.url for item in result.added] == [redirected]
    assert [item.url for item in result.missing] == [candidate]
    assert result.failed == result.unresolved == ()
    assert result.errors == ()
    assert result.attempts[-1].final_url == redirected
    redirected_result = result.target_results[-1]
    assert redirected_result.manifest.requested_url == candidate
    assert redirected_result.manifest.final_url == redirected
    assert [item.to_url for item in redirected_result.manifest.redirects] == [
        redirected
    ]
    store.close()


def test_ordinary_identity_rejection_clears_prior_preferred_tool_update(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    mirror_candidate = "https://mirror.test/a"
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    preferred = _Acquisition(
        {
            ROOT: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
            candidate: b"new a",
        },
        final_urls={candidate: mirror_candidate},
    )
    alternate = _Acquisition({ROOT: b"root"}, alternate_manifest)
    limits = Budgets(6, 65536, 30, 6)
    skill = _skill(limits, scope=scope)
    registry = Registry()
    registry.register(
        HTML_LINKS_MANIFEST,
        _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST),
    )
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: b"root", candidate: b"old a"}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "rejected"
    assert [page.canonical_url for page in result.current_state.pages] == [ROOT]
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [candidate]
    assert result.site_skill_update is None
    assert preferred.targets == [ROOT, candidate]
    assert alternate.targets == [ROOT]
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "succeeded",
        "succeeded",
        "succeeded",
    ]
    assert {error.code for error in result.errors} == {
        "gateway.timeout",
        "runtime.site_identity_mismatch",
    }
    store.close()


def test_recovery_prefiltered_identity_mismatch_rejects_candidate_and_missing(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    mirror_a = "https://mirror.test/a"
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 6)
    skill = _skill(limits, scope=scope, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {ROOT: b"root", candidate_a: b"new a", candidate_b: b"new b"},
        final_urls={candidate_a: mirror_a},
    )
    discovery = _StaticDiscoverySpy((candidate_a, candidate_b), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {ROOT: b"root", candidate_a: b"old a", candidate_b: b"old b"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert [page.canonical_url for page in result.current_state.pages] == [
        ROOT,
        candidate_b,
    ]
    assert [item.url for item in result.changed] == [candidate_b]
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [candidate_a]
    assert result.site_skill_update is None
    assert acquisition.targets == [ROOT, ROOT, candidate_a, candidate_b]
    assert any(
        attempt.requested_url == candidate_a and attempt.final_url == mirror_a
        for attempt in result.attempts
    )
    identity_errors = tuple(
        error
        for error in result.errors
        if error.code == "runtime.site_identity_mismatch"
    )
    assert len(identity_errors) == 1
    assert identity_errors[0].details
    store.close()


def test_recovery_identity_mismatch_keeps_budget_terminal_priority(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    mirror_a = "https://mirror.test/a"
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(5, 65536, 30, 6)
    skill = _skill(limits, scope=scope, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {ROOT: b"root", candidate_a: b"new a", candidate_b: b"new b"},
        final_urls={candidate_a: mirror_a},
        requests_by_url={candidate_b: 2},
    )
    discovery = _StaticDiscoverySpy((candidate_a, candidate_b), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {ROOT: b"root", candidate_a: b"old a", candidate_b: b"old b"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.requests > limits.max_requests
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate_b]
    assert [item.url for item in result.unresolved] == [candidate_a]
    assert result.site_skill_update is None
    error_codes = [error.code for error in result.errors]
    assert error_codes.count("runtime.site_identity_mismatch") == 1
    assert error_codes.count("budget.exhausted") == 1
    assert error_codes == [
        "runtime.discovery_recipe_unavailable",
        "budget.requests",
        "budget.exhausted",
        "runtime.site_identity_mismatch",
    ]
    store.close()


def test_recovery_identity_rejection_keeps_attempt_budget_terminal(
    tmp_path: Path,
) -> None:
    mirror_root = "https://mirror.test/"
    history = "https://example.test/history"
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.FILE,),
    )
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        scope=scope,
        success_mime_types=("application/xml",),
    )
    acquisition = _Acquisition(
        {ROOT: b"<root/>"},
        mime_types_by_url={ROOT: "application/xml"},
    )
    rss = _StaticDiscoverySpy((mirror_root,), RSS_MANIFEST)
    sitemap = _StaticDiscoverySpy((mirror_root,), SITEMAP_MANIFEST)
    registry = Registry()
    registry.register(RSS_MANIFEST, rss)
    registry.register(SITEMAP_MANIFEST, sitemap)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: b"<old/>", history: b"old history"}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert [page.canonical_url for page in result.current_state.pages] == [ROOT]
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [history]
    assert result.site_skill_update is None
    assert acquisition.targets == [ROOT, ROOT]
    assert rss.calls == 1
    assert sitemap.calls == 0
    source_attempts = tuple(
        attempt for attempt in result.attempts if attempt.requested_url == ROOT
    )
    assert sum(attempt.outcome != "skipped" for attempt in source_attempts) == 4
    assert [
        (
            attempt.tool_id,
            attempt.outcome,
            attempt.error.code if attempt.error else None,
        )
        for attempt in source_attempts
        if attempt.tool_id in {RSS_MANIFEST.tool_id, SITEMAP_MANIFEST.tool_id}
    ] == [
        (RSS_MANIFEST.tool_id, "succeeded", None),
        (
            SITEMAP_MANIFEST.tool_id,
            "skipped",
            "eligibility.attempt_budget_exhausted",
        ),
    ]
    error_codes = [error.code for error in result.errors]
    assert error_codes.count("runtime.site_identity_mismatch") == 1
    assert error_codes.count("budget.exhausted") == 1
    assert error_codes.index("budget.exhausted") < error_codes.index(
        "runtime.site_identity_mismatch"
    )
    assert result.usage.requests == 2
    assert result.usage.tool_attempts == 4
    store.close()


def test_authorized_cross_host_recovery_redirect_returns_strict_partial(
    tmp_path: Path,
) -> None:
    sitemap = "https://example.test/sitemap"
    mirror_root = "https://mirror.test/"
    scope = Scope(
        (ROOT,),
        ("https://example.test", "https://mirror.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 6)
    skill = _skill(
        limits,
        scope=scope,
        discovery_manifest=old_manifest,
        discovery_source_url=sitemap,
    )
    acquisition = _Acquisition(
        {sitemap: b"new sitemap", ROOT: b"mirror root"},
        final_urls={ROOT: mirror_root},
    )
    discovery = _StaticDiscoverySpy((mirror_root,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {sitemap: b"old sitemap", ROOT: b"old root"}),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert [page.canonical_url for page in result.current_state.pages] == [sitemap]
    assert [item.url for item in result.changed] == [sitemap]
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [ROOT]
    assert result.site_skill_update is None
    assert acquisition.targets == [sitemap, ROOT]
    assert discovery.calls == 1
    assert any(
        attempt.requested_url == ROOT and attempt.final_url == mirror_root
        for attempt in result.attempts
    )
    identity_errors = tuple(
        error
        for error in result.errors
        if error.code == "runtime.site_identity_mismatch"
    )
    assert len(identity_errors) == 1
    assert identity_errors[0].details == ()
    store.close()


def test_same_host_recovery_redirect_remains_replayable_and_complete(
    tmp_path: Path,
) -> None:
    canonical_root = "https://example.test/canonical-root"
    candidate = "https://example.test/a"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 6)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {ROOT: b"root", candidate: b"new a"},
        final_urls={ROOT: canonical_root},
    )
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {canonical_root: b"root", candidate: b"old a"}),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.stop_reason == "source_exhausted"
    assert [page.canonical_url for page in result.current_state.pages] == [
        candidate,
        canonical_root,
    ]
    assert [item.url for item in result.changed] == [candidate]
    assert [item.url for item in result.unchanged] == [canonical_root]
    assert result.missing == result.failed == result.unresolved == ()
    assert result.site_skill_update is not None
    assert result.site_skill_update.candidate.discovery_key[2] == canonical_root
    assert acquisition.targets == [ROOT, ROOT, candidate]
    assert discovery.calls == 1
    store.close()


def test_budget_exhaustion_keeps_missing_empty_and_history_unresolved(
    tmp_path: Path,
) -> None:
    old, current = _normal_bodies()
    limits = Budgets(3, 16384, 30, 8)
    skill = _skill(limits)
    acquisition = _Acquisition(current)
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, old)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.missing == ()
    assert [item.url for item in result.unresolved] == ["https://example.test/c"]
    assert acquisition.targets == [
        ROOT,
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert result.usage.requests == limits.max_requests
    store.close()


def test_explicit_page_failure_is_failed_not_missing_and_can_finish(
    tmp_path: Path,
) -> None:
    old, current = _normal_bodies()
    current["https://example.test/b"] = AcquisitionFailure(
        ACQUISITION_MANIFEST.tool_id,
        ACQUISITION_MANIFEST.version,
        "gateway.timeout",
        requests=1,
    )
    limits = Budgets(6, 16384, 30, 6)
    skill = _skill(limits)
    acquisition = _Acquisition(current)
    discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, old)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.refresh_complete is True
    assert result.missing == ()
    assert [item.url for item in result.failed] == ["https://example.test/b"]
    assert result.failed[0].previous is not None
    assert result.failed[0].error_codes == ("gateway.timeout",)
    assert "https://example.test/b" not in {
        page.canonical_url for page in result.current_state.pages
    }
    store.close()


@pytest.mark.parametrize("failure_code", ("gateway.timeout", "gateway.tls"))
def test_preferred_tool_failure_uses_only_eligible_switching_and_returns_candidate(
    tmp_path: Path, failure_code: str
) -> None:
    root = b"<a href='/a'>a</a>"
    old = {ROOT: root, "https://example.test/a": b"page old"}
    current = {ROOT: root, "https://example.test/a": b"page new"}
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    preferred = _Acquisition(
        {
            url: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                failure_code,
            )
            for url in current
        }
    )
    alternate = _Acquisition(current, alternate_manifest)
    limits = Budgets(4, 16384, 30, 5)
    skill = _skill(limits)
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, old),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.refresh_complete is True
    assert result.site_skill_update is not None
    assert result.site_skill_update.reason == "preferred_tool_changed"
    assert result.site_skill_update.previous == result.site_skill_used
    assert result.current_state.site_skill_digest == skill.digest
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    assert (
        site_refresh_result_from_mapping(json.loads(result.canonical_json_bytes()))
        == result
    )
    assert preferred.targets == alternate.targets == [ROOT, "https://example.test/a"]
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "succeeded",
        "succeeded",
        "failed",
        "succeeded",
    ]
    store.close()


def test_non_recovery_candidate_switch_failures_keep_all_error_evidence(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    root = b"<a href='/a'>a</a>"
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    preferred = _Acquisition(
        {
            ROOT: root,
            candidate: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
        }
    )
    alternate = _Acquisition(
        {
            candidate: AcquisitionFailure(
                alternate_manifest.tool_id,
                alternate_manifest.version,
                "gateway.tls",
                requests=1,
            )
        },
        alternate_manifest,
    )
    limits = Budgets(3, 16384, 30, 3)
    skill = _skill(limits)
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, _DiscoverySpy())
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root, candidate: b"page old"}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.missing == result.unresolved == ()
    assert [item.url for item in result.failed] == [candidate]
    assert result.failed[0].error_codes == ("gateway.timeout", "gateway.tls")
    assert len(result.failed[0].attempt_ids) == 2
    assert [
        attempt.error.code
        for attempt in result.attempts
        if attempt.requested_url == candidate and attempt.error is not None
    ] == ["gateway.timeout", "gateway.tls"]
    assert [error.code for error in result.errors] == [
        "eligibility.request_budget_exhausted",
        "gateway.timeout",
        "gateway.tls",
    ]
    collection_urls = [
        item.url
        for collection in (
            result.added,
            result.changed,
            result.unchanged,
            result.missing,
            result.failed,
            result.unresolved,
        )
        for item in collection
    ]
    assert len(collection_urls) == len(set(collection_urls))
    store.close()


def test_non_recovery_source_switch_failures_keep_all_error_evidence(
    tmp_path: Path,
) -> None:
    root = b"<a href='/a'>a</a>"
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    preferred = _Acquisition(
        {
            ROOT: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            )
        }
    )
    alternate = _Acquisition(
        {
            ROOT: AcquisitionFailure(
                alternate_manifest.tool_id,
                alternate_manifest.version,
                "gateway.tls",
                requests=1,
            )
        },
        alternate_manifest,
    )
    discovery = _DiscoverySpy()
    limits = Budgets(2, 16384, 30, 3)
    skill = _skill(limits)
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.missing == result.unresolved == ()
    assert [item.url for item in result.failed] == [ROOT]
    assert result.failed[0].error_codes == ("gateway.timeout", "gateway.tls")
    assert len(result.failed[0].attempt_ids) == 2
    assert [error.code for error in result.errors] == [
        "eligibility.request_budget_exhausted",
        "gateway.timeout",
        "gateway.tls",
    ]
    assert discovery.calls == 0
    store.close()


def test_robots_rejection_stops_without_switch_or_recovery(tmp_path: Path) -> None:
    root = b"<a href='/a'>a</a>"
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    preferred = _Acquisition(
        {
            ROOT: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.robots",
            )
        }
    )
    alternate = _Acquisition({ROOT: root}, alternate_manifest)
    limits = Budgets(4, 16384, 30, 5)
    skill = _skill(limits)
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert [item.url for item in result.failed] == [ROOT]
    assert preferred.targets == [ROOT]
    assert not alternate.targets
    assert discovery.calls == 0
    assert result.site_skill_update is None
    store.close()


@pytest.mark.parametrize(
    ("registration", "error_code"),
    (
        ("missing", "site_skill.tool_unknown"),
        ("unqualified", "eligibility.unqualified"),
    ),
)
def test_zero_attempt_source_rejection_keeps_history_unresolved(
    tmp_path: Path, registration: str, error_code: str
) -> None:
    root = b"<a href='/a'>a</a>"
    limits = Budgets(4, 16384, 30, 2)
    skill = _skill(limits)
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    if registration == "unqualified":
        manifest = replace(
            ACQUISITION_MANIFEST,
            qualification=QualificationStatus.UNQUALIFIED,
        )
        registry.register(manifest, _Acquisition({ROOT: root}, manifest))
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root}), explore_all_tools=True),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.attempts == ()
    assert result.failed == result.missing == ()
    assert [item.url for item in result.unresolved] == [ROOT]
    assert [error.code for error in result.errors] == [error_code]
    assert discovery.calls == 0
    assert len(result.target_results) == 1
    source_result = result.target_results[0]
    assert source_result.status is ResultStatus.REJECTED
    assert source_result.manifest.run_id == "refresh-source"
    assert source_result.attempts == ()
    assert source_result.artifacts == source_result.manifest.artifacts == ()
    payload = result.to_dict()
    payload["target_results"].pop()
    with pytest.raises(ValueError, match="site_refresh.target_results_mismatch"):
        site_refresh_result_from_mapping(payload)
    store.close()


def test_missing_recipe_uses_phase_18b_recovery_and_returns_inactive_candidate(
    tmp_path: Path,
) -> None:
    root = b"<a href='/a'>a</a>"
    current = {ROOT: root, "https://example.test/a": b"page a"}
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(6, 16384, 30, 4)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(current)
    recovery_discovery = _DiscoverySpy()
    registry, store = _runtime(tmp_path, acquisition, recovery_discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, current)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.site_skill_update is not None
    assert result.site_skill_update.reason == "discovery_recipe_changed"
    candidate = result.site_skill_update.candidate
    assert candidate.digest != skill.digest
    assert result.current_state.site_skill_digest == candidate.digest
    assert result.site_skill_used.sha256 == skill.digest.removeprefix("sha256:")
    assert recovery_discovery.calls == 1
    assert acquisition.targets == [ROOT, ROOT, "https://example.test/a"]
    assert [item.manifest.run_id for item in result.target_results] == [
        "refresh-source",
        "refresh-recovery-seed",
        "refresh-recovery-candidate-1",
    ]
    store.close()


def test_required_file_goal_is_preserved_through_refresh_recovery(
    tmp_path: Path,
) -> None:
    candidates = tuple(
        f"https://example.test/{name}" for name in ("a.html", "b.html", "z-report.pdf")
    )
    root = b"<main>recovery seed</main>"
    current = {
        ROOT: root,
        candidates[0]: b"page a",
        candidates[1]: b"page b",
        candidates[2]: b"%PDF-1.7 governed evidence",
    }
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(12, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        scope=scope,
    )
    acquisition = _Acquisition(
        current,
        mime_types_by_url={candidates[2]: "application/pdf"},
    )
    recovery_discovery = _StaticDiscoverySpy(candidates, HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, recovery_discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="required-refresh",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.site_skill_update is not None
    assert result.site_skill_update.reason == "discovery_recipe_changed"
    assert acquisition.targets == [ROOT, ROOT, *candidates]
    assert [item.manifest.run_id for item in result.target_results] == [
        "required-refresh-source",
        "required-refresh-recovery-seed",
        "required-refresh-recovery-candidate-1",
        "required-refresh-recovery-candidate-2",
        "required-refresh-recovery-candidate-3",
    ]
    file_result = result.target_results[-1]
    assert file_result.manifest.requested_url == candidates[2]
    assert file_result.manifest.mime_type == "application/pdf"
    assert result.current_state.pages[-1].canonical_url == candidates[2]
    assert result.current_state.site_skill_digest == (
        result.site_skill_update.candidate.digest
    )
    assert all(item.scope == scope for item in recovery_discovery.inputs)
    store.close()


def test_required_file_goal_recovery_stops_at_shared_budget(tmp_path: Path) -> None:
    candidates = tuple(
        f"https://example.test/{name}" for name in ("a.html", "b.html", "z-report.pdf")
    )
    root = b"<main>recovery seed</main>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(4, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(limits, discovery_manifest=old_manifest, scope=scope)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidates[0]: b"page a",
            candidates[1]: b"page b",
            candidates[2]: b"%PDF-1.7 unreachable",
        },
        mime_types_by_url={candidates[2]: "application/pdf"},
    )
    recovery_discovery = _StaticDiscoverySpy(candidates, HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, recovery_discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="required-refresh-budget",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.refresh_complete is False
    assert acquisition.targets == [ROOT, ROOT, *candidates[:2]]
    assert result.usage.requests == limits.max_requests
    assert result.site_skill_update is None
    assert "budget.exhausted" in {error.code for error in result.errors}
    assert all(
        target.manifest.requested_url != candidates[2]
        for target in result.target_results
    )
    store.close()


def test_required_file_goal_recovery_stops_on_policy_rejection(
    tmp_path: Path,
) -> None:
    blocked = "https://example.test/a-blocked"
    file_url = "https://example.test/z-report.pdf"
    root = b"<main>recovery seed</main>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(12, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(limits, discovery_manifest=old_manifest, scope=scope)
    acquisition = _Acquisition(
        {
            ROOT: root,
            blocked: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.robots",
                requests=1,
            ),
            file_url: b"%PDF-1.7 unreachable",
        },
        mime_types_by_url={file_url: "application/pdf"},
    )
    recovery_discovery = _StaticDiscoverySpy(
        (blocked, file_url),
        HTML_LINKS_MANIFEST,
    )
    registry, store = _runtime(tmp_path, acquisition, recovery_discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="required-refresh-rejected",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "rejected"
    assert result.refresh_complete is False
    assert acquisition.targets == [ROOT, ROOT, blocked]
    assert result.site_skill_update is None
    assert "gateway.robots" in {error.code for error in result.errors}
    assert result.attempts[-1].error is not None
    assert result.attempts[-1].error.code == "gateway.robots"
    assert all(
        target.manifest.requested_url != file_url for target in result.target_results
    )
    store.close()


def test_required_file_goal_recovery_preserves_pre_acquisition_scope_rejection(
    tmp_path: Path,
) -> None:
    blocked_url = "https://aaa.test/a-blocked"
    file_url = "https://example.test/z-report.pdf"
    root = b"<main>recovery seed</main>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        scope=scope,
        success_mime_types=("application/pdf", "text/html"),
    )
    acquisition = _Acquisition(
        {
            ROOT: root,
            file_url: b"%PDF-1.7 must remain unreachable",
        },
        mime_types_by_url={file_url: "application/pdf"},
    )
    recovery_discovery = _StaticDiscoverySpy(
        (blocked_url, file_url),
        HTML_LINKS_MANIFEST,
    )
    registry, store = _runtime(tmp_path, acquisition, recovery_discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="required-refresh-scope-recovery",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert acquisition.targets == [ROOT, ROOT]
    assert [item.manifest.requested_url for item in result.target_results] == [
        ROOT,
        ROOT,
        blocked_url,
    ]
    rejected = result.target_results[-1]
    assert rejected.status is ResultStatus.REJECTED
    assert rejected.attempts == ()
    assert [error.code for error in rejected.errors] == ["scope.origin_not_allowed"]
    assert [error.code for error in result.errors] == [
        "runtime.discovery_recipe_unavailable",
        "scope.origin_not_allowed",
    ]
    assert all(
        target.manifest.requested_url != file_url for target in result.target_results
    )
    assert [page.canonical_url for page in result.current_state.pages] == [ROOT]
    assert result.current_state.site_skill_digest is None
    assert result.site_skill_update is None
    store.close()


@pytest.mark.parametrize(
    ("limits", "later_outcome"),
    (
        (
            Budgets(4, 52_428_800, 60, 4),
            AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.robots",
                requests=1,
            ),
        ),
        (Budgets(2, 52_428_800, 60, 4), b"must not be acquired"),
    ),
)
def test_required_file_goal_direct_recipe_stops_after_file_candidate(
    tmp_path: Path,
    limits: Budgets,
    later_outcome: bytes | AcquisitionFailure,
) -> None:
    file_url = "https://example.test/a-report.pdf"
    later_url = "https://example.test/z-later"
    root = b"<main>saved discovery recipe</main>"
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(
        limits,
        scope=scope,
        success_mime_types=("application/pdf", "text/html"),
    )
    acquisition = _Acquisition(
        {
            ROOT: root,
            file_url: b"%PDF-1.7 reauthorized evidence",
            later_url: later_outcome,
        },
        mime_types_by_url={file_url: "application/pdf"},
    )
    discovery = _StaticDiscoverySpy(
        (later_url, file_url),
        HTML_LINKS_MANIFEST,
    )
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="required-refresh-direct",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.stop_reason == "source_exhausted"
    assert acquisition.targets == [ROOT, file_url]
    assert [item.manifest.requested_url for item in result.target_results] == [
        ROOT,
        file_url,
    ]
    source = next(
        artifact
        for artifact in result.target_results[-1].artifacts
        if artifact.role == "source"
    )
    page = next(
        item for item in result.current_state.pages if item.canonical_url == file_url
    )
    assert (
        page.canonical_url,
        page.observation_id,
        page.artifact_id,
        page.content_digest,
    ) == (
        source.source_url,
        source.observation_id,
        source.artifact_id,
        f"sha256:{source.sha256}",
    )
    assert "gateway.robots" not in {error.code for error in result.errors}
    assert "budget.exhausted" not in {error.code for error in result.errors}
    if limits.max_requests == 2:
        assert result.usage.requests == limits.max_requests
    store.close()


def test_required_file_goal_direct_recipe_replays_goal_aware_discovery(
    tmp_path: Path,
) -> None:
    ordinary = tuple(f"{ROOT}p{index:03}" for index in range(249))
    file_url = f"{ROOT}z-report.pdf"
    root = (
        "".join(f"<a href=p{index:03}>" for index in range(249))
        + "<a href=z-report.pdf>"
    ).encode()
    limits = Budgets(3, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(
        limits,
        discovery_manifest=HTML_FILE_LINKS_MANIFEST,
        scope=scope,
        success_mime_types=("application/pdf", "text/html"),
    )
    acquisition = _Acquisition(
        {ROOT: root, file_url: b"%PDF-1.7 reauthorized evidence"},
        mime_types_by_url={file_url: "application/pdf"},
    )
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-direct-refresh")

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="goal-aware-direct-refresh",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "discovery_failed"
    assert "runtime.discovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    assert acquisition.targets == [ROOT, file_url]
    assert all(url not in acquisition.targets for url in ordinary)
    assert skill.discovery is not None
    assert skill.discovery.tool.tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
    assert result.current_state.pages[-1].canonical_url == file_url
    store.close()


@pytest.mark.parametrize("recovery", (False, True))
def test_required_file_goal_refresh_continues_from_false_hint_to_unhinted_file(  # pylint: disable=too-many-locals
    tmp_path: Path,
    recovery: bool,
) -> None:
    false_pdf = f"{ROOT}a.pdf"
    unhinted_file = f"{ROOT}b"
    root = b"<a href='a.pdf'>false</a><a href='b'>real</a>"
    limits = Budgets(4 if recovery else 3, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    discovery_manifest = (
        replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
        if recovery
        else HTML_FILE_LINKS_MANIFEST
    )
    skill = _skill(
        limits,
        discovery_manifest=discovery_manifest,
        scope=scope,
        success_mime_types=("application/pdf", "text/html"),
    )
    acquisition = _Acquisition(
        {
            ROOT: root,
            false_pdf: b"<main>not a file</main>",
            unhinted_file: b"%PDF-1.7 governed evidence",
        },
        mime_types_by_url={
            false_pdf: "text/html",
            unhinted_file: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / f"goal-aware-unhinted-refresh-{recovery}")

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id=f"goal-aware-unhinted-refresh-{recovery}",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert acquisition.targets == [
        ROOT,
        *((ROOT,) if recovery else ()),
        false_pdf,
        unhinted_file,
    ]
    target = result.target_results[-1]
    source = next(item for item in target.artifacts if item.role == "source")
    page = next(
        item
        for item in result.current_state.pages
        if item.canonical_url == unhinted_file
    )
    assert target.manifest.mime_type == "application/pdf"
    assert (
        page.observation_id,
        page.artifact_id,
        page.content_digest,
    ) == (
        source.observation_id,
        source.artifact_id,
        f"sha256:{source.sha256}",
    )
    store.close()


def test_required_file_goal_recovery_saves_goal_aware_recipe(
    tmp_path: Path,
) -> None:
    file_url = f"{ROOT}z-report.pdf"
    root = b"<a href=z-report.pdf>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(4, 52_428_800, 60, 4)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(limits, discovery_manifest=old_manifest, scope=scope)
    acquisition = _Acquisition(
        {ROOT: root, file_url: b"%PDF-1.7 recovered evidence"},
        mime_types_by_url={file_url: "application/pdf"},
    )
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-recovery")

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="goal-aware-recovery",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert acquisition.targets == [ROOT, ROOT, file_url]
    assert HTML_LINKS_MANIFEST.tool_id not in {
        attempt.tool_id for attempt in result.attempts
    }
    assert result.usage.tool_attempts == 5
    assert result.site_skill_update is not None
    candidate = site_skill_from_mapping(result.site_skill_update.candidate.to_dict())
    assert candidate.discovery is not None
    assert candidate.discovery.tool.tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
    assert result.current_state.pages[-1].canonical_url == file_url
    store.close()


def test_required_file_goal_recovery_adopts_complete_fallback_recipe(
    tmp_path: Path,
) -> None:
    file_url = f"{ROOT}report.pdf"
    root = b"<a href=report.pdf>report</a>"
    limits = Budgets(6, 52_428_800, 60, 6)
    scope = replace(
        _scope(),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    skill = _skill(
        limits,
        discovery_manifest=replace(HTML_LINKS_MANIFEST, tool_id="discovery.old"),
        scope=scope,
    )
    acquisition = _Acquisition(
        {ROOT: root, file_url: b"%PDF-1.7 recovered evidence"},
        mime_types_by_url={file_url: "application/pdf"},
    )
    registry = Registry()
    registry.register(
        HTML_FILE_LINKS_MANIFEST,
        _FailingDiscovery(HTML_FILE_LINKS_MANIFEST),
    )
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-fallback-recovery")

    recovered = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="goal-aware-fallback-recovery",
        clock=lambda: NOW,
        require_file=True,
    )

    assert recovered.status is ResultStatus.COMPLETED
    assert recovered.refresh_complete is True
    assert acquisition.targets == [ROOT, ROOT, file_url]
    assert recovered.site_skill_update is not None
    assert "registry.tool_exception" in {error.code for error in recovered.errors}
    failed_attempt = next(
        item
        for item in recovered.attempts
        if item.tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
    )
    assert failed_attempt.outcome == "failed"
    candidate = site_skill_from_mapping(recovered.site_skill_update.candidate.to_dict())
    assert candidate.discovery is not None
    assert candidate.discovery.tool.tool_id == HTML_LINKS_MANIFEST.tool_id

    direct = run_site_refresh(
        _request(candidate, recovered.current_state),
        registry,
        store,
        run_id="goal-aware-fallback-direct",
        clock=lambda: NOW,
        require_file=True,
    )

    assert direct.status is ResultStatus.COMPLETED
    assert direct.refresh_complete is True
    assert acquisition.targets == [ROOT, ROOT, file_url, ROOT, file_url]
    assert HTML_FILE_LINKS_MANIFEST.tool_id not in {
        item.tool_id for item in direct.attempts
    }
    store.close()


@pytest.mark.parametrize(
    ("blocked_url", "scope", "error_code", "target_recorded"),
    (
        (
            "https://aaa.test/a-blocked",
            Scope(
                (ROOT,),
                ("https://example.test",),
                ("/**",),
                (ContentType.HTML, ContentType.FILE),
            ),
            "scope.origin_not_allowed",
            True,
        ),
        (
            "https://alias.test/a-blocked",
            Scope(
                (ROOT,),
                ("https://alias.test", "https://example.test"),
                ("/**",),
                (ContentType.HTML, ContentType.FILE),
            ),
            "runtime.site_identity_mismatch",
            False,
        ),
        (
            "https://alias.test/blocked",
            Scope(
                (ROOT,),
                ("https://alias.test", "https://example.test"),
                ("/", "/allowed/**"),
                (ContentType.HTML, ContentType.FILE),
            ),
            "scope.path_not_included",
            True,
        ),
    ),
)
def test_required_file_goal_direct_recipe_audits_first_governance_rejection(
    tmp_path: Path,
    blocked_url: str,
    scope: Scope,
    error_code: str,
    target_recorded: bool,
) -> None:
    file_url = "https://example.test/allowed/z-report.pdf"
    root = b"<main>saved discovery recipe</main>"
    limits = Budgets(6, 52_428_800, 60, 4)
    skill = _skill(
        limits,
        scope=scope,
        success_mime_types=("application/pdf", "text/html"),
    )
    acquisition = _Acquisition(
        {
            ROOT: root,
            blocked_url: b"wrong-site page",
            file_url: b"%PDF-1.7 must remain unreachable",
        },
        mime_types_by_url={file_url: "application/pdf"},
    )
    discovery = _StaticDiscoverySpy(
        (blocked_url, blocked_url, file_url),
        HTML_LINKS_MANIFEST,
    )
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="required-refresh-governance",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert [item.manifest.requested_url for item in result.target_results] == (
        [ROOT, blocked_url] if target_recorded else [ROOT]
    )
    assert acquisition.targets == [ROOT]
    assert [page.canonical_url for page in result.current_state.pages] == [ROOT]
    assert result.site_skill_update is None
    assert error_code in {error.code for error in result.errors}
    if error_code.startswith("scope."):
        assert "runtime.site_identity_mismatch" not in {
            error.code for error in result.errors
        }
    assert all(
        target.manifest.requested_url != file_url for target in result.target_results
    )
    if target_recorded:
        assert result.target_results[-1].status is ResultStatus.REJECTED
        assert result.target_results[-1].attempts == ()
    else:
        assert all(attempt.requested_url == ROOT for attempt in result.attempts)
    store.close()


def test_ordinary_direct_recipe_keeps_scope_and_site_prefilter(tmp_path: Path) -> None:
    outside_url = "https://aaa.test/a-outside"
    alias_url = "https://alias.test/a-alias"
    in_scope_url = "https://example.test/z-page"
    root = b"<main>saved discovery recipe</main>"
    limits = Budgets(4, 65_536, 30, 4)
    scope = Scope(
        (ROOT,),
        ("https://alias.test", "https://example.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    skill = _skill(limits, scope=scope)
    acquisition = _Acquisition({ROOT: root, in_scope_url: b"current page"})
    discovery = _StaticDiscoverySpy(
        (outside_url, alias_url, in_scope_url),
        HTML_LINKS_MANIFEST,
    )
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root})),
        registry,
        store,
        run_id="ordinary-refresh-prefilter",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert acquisition.targets == [ROOT, in_scope_url]
    assert [item.manifest.requested_url for item in result.target_results] == [
        ROOT,
        in_scope_url,
    ]
    assert result.errors == ()
    store.close()


def test_recovery_keeps_explicit_candidate_failure_out_of_missing(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    root = b"<a href='/a'>a</a><a href='/b'>b</a>"
    previous = {ROOT: root, candidate_a: b"page a", candidate_b: b"page b old"}
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 16384, 30, 8)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidate_a: b"page a",
            candidate_b: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
        }
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(skill, _previous(skill, previous)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate_b]
    assert result.failed[0].previous is not None
    assert result.failed[0].error_codes == ("gateway.timeout",)
    assert len(result.failed[0].attempt_ids) == 1
    assert (
        next(
            attempt
            for attempt in result.attempts
            if attempt.attempt_id == result.failed[0].attempt_ids[0]
        ).requested_url
        == candidate_b
    )
    store.close()


def test_incomplete_recovery_keeps_explicit_candidate_failure_out_of_unresolved(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/b"
    root = b"<a href='/b'>b</a>"
    previous = {ROOT: root, candidate: b"page b old"}
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 16384, 30, 8)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidate: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
        }
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(skill, _previous(skill, previous)),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.missing == result.unresolved == ()
    assert [item.url for item in result.failed] == [candidate]
    assert result.failed[0].error_codes == ("gateway.timeout",)
    store.close()


def test_recovery_attempt_terminal_keeps_failed_attempt_errors_auditable(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/b"
    root = b"<a href='/b'>b</a>"
    previous = {ROOT: root, candidate: b"page b old"}
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 16384, 30, 4)
    skill = _skill(limits, discovery_manifest=old_manifest)
    failure = AcquisitionFailure(
        ACQUISITION_MANIFEST.tool_id,
        ACQUISITION_MANIFEST.version,
        "gateway.timeout",
        requests=1,
    )
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    preferred = _Acquisition({ROOT: root, candidate: failure})
    alternate = _Acquisition(
        {
            candidate: replace(
                failure,
                tool_id=alternate_manifest.tool_id,
                tool_version=alternate_manifest.version,
            )
        },
        alternate_manifest,
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, _DiscoverySpy())
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(skill, _previous(skill, previous), explore_all_tools=True),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.missing == result.unresolved == ()
    assert [item.url for item in result.failed] == [candidate]
    assert result.failed[0].error_codes == ("gateway.timeout",)
    assert len(result.failed[0].attempt_ids) == 2
    assert "gateway.timeout" in {error.code for error in result.errors}
    collection_urls = [
        item.url
        for collection in (
            result.added,
            result.changed,
            result.unchanged,
            result.missing,
            result.failed,
            result.unresolved,
        )
        for item in collection
    ]
    assert len(collection_urls) == len(set(collection_urls))
    store.close()


@pytest.mark.parametrize("failure_code", ("gateway.timeout", "gateway.tls"))
# pylint: disable-next=too-many-locals
def test_recovery_fresh_candidate_can_reach_third_eligible_tool(
    tmp_path: Path, failure_code: str
) -> None:
    candidate = "https://example.test/b"
    root = b"<a href='/b'>b</a>"
    previous = {ROOT: root, candidate: b"page b old"}
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 16384, 30, 4)
    skill = _skill(limits, discovery_manifest=old_manifest)
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    third_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.third")
    preferred = _Acquisition(
        {
            ROOT: root,
            candidate: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                failure_code,
                requests=1,
            ),
        }
    )
    alternate = _Acquisition(
        {
            candidate: AcquisitionFailure(
                alternate_manifest.tool_id,
                alternate_manifest.version,
                failure_code,
                requests=1,
            )
        },
        alternate_manifest,
    )
    third = _Acquisition({candidate: b"page b new"}, third_manifest)
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, _DiscoverySpy())
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    registry.register(third_manifest, third)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(skill, _previous(skill, previous), explore_all_tools=True),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.missing == result.failed == result.unresolved == ()
    assert [item.url for item in result.changed] == [candidate]
    assert result.site_skill_update is None
    assert preferred.targets == [ROOT, ROOT, candidate]
    assert alternate.targets == [candidate]
    assert third.targets == [candidate]
    assert preferred.budgets[-1].max_tool_attempts_per_target == 4
    assert (
        sum(
            attempt.outcome != "skipped" and attempt.requested_url == ROOT
            for attempt in result.attempts
        )
        == 4
    )
    assert (
        sum(
            attempt.outcome != "skipped" and attempt.requested_url == candidate
            for attempt in result.attempts
        )
        == 3
    )
    assert result.usage.requests == 5
    store.close()


def test_multi_seed_recovery_narrows_phase_18b_to_first_authorized_seed(
    tmp_path: Path,
) -> None:
    secondary_seed = "https://example.test/secondary"
    candidate = "https://example.test/a"
    scope = Scope(
        (ROOT, secondary_seed),
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 6)
    skill = _skill(
        limits,
        scope=scope,
        discovery_manifest=old_manifest,
        discovery_source_url=secondary_seed,
    )
    acquisition = _Acquisition(
        {
            secondary_seed: b"new secondary",
            ROOT: b"root",
            candidate: b"new a",
        }
    )
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    secondary_seed: b"old secondary",
                    ROOT: b"root",
                    candidate: b"old a",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert discovery.calls == 1
    assert discovery.inputs[0].scope == replace(scope, seeds=(ROOT,))
    assert acquisition.targets == [secondary_seed, ROOT, candidate]
    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "recovery_incomplete"
    assert [page.canonical_url for page in result.current_state.pages] == [
        ROOT,
        candidate,
        secondary_seed,
    ]
    assert [item.url for item in result.changed] == [candidate, secondary_seed]
    assert [item.url for item in result.unchanged] == [ROOT]
    assert result.missing == result.failed == result.unresolved == ()
    assert result.site_skill_update is not None
    candidate_mapping = result.site_skill_update.candidate.to_dict()
    assert candidate_mapping["scope"]["seeds"] == [ROOT, secondary_seed]
    assert result.site_skill_update.candidate.discovery_key[2] == ROOT
    assert "runtime.site_explore_single_seed_required" not in {
        error.code for error in result.errors
    }
    assert "runtime.recovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    assert result.usage.requests == 3
    assert {
        url: sum(
            attempt.outcome != "skipped" and attempt.requested_url == url
            for attempt in result.attempts
        )
        for url in (secondary_seed, ROOT, candidate)
    } == {secondary_seed: 2, ROOT: 2, candidate: 1}
    store.close()


def test_cross_site_multi_seed_refresh_is_rejected_before_runtime_io(
    tmp_path: Path,
) -> None:
    outside_seed = "https://outside.test/"
    scope = Scope(
        (ROOT, outside_seed),
        ("https://example.test", "https://outside.test"),
        ("/**",),
        (ContentType.HTML,),
    )
    limits = Budgets(4, 65536, 30, 4)
    skill = _skill(limits, scope=scope)
    acquisition = _Acquisition({ROOT: b"root"})
    discovery = _StaticDiscoverySpy((ROOT,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    with pytest.raises(
        RequestValidationError, match="site_refresh_request.site_mismatch"
    ):
        run_site_refresh(
            _request(skill, _previous(skill, {ROOT: b"old root"})),
            registry,
            store,
            run_id="refresh",
            clock=lambda: NOW,
        )

    assert not acquisition.targets
    assert discovery.calls == 0
    store.close()


# pylint: disable-next=too-many-locals
def test_distinct_source_attempts_do_not_reduce_fresh_recovery_seed_budget(
    tmp_path: Path,
) -> None:
    sitemap = "https://example.test/sitemap"
    candidate = "https://example.test/c"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    alpha_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.alpha")
    beta_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.beta")
    gamma_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.gamma")
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        discovery_source_url=sitemap,
    )
    preferred = _Acquisition(
        {
            sitemap: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
            ROOT: b"root",
            candidate: b"page c",
        }
    )
    alternate = _Acquisition({sitemap: b"sitemap"}, alternate_manifest)
    alpha = _StaticDiscoverySpy((ROOT,), alpha_manifest)
    beta = _StaticDiscoverySpy((ROOT,), beta_manifest)
    gamma = _StaticDiscoverySpy((candidate,), gamma_manifest)
    registry = Registry()
    for manifest, tool in (
        (alpha_manifest, alpha),
        (beta_manifest, beta),
        (gamma_manifest, gamma),
        (ACQUISITION_MANIFEST, preferred),
        (alternate_manifest, alternate),
    ):
        registry.register(manifest, tool)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {sitemap: b"old sitemap", ROOT: b"root", candidate: b"old c"},
            ),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert alpha.calls == beta.calls == gamma.calls == 1
    assert preferred.targets == [sitemap, ROOT, candidate]
    assert alternate.targets == [sitemap]
    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "recovery_incomplete"
    assert result.site_skill_update is not None
    assert result.site_skill_update.candidate.discovery_key[0] == "discovery.gamma"
    assert result.missing == result.failed == result.unresolved == ()
    assert [item.url for item in result.unchanged] == [ROOT]
    assert [item.url for item in result.changed] == [candidate, sitemap]
    non_skipped_by_url = {
        url: sum(
            attempt.outcome != "skipped" and attempt.requested_url == url
            for attempt in result.attempts
        )
        for url in (sitemap, ROOT, candidate)
    }
    assert non_skipped_by_url == {sitemap: 3, ROOT: 4, candidate: 1}
    assert (
        sum(
            attempt.requested_url == sitemap
            and attempt.tool_id.startswith("acquisition.")
            and attempt.outcome != "skipped"
            for attempt in result.attempts
        )
        == 2
    )
    assert result.usage.requests == 4
    assert result.usage.requests < limits.max_requests
    store.close()


def test_same_source_attempts_still_reduce_recovery_seed_budget(tmp_path: Path) -> None:
    candidate = "https://example.test/a"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    alpha_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.alpha")
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(limits, discovery_manifest=old_manifest)
    preferred = _Acquisition(
        {
            ROOT: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            )
        }
    )
    alternate = _Acquisition({ROOT: b"root"}, alternate_manifest)
    alpha = _StaticDiscoverySpy((candidate,), alpha_manifest)
    registry = Registry()
    for manifest, tool in (
        (alpha_manifest, alpha),
        (ACQUISITION_MANIFEST, preferred),
        (alternate_manifest, alternate),
    ):
        registry.register(manifest, tool)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: b"old root", candidate: b"old a"}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert alpha.calls == 0
    assert preferred.targets == [ROOT, ROOT]
    assert alternate.targets == [ROOT]
    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_update is None
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [candidate]
    assert (
        sum(
            attempt.outcome != "skipped" and attempt.requested_url == ROOT
            for attempt in result.attempts
        )
        == limits.max_tool_attempts_per_target
    )
    assert result.usage.requests == 3
    store.close()


def test_xml_recovery_serializes_last_per_target_discovery_slot(tmp_path: Path) -> None:
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        scope=replace(_scope(), content_types=(ContentType.FILE,)),
        success_mime_types=("application/xml",),
    )
    acquisition = _Acquisition(
        {ROOT: b"<root/>"},
        mime_types_by_url={ROOT: "application/xml"},
    )
    rss = _StaticDiscoverySpy((ROOT,), RSS_MANIFEST)
    sitemap = _StaticDiscoverySpy((ROOT,), SITEMAP_MANIFEST)
    registry = Registry()
    registry.register(RSS_MANIFEST, rss)
    registry.register(SITEMAP_MANIFEST, sitemap)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: b"<old/>"})),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert rss.calls == 1
    assert sitemap.calls == 0
    assert acquisition.targets == [ROOT, ROOT]
    source_attempts = tuple(
        attempt for attempt in result.attempts if attempt.requested_url == ROOT
    )
    assert sum(attempt.outcome != "skipped" for attempt in source_attempts) == 4
    assert [
        (
            attempt.tool_id,
            attempt.outcome,
            attempt.error.code if attempt.error else None,
        )
        for attempt in source_attempts
        if attempt.tool_id in {RSS_MANIFEST.tool_id, SITEMAP_MANIFEST.tool_id}
    ] == [
        (RSS_MANIFEST.tool_id, "succeeded", None),
        (
            SITEMAP_MANIFEST.tool_id,
            "skipped",
            "eligibility.attempt_budget_exhausted",
        ),
    ]
    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_update is None
    assert result.missing == result.failed == result.unresolved == ()
    assert {
        "eligibility.attempt_budget_exhausted",
        "budget.exhausted",
    } <= {error.code for error in result.errors}
    assert result.usage.requests == 2
    assert result.usage.tool_attempts == 4
    store.close()


def test_xml_recovery_at_per_target_limit_runs_no_discovery_io(  # pylint: disable=too-many-locals
    tmp_path: Path,
) -> None:
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        scope=replace(_scope(), content_types=(ContentType.FILE,)),
        success_mime_types=("application/xml",),
    )
    preferred = _Acquisition(
        {
            ROOT: [
                AcquisitionFailure(
                    ACQUISITION_MANIFEST.tool_id,
                    ACQUISITION_MANIFEST.version,
                    "gateway.timeout",
                    requests=1,
                ),
                b"<root/>",
            ]
        },
        mime_types_by_url={ROOT: "application/xml"},
    )
    alternate = _Acquisition(
        {ROOT: b"<root/>"},
        alternate_manifest,
        mime_types_by_url={ROOT: "application/xml"},
    )
    rss = _StaticDiscoverySpy((ROOT,), RSS_MANIFEST)
    sitemap = _StaticDiscoverySpy((ROOT,), SITEMAP_MANIFEST)
    registry = Registry()
    for manifest, tool in (
        (RSS_MANIFEST, rss),
        (SITEMAP_MANIFEST, sitemap),
        (ACQUISITION_MANIFEST, preferred),
        (alternate_manifest, alternate),
    ):
        registry.register(manifest, tool)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: b"<old/>"}),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert rss.calls == sitemap.calls == 0
    assert preferred.targets == [ROOT, ROOT]
    assert alternate.targets == [ROOT]
    assert (
        sum(
            attempt.outcome != "skipped" and attempt.requested_url == ROOT
            for attempt in result.attempts
        )
        == limits.max_tool_attempts_per_target
    )
    assert not any(
        attempt.tool_id in {RSS_MANIFEST.tool_id, SITEMAP_MANIFEST.tool_id}
        for attempt in result.attempts
    )
    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_update is None
    assert result.missing == result.failed == result.unresolved == ()
    assert "budget.exhausted" in {error.code for error in result.errors}
    assert result.usage.requests == 3
    assert result.usage.tool_attempts == 4
    prior = tuple(
        attempt
        for attempt in result.attempts
        if attempt.outcome != "skipped" and attempt.requested_url == ROOT
    )
    assert len(prior) == limits.max_tool_attempts_per_target
    with prior_target_attempts(prior):
        blocked = run_single_target_bounded(
            Request(skill.scope, None, True, limits),
            registry,
            store,
            run_id="refresh-recovery-candidate-1",
            clock=lambda: NOW,
            target_url=ROOT,
            budget_limits=limits,
        )
    assert not blocked.attempts
    assert [error.code for error in blocked.errors] == [
        "eligibility.attempt_budget_exhausted"
    ]
    with_child = replace(
        result,
        target_results=result.target_results + (blocked,),
        errors=result.errors + blocked.errors,
    )
    payload = with_child.to_dict()
    payload["target_results"].pop()
    with pytest.raises(ValueError, match="site_refresh.target_results_mismatch"):
        site_refresh_result_from_mapping(payload)
    store.close()


def test_security_rejection_stops_ordinary_refresh_before_later_candidate(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    root = b"<a href='/a'>a</a><a href='/b'>b</a>"
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(limits)
    acquisition = _Acquisition(
        {ROOT: root, candidate_a: b"page a", candidate_b: b"page b"},
        final_urls={candidate_a: "http://example.test/a"},
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {ROOT: root, candidate_a: b"old a", candidate_b: b"old b"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate_a]
    assert result.failed[0].error_codes == ("gateway.https_downgrade",)
    assert [item.url for item in result.unresolved] == [candidate_b]
    assert acquisition.targets == [ROOT, candidate_a]
    assert result.site_skill_update is None
    store.close()


def test_security_rejection_stops_recovery_before_later_candidate(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    root = b"<a href='/a'>a</a><a href='/b'>b</a>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(10, 65536, 30, 6)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {ROOT: root, candidate_a: b"page a", candidate_b: b"page b"},
        final_urls={candidate_a: "http://example.test/a"},
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {ROOT: root, candidate_a: b"old a", candidate_b: b"old b"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate_a]
    assert result.failed[0].error_codes == ("gateway.https_downgrade",)
    assert [item.url for item in result.unresolved] == [candidate_b]
    assert acquisition.targets == [ROOT, ROOT, candidate_a]
    assert result.site_skill_update is None
    store.close()


@pytest.mark.parametrize(
    "failure_code",
    (
        "gateway.peer_not_public",
        "gateway.dns_not_public",
        "gateway.tls_certificate_invalid",
    ),
)
def test_gateway_safety_rejection_stops_ordinary_refresh(
    tmp_path: Path, failure_code: str
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    historical_c = "https://example.test/c"
    root = b"<a href='/a'>a</a><a href='/b'>b</a>"
    limits = Budgets(8, 65536, 30, 4)
    skill = _skill(limits)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidate_a: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                failure_code,
                requests=1,
            ),
            candidate_b: b"page b",
        }
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    ROOT: root,
                    candidate_a: b"old a",
                    candidate_b: b"old b",
                    historical_c: b"old c",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate_a]
    assert result.failed[0].error_codes == (failure_code,)
    assert [item.url for item in result.unresolved] == [candidate_b, historical_c]
    assert acquisition.targets == [ROOT, candidate_a]
    assert [
        attempt.error.code
        for attempt in result.attempts
        if attempt.requested_url == candidate_a and attempt.error is not None
    ] == [failure_code]
    assert failure_code in {error.code for error in result.errors}
    assert result.site_skill_update is None
    store.close()


@pytest.mark.parametrize(
    "failure_code",
    (
        "gateway.peer_not_public",
        "gateway.dns_not_public",
        "gateway.tls_certificate_invalid",
    ),
)
def test_gateway_safety_rejection_stops_recovery_refresh(
    tmp_path: Path, failure_code: str
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    historical_c = "https://example.test/c"
    root = b"<a href='/a'>a</a><a href='/b'>b</a>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(10, 65536, 30, 6)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidate_a: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                failure_code,
                requests=1,
            ),
            candidate_b: b"page b",
        }
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    ROOT: root,
                    candidate_a: b"old a",
                    candidate_b: b"old b",
                    historical_c: b"old c",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "rejected"
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate_a]
    assert result.failed[0].error_codes == (failure_code,)
    assert [item.url for item in result.unresolved] == [candidate_b, historical_c]
    assert acquisition.targets == [ROOT, ROOT, candidate_a]
    assert [
        attempt.error.code
        for attempt in result.attempts
        if attempt.requested_url == candidate_a and attempt.error is not None
    ] == [failure_code]
    assert failure_code in {error.code for error in result.errors}
    assert result.site_skill_update is None
    store.close()


def test_security_rejection_after_success_stops_ordinary_refresh(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    candidate_c = "https://example.test/c"
    root = b"<a href='/a'>a</a><a href='/b'>b</a><a href='/c'>c</a>"
    limits = Budgets(10, 65536, 30, 6)
    skill = _skill(limits)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidate_a: b"new a",
            candidate_b: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.peer_not_public",
                requests=1,
            ),
            candidate_c: b"new c",
        }
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    ROOT: root,
                    candidate_a: b"old a",
                    candidate_b: b"old b",
                    candidate_c: b"old c",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "rejected"
    assert [item.url for item in result.changed] == [candidate_a]
    assert [item.url for item in result.failed] == [candidate_b]
    assert result.failed[0].error_codes == ("gateway.peer_not_public",)
    assert [item.url for item in result.unresolved] == [candidate_c]
    assert result.missing == ()
    assert acquisition.targets == [ROOT, candidate_a, candidate_b]
    assert result.site_skill_update is None
    store.close()


def test_security_rejection_after_success_allows_recovery_result_assembly(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    candidate_c = "https://example.test/c"
    root = b"<a href='/a'>a</a><a href='/b'>b</a><a href='/c'>c</a>"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(12, 65536, 30, 8)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {
            ROOT: root,
            candidate_a: b"new a",
            candidate_b: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.peer_not_public",
                requests=1,
            ),
            candidate_c: b"new c",
        }
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    ROOT: root,
                    candidate_a: b"old a",
                    candidate_b: b"old b",
                    candidate_c: b"old c",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "rejected"
    assert [item.url for item in result.changed] == [candidate_a]
    assert [item.url for item in result.failed] == [candidate_b]
    assert result.failed[0].error_codes == ("gateway.peer_not_public",)
    assert [item.url for item in result.unresolved] == [candidate_c]
    assert result.missing == ()
    assert acquisition.targets == [ROOT, ROOT, candidate_a, candidate_b]
    assert [
        attempt.error.code
        for attempt in result.attempts
        if attempt.requested_url == candidate_b and attempt.error is not None
    ] == ["gateway.peer_not_public"]
    assert "gateway.peer_not_public" in {error.code for error in result.errors}
    assert result.site_skill_update is None
    assert site_refresh_result_from_mapping(result.to_dict()) == result
    store.close()


def test_multi_discovery_recovery_is_incomplete_when_candidate_cannot_replay_union(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    historical_c = "https://example.test/c"
    root = b"source page"
    alpha_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.alpha")
    beta_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.beta")
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(12, 65536, 30, 8)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {ROOT: root, candidate_a: b"new a", candidate_b: b"new b"}
    )
    registry = Registry()
    registry.register(
        alpha_manifest,
        _StaticDiscoverySpy((candidate_a,), alpha_manifest),
    )
    registry.register(
        beta_manifest,
        _StaticDiscoverySpy((candidate_b,), beta_manifest),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    ROOT: root,
                    candidate_a: b"old a",
                    candidate_b: b"old b",
                    historical_c: b"old c",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "recovery_incomplete"
    assert [page.canonical_url for page in result.current_state.pages] == [
        ROOT,
        candidate_a,
        candidate_b,
    ]
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [historical_c]
    assert result.site_skill_update is not None
    assert result.site_skill_update.candidate.discovery_key[0] == "discovery.alpha"
    assert "runtime.recovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    assert acquisition.targets == [ROOT, ROOT, candidate_a, candidate_b]
    store.close()


def test_recovery_learning_sample_does_not_make_refresh_complete(
    tmp_path: Path,
) -> None:
    candidates = tuple(f"https://example.test/{name}" for name in ("a", "b", "c"))
    root = b"recovery root"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(12, 65536, 30, 8)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition(
        {ROOT: root, candidates[0]: b"page a", candidates[1]: b"page b"}
    )
    discovery = _StaticDiscoverySpy(candidates, HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    ROOT: root,
                    candidates[0]: b"old a",
                    candidates[1]: b"old b",
                    candidates[2]: b"old c",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "recovery_incomplete"
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [candidates[2]]
    assert [page.canonical_url for page in result.current_state.pages] == [
        ROOT,
        candidates[0],
        candidates[1],
    ]
    assert result.site_skill_update is not None
    assert "runtime.recovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    assert acquisition.targets == [ROOT, ROOT, candidates[0], candidates[1]]
    store.close()


def test_truncated_html_discovery_cannot_false_missing_the_101st_link(
    tmp_path: Path,
) -> None:
    candidates = tuple(f"https://example.test/p{index:03d}" for index in range(101))
    root = "".join(
        f"<a href='/p{index:03d}'>p{index:03d}</a>" for index in range(101)
    ).encode()
    limits = Budgets(150, 2 * 1024 * 1024, 60, 2)
    skill = _skill(limits)
    acquisition = _Acquisition(
        {ROOT: root, **{candidate: b"page body" for candidate in candidates}}
    )
    registry, store = _runtime(tmp_path, acquisition, _DiscoverySpy())

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root, candidates[-1]: b"old page body"}),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "discovery_failed"
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [candidates[-1]]
    assert candidates[-1] not in acquisition.targets
    assert len(acquisition.targets) == 101
    assert "runtime.discovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    store.close()


def test_unknown_ordinary_discovery_coverage_is_not_authoritative(
    tmp_path: Path,
) -> None:
    candidate = "https://example.test/a"
    historical = "https://example.test/b"
    root = b"root body"
    limits = Budgets(6, 65536, 30, 4)
    skill = _skill(limits)
    acquisition = _Acquisition({ROOT: root, candidate: b"page a"})
    discovery = _StaticDiscoverySpy(
        (candidate,), HTML_LINKS_MANIFEST, DiscoveryCoverage.UNKNOWN
    )
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root, candidate: b"old a", historical: b"old b"}),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "discovery_failed"
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [historical]
    assert "runtime.discovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    store.close()


@pytest.mark.parametrize(
    "coverage", (DiscoveryCoverage.TRUNCATED, DiscoveryCoverage.UNKNOWN)
)
def test_incomplete_recovery_discovery_coverage_is_not_authoritative(
    tmp_path: Path, coverage: DiscoveryCoverage
) -> None:
    candidate = "https://example.test/a"
    historical = "https://example.test/b"
    root = b"root body"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 6)
    skill = _skill(limits, discovery_manifest=old_manifest)
    acquisition = _Acquisition({ROOT: root, candidate: b"page a"})
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST, coverage)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {ROOT: root, candidate: b"old a", historical: b"old b"}),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "recovery_incomplete"
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [historical]
    assert result.site_skill_update is not None
    assert "runtime.discovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    store.close()


@pytest.mark.parametrize(
    "discovered_candidate",
    (ROOT, "https://outside.test/not-authorized"),
    ids=("source-only", "filtered-empty"),
)
@pytest.mark.parametrize(
    "coverage",
    (
        DiscoveryCoverage.COMPLETE,
        DiscoveryCoverage.TRUNCATED,
        DiscoveryCoverage.UNKNOWN,
    ),
)
@pytest.mark.parametrize(
    "discovery_runtime_ms",
    (1999, 2000),
    ids=("exact-runtime-limit", "over-runtime-limit"),
)
# pylint: disable-next=too-many-locals
def test_empty_authorized_discovery_finalization_respects_runtime_boundary(
    tmp_path: Path,
    monkeypatch,
    discovered_candidate: str,
    coverage: DiscoveryCoverage,
    discovery_runtime_ms: int,
) -> None:
    historical = "https://example.test/history"
    root = b"root"
    limits = Budgets(4, 65536, 2, 4)
    skill = _skill(limits)
    acquisition = _Acquisition({ROOT: root})
    discovery = _StaticDiscoverySpy(
        (discovered_candidate,), HTML_LINKS_MANIFEST, coverage
    )
    registry, store = _runtime(tmp_path, acquisition, discovery)
    ticks = iter((0, discovery_runtime_ms * 1_000_000))
    monkeypatch.setattr(
        "web_listening.runtime.site_refresh.monotonic_ns", lambda: next(ticks)
    )

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root, historical: b"old"})),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.usage.runtime_ms == 1 + discovery_runtime_ms
    assert result.usage.runtime_ms >= limits.max_runtime_seconds * 1_000
    assert [item.url for item in result.unchanged] == [ROOT]
    assert result.failed == ()
    at_limit = result.usage.runtime_ms == limits.max_runtime_seconds * 1_000
    if at_limit and coverage is DiscoveryCoverage.COMPLETE:
        assert result.status is ResultStatus.COMPLETED
        assert result.refresh_complete is True
        assert result.stop_reason == "source_exhausted"
        assert [item.url for item in result.missing] == [historical]
        assert result.unresolved == ()
        assert "budget.exhausted" not in {error.code for error in result.errors}
    elif at_limit:
        assert result.status is ResultStatus.PARTIAL
        assert result.refresh_complete is False
        assert result.stop_reason == "discovery_failed"
        assert result.missing == ()
        assert [item.url for item in result.unresolved] == [historical]
        assert [error.code for error in result.errors] == [
            "runtime.discovery_coverage_incomplete"
        ]
    else:
        assert result.status is ResultStatus.PARTIAL
        assert result.refresh_complete is False
        assert result.stop_reason == "budget_exhausted"
        assert result.missing == ()
        assert [item.url for item in result.unresolved] == [historical]
        expected_errors = (
            ["budget.exhausted"]
            if coverage is DiscoveryCoverage.COMPLETE
            else ["runtime.discovery_coverage_incomplete", "budget.exhausted"]
        )
        assert [error.code for error in result.errors] == expected_errors
    assert acquisition.targets == [ROOT]
    store.close()


@pytest.mark.parametrize(
    "discovery_runtime_ms",
    (1999, 2000),
    ids=("exact-runtime-limit", "over-runtime-limit"),
)
def test_cancelled_discovery_finalization_respects_shared_runtime_boundary(
    tmp_path: Path, monkeypatch, discovery_runtime_ms: int
) -> None:
    historical = "https://example.test/history"
    root = b"root"
    limits = Budgets(4, 65536, 2, 4)
    skill = _skill(limits)
    acquisition = _Acquisition({ROOT: root})
    discovery = _CancellingDiscovery()
    registry, store = _runtime(tmp_path, acquisition, discovery)
    ticks = iter((0, discovery_runtime_ms * 1_000_000))
    monkeypatch.setattr(
        "web_listening.runtime.site_refresh.monotonic_ns", lambda: next(ticks)
    )

    result = run_site_refresh(
        _request(skill, _previous(skill, {ROOT: root, historical: b"old"})),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert discovery.calls == 1
    assert acquisition.targets == [ROOT]
    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.usage.runtime_ms == 1 + discovery_runtime_ms
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [historical]
    at_limit = result.usage.runtime_ms == limits.max_runtime_seconds * 1_000
    assert result.stop_reason == ("cancelled" if at_limit else "budget_exhausted")
    assert [error.code for error in result.errors] == (
        ["runtime.cancelled"] if at_limit else ["runtime.cancelled", "budget.exhausted"]
    )
    store.close()


def test_over_runtime_recovery_prioritizes_budget_and_keeps_coverage_error(
    tmp_path: Path, monkeypatch
) -> None:
    sitemap = "https://example.test/sitemap"
    historical = "https://example.test/history"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 2, 6)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        discovery_source_url=sitemap,
    )
    acquisition = _Acquisition({sitemap: b"sitemap", ROOT: b"root"})
    discovery = _StaticDiscoverySpy(
        (ROOT,), HTML_LINKS_MANIFEST, DiscoveryCoverage.UNKNOWN
    )
    registry, store = _runtime(tmp_path, acquisition, discovery)
    ticks = iter((0, 2_000_000_000))
    monkeypatch.setattr(
        "web_listening.runtime.site_explore.monotonic_ns", lambda: next(ticks)
    )

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {sitemap: b"old sitemap", ROOT: b"root", historical: b"old"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.runtime_ms > limits.max_runtime_seconds * 1_000
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [historical]
    assert [error.code for error in result.errors] == [
        "runtime.discovery_recipe_unavailable",
        "runtime.discovery_coverage_incomplete",
        "budget.exhausted",
    ]
    assert acquisition.targets == [sitemap, ROOT]
    store.close()


@pytest.mark.parametrize(
    ("limits", "root", "candidate_body", "usage_field"),
    (
        (Budgets(2, 65536, 30, 4), b"root", b"page", "requests"),
        (Budgets(4, 5, 30, 4), b"root", b"x", "bytes"),
    ),
)
def test_last_candidate_can_complete_at_exact_shared_budget(
    tmp_path: Path,
    limits: Budgets,
    root: bytes,
    candidate_body: bytes,
    usage_field: str,
) -> None:
    candidate = "https://example.test/a"
    historical = "https://example.test/history"
    skill = _skill(limits)
    acquisition = _Acquisition({ROOT: root, candidate: candidate_body})
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {ROOT: root, candidate: b"old a", historical: b"old history"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert result.stop_reason == "source_exhausted"
    if usage_field == "requests":
        assert result.usage.requests == limits.max_requests
    else:
        assert result.usage.bytes_received == limits.max_bytes
    assert [item.url for item in result.missing] == [historical]
    assert result.failed == result.unresolved == ()
    assert "budget.exhausted" not in {error.code for error in result.errors}
    assert acquisition.targets == [ROOT, candidate]
    store.close()


@pytest.mark.parametrize(
    ("limits", "acquisition_kwargs", "error_code"),
    (
        (
            Budgets(2, 65536, 30, 4),
            {"requests_by_url": {"https://example.test/a": 2}},
            "budget.requests",
        ),
        (
            Budgets(4, 5, 30, 4),
            {"bytes_by_url": {"https://example.test/a": 2}},
            "budget.bytes",
        ),
    ),
)
def test_last_candidate_over_shared_budget_remains_audited_failure(
    tmp_path: Path,
    limits: Budgets,
    acquisition_kwargs: dict[str, dict[str, int]],
    error_code: str,
) -> None:
    candidate = "https://example.test/a"
    historical = "https://example.test/history"
    root = b"root"
    skill = _skill(limits)
    acquisition = _Acquisition(
        {ROOT: root, candidate: b"x"},
        **acquisition_kwargs,
    )
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {ROOT: root, candidate: b"old a", historical: b"old history"},
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.missing == ()
    assert [item.url for item in result.failed] == [candidate]
    assert result.failed[0].error_codes == (error_code,)
    assert [item.url for item in result.unresolved] == [historical]
    assert error_code in {error.code for error in result.errors}
    assert acquisition.targets == [ROOT, candidate]
    store.close()


def test_distinct_successful_old_source_makes_recovery_incomplete_when_unreplayable(
    tmp_path: Path,
) -> None:
    sitemap = "https://example.test/sitemap"
    candidate = "https://example.test/a"
    historical = "https://example.test/history"
    root = b"root page"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(10, 65536, 30, 8)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        discovery_source_url=sitemap,
    )
    acquisition = _Acquisition(
        {sitemap: b"old source", ROOT: root, candidate: b"page a"}
    )
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(
                skill,
                {
                    sitemap: b"old source",
                    ROOT: root,
                    candidate: b"page a",
                    historical: b"old history",
                },
            ),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.refresh_complete is False
    assert result.stop_reason == "recovery_incomplete"
    assert [page.canonical_url for page in result.current_state.pages] == [
        ROOT,
        candidate,
        sitemap,
    ]
    assert [item.url for item in result.unchanged] == [ROOT, candidate, sitemap]
    assert result.missing == result.failed == ()
    assert [item.url for item in result.unresolved] == [historical]
    assert result.site_skill_update is not None
    assert result.site_skill_update.candidate.discovery_key[2] == ROOT
    assert "runtime.recovery_coverage_incomplete" in {
        error.code for error in result.errors
    }
    assert acquisition.targets == [sitemap, ROOT, candidate]
    assert any(
        attempt.requested_url == sitemap and attempt.outcome == "succeeded"
        for attempt in result.attempts
    )
    store.close()


def test_distinct_old_source_can_complete_when_selected_recipe_replays_it(
    tmp_path: Path,
) -> None:
    sitemap = "https://example.test/sitemap"
    candidate = "https://example.test/a"
    old_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.old")
    limits = Budgets(8, 65536, 30, 6)
    skill = _skill(
        limits,
        discovery_manifest=old_manifest,
        scope=_scope(sitemap),
    )
    acquisition = _Acquisition({sitemap: b"source", candidate: b"page a"})
    discovery = _StaticDiscoverySpy((candidate,), HTML_LINKS_MANIFEST)
    registry, store = _runtime(tmp_path, acquisition, discovery)

    result = run_site_refresh(
        _request(
            skill,
            _previous(skill, {sitemap: b"source", candidate: b"page a"}),
        ),
        registry,
        store,
        run_id="refresh",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.refresh_complete is True
    assert [page.canonical_url for page in result.current_state.pages] == [
        candidate,
        sitemap,
    ]
    assert result.missing == result.failed == result.unresolved == ()
    assert result.site_skill_update is not None
    assert result.site_skill_update.candidate.discovery_key[2] == sitemap
    assert acquisition.targets == [sitemap, sitemap, candidate]
    store.close()
