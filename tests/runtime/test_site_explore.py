"""Deterministic governed site-explore orchestration tests."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-lines
# pylint: disable=too-few-public-methods

from __future__ import annotations

import hashlib
from asyncio import CancelledError
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import web_listening.runtime.site_explore as site_explore_runtime
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.attempts import Attempt
from web_listening.result.errors import SafeError
from web_listening.result.model import ResultStatus
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.workflow import prior_target_attempts, run_single_target
from web_listening.site_skill.repository import SiteSkillRepository
from web_listening.site_skill.update import SiteSkillCandidate
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_FILE_LINKS_MANIFEST,
    HTML_LINKS_MANIFEST,
    HtmlFileLinksDiscoveryTool,
    HtmlLinksDiscoveryTool,
)
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
    DiscoveryFailure,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

NOW = "2026-08-28T00:00:00Z"
ACQUISITION_MANIFEST = ToolManifest(
    "acquisition.web_http",
    "1.0.0",
    ToolCategory.ACQUISITION,
    ToolDistribution.BUILTIN,
    frozenset({"http_get"}),
    ToolLimits(30, 4096, 4096),
    HealthStatus.HEALTHY,
    QualificationStatus.QUALIFIED,
)


@dataclass
class _Acquisition:
    bodies: dict[str, bytes]
    manifest: ToolManifest = ACQUISITION_MANIFEST
    final_urls: dict[str, str] | None = None
    mime_types: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self.targets: list[str] = []
        self.budgets: list[Budgets] = []

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionOutput:
        self.targets.append(tool_input.target_url)
        self.budgets.append(tool_input.request.budgets)
        body = self.bodies[tool_input.target_url]
        final_url = (
            tool_input.target_url
            if self.final_urls is None
            else self.final_urls.get(tool_input.target_url, tool_input.target_url)
        )
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            final_url,
            200,
            (
                "text/html"
                if self.mime_types is None
                else self.mime_types[tool_input.target_url]
            ),
            body,
            hashlib.sha256(body).hexdigest(),
            (
                ()
                if final_url == tool_input.target_url
                else (AcquisitionRedirect(tool_input.target_url, final_url, 302),)
            ),
            1,
            1 if final_url == tool_input.target_url else 2,
            len(body),
        )


@dataclass
class _FailingAcquisition:
    manifest: ToolManifest = ACQUISITION_MANIFEST

    def __post_init__(self) -> None:
        self.targets: list[str] = []

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionFailure:
        self.targets.append(tool_input.target_url)
        return AcquisitionFailure(
            self.manifest.tool_id,
            self.manifest.version,
            "gateway.timeout",
        )


@dataclass
class _ScriptedAcquisition:
    outcomes: dict[str, bytes | AcquisitionFailure]
    manifest: ToolManifest = ACQUISITION_MANIFEST

    def __post_init__(self) -> None:
        self.targets: list[str] = []

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.targets.append(tool_input.target_url)
        outcome = self.outcomes[tool_input.target_url]
        if isinstance(outcome, AcquisitionFailure):
            return outcome
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            tool_input.target_url,
            200,
            "text/html",
            outcome,
            hashlib.sha256(outcome).hexdigest(),
            (),
            1,
            1,
            len(outcome),
        )


@dataclass
class _SelectiveAcquisition:
    bodies: dict[str, bytes]
    successful_targets: frozenset[str]
    manifest: ToolManifest = ACQUISITION_MANIFEST

    def __post_init__(self) -> None:
        self.targets: list[str] = []

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.targets.append(tool_input.target_url)
        if tool_input.target_url not in self.successful_targets:
            return AcquisitionFailure(
                self.manifest.tool_id,
                self.manifest.version,
                "gateway.timeout",
            )
        body = self.bodies[tool_input.target_url]
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            tool_input.target_url,
            200,
            "text/html",
            body,
            hashlib.sha256(body).hexdigest(),
            (),
            1,
            1,
            len(body),
        )


@dataclass
class _DiscoverySpy:
    max_candidates: int = 2
    manifest: ToolManifest = HTML_LINKS_MANIFEST

    def __post_init__(self) -> None:
        self.calls = 0
        self._tool = HtmlLinksDiscoveryTool(max_candidates=self.max_candidates)

    def discover(self, tool_input):
        self.calls += 1
        return self._tool.discover(tool_input)


@dataclass
class _StaticDiscovery:
    candidate: str
    manifest: ToolManifest
    coverage: str = "complete"

    def discover(self, tool_input) -> DiscoveryOutput:
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            (self.candidate,),
            (tool_input.source_url,),
            self.coverage,
        )


@dataclass
class _FailingDiscovery:
    manifest: ToolManifest = HTML_LINKS_MANIFEST
    code: str = "discovery.no_candidates"

    def discover(self, _tool_input) -> DiscoveryFailure:
        return DiscoveryFailure(
            self.manifest.tool_id,
            self.manifest.version,
            self.code,
        )


@dataclass
class _CancellingDiscovery:
    manifest: ToolManifest = HTML_LINKS_MANIFEST

    def discover(self, _tool_input):
        raise CancelledError


@dataclass
class _CancellingAcquisition:
    bodies: dict[str, bytes]
    cancel_targets: frozenset[str]
    manifest: ToolManifest = ACQUISITION_MANIFEST

    def __post_init__(self) -> None:
        self.targets: list[str] = []

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionOutput:
        self.targets.append(tool_input.target_url)
        if tool_input.target_url in self.cancel_targets:
            raise CancelledError
        body = self.bodies[tool_input.target_url]
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            tool_input.target_url,
            200,
            "text/html",
            body,
            hashlib.sha256(body).hexdigest(),
            (),
            1,
            1,
            len(body),
        )


class _FailingTransform:
    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    def __init__(self) -> None:
        self.calls = 0

    def transform(self, _tool_input: TransformInput) -> TransformFailure:
        self.calls += 1
        return TransformFailure(
            self.manifest.tool_id,
            self.manifest.version,
            "transform.fixture_failed",
        )


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


def _request(max_requests: int = 3, max_attempts: int = 4) -> Request:
    return Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(max_requests, 4096, 30, max_attempts),
    )


def _runtime(tmp_path: Path, bodies: dict[str, bytes]):
    acquisition = _Acquisition(bodies)
    discovery = HtmlLinksDiscoveryTool(max_candidates=2)
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    return acquisition, registry, store


def test_complete_exploration_builds_state_and_inactive_reusable_candidate(
    tmp_path: Path,
) -> None:
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": b"<a href='/b'>b</a><a href='/a'>a</a>",
            "https://example.test/a": b"page a",
            "https://example.test/b": b"page b",
        },
    )

    result = run_site_explore(
        _request(max_attempts=2),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.discovery[0].coverage == "complete"
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert acquisition.targets == [
        "https://example.test/",
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert [budget.max_requests for budget in acquisition.budgets] == [3, 2, 1]
    assert [budget.max_bytes for budget in acquisition.budgets] == [
        4096,
        4096 - len(b"<a href='/b'>b</a><a href='/a'>a</a>"),
        4096 - len(b"<a href='/b'>b</a><a href='/a'>a</a>") - len(b"page a"),
    ]
    assert [budget.max_runtime_seconds for budget in acquisition.budgets] == [
        30,
        29,
        29,
    ]
    assert [budget.max_tool_attempts_per_target for budget in acquisition.budgets] == [
        2,
        2,
        2,
    ]
    candidate = result.site_skill_candidate
    assert candidate is not None
    candidate_skill = site_skill_from_mapping(candidate.to_dict())
    assert candidate_skill.discovery is not None
    assert candidate_skill.discovery.source_url == "https://example.test/"
    assert result.site_state.site_skill_digest == candidate.digest
    assert result.usage.requests == 3
    assert [item.manifest.run_id for item in result.target_results] == [
        "explore-seed",
        "explore-candidate-1",
        "explore-candidate-2",
    ]
    assert [item.manifest.requested_url for item in result.target_results] == [
        "https://example.test/",
        "https://example.test/a",
        "https://example.test/b",
    ]

    reused = run_single_target(
        Request(
            candidate_skill.scope,
            candidate_skill,
            False,
            candidate_skill.budgets,
        ),
        registry,
        store,
        run_id="reuse",
        clock=lambda: NOW,
    )
    assert reused.status is ResultStatus.COMPLETED
    assert acquisition.targets[-1] == "https://example.test/"
    store.close()


def test_site_explore_target_results_run_existing_transform_for_seed_and_candidate(
    tmp_path: Path,
) -> None:
    seed_body = (
        b"<main><p>Seed page has enough visible words for markdown.</p>"
        b"<a href='/a'>Candidate page</a></main>"
    )
    candidate_body = (
        b"<main><p>Candidate page also has enough visible words.</p></main>"
    )
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": seed_body,
            "https://example.test/a": candidate_body,
        },
    )
    registry.register(
        SIMPLE_HTML_MARKDOWN_MANIFEST,
        SimpleHtmlMarkdownTransform(),
    )

    result = run_site_explore(
        _request(max_requests=2, max_attempts=3),
        registry,
        store,
        run_id="explore-transform",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert [item.manifest.run_id for item in result.target_results] == [
        "explore-transform-seed",
        "explore-transform-candidate-1",
    ]
    for target_result in result.target_results:
        source, derived = target_result.artifacts
        assert source.role == "source"
        assert source.mime_type == "text/html"
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
    assert result.usage.requests == len(result.target_results)
    assert result.usage.tool_attempts == sum(
        attempt.outcome != "skipped" for attempt in result.attempts
    )
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/a",
    ]
    assert {
        (page.observation_id, page.artifact_id) for page in result.site_state.pages
    } == {
        (item.artifacts[0].observation_id, item.artifacts[0].artifact_id)
        for item in result.target_results
    }
    assert (
        site_explore_runtime.site_explore_result_from_mapping(result.to_dict())
        == result
    )
    assert acquisition.targets == [
        "https://example.test/",
        "https://example.test/a",
    ]
    store.close()


@pytest.mark.parametrize(
    ("transform", "error_code", "stop_reason"),
    (
        (_FailingTransform(), "transform.fixture_failed", "discovery_failed"),
        (_CancellingTransform(), "runtime.cancelled", "cancelled"),
    ),
    ids=("failure", "cancellation"),
)
def test_site_explore_transform_failure_or_cancellation_preserves_source(
    tmp_path: Path,
    transform,
    error_code: str,
    stop_reason: str,
) -> None:
    body = b"<main><p>Source has enough visible words for transform.</p></main>"
    acquisition = _Acquisition({"https://example.test/": body})
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition)
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_attempts=2),
        registry,
        store,
        run_id="explore-transform-terminal",
        clock=lambda: NOW,
    )

    target_result = result.target_results[0]
    assert [artifact.role for artifact in target_result.artifacts] == ["source"]
    assert [attempt.tool_id for attempt in target_result.attempts] == [
        ACQUISITION_MANIFEST.tool_id,
        SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id,
    ]
    assert target_result.attempts[-1].outcome == "failed"
    assert target_result.attempts[-1].error is not None
    assert target_result.attempts[-1].error.code == error_code
    assert target_result.attempts[-1].requests == 0
    assert target_result.attempts[-1].bytes_received == 0
    assert error_code in {error.code for error in target_result.errors}
    assert result.stop_reason == stop_reason
    assert acquisition.targets == ["https://example.test/"]
    assert transform.calls == 1
    assert (
        site_explore_runtime.site_explore_result_from_mapping(result.to_dict())
        == result
    )
    store.close()


def test_site_explore_without_eligible_transform_keeps_source_only(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(
        {
            "https://example.test/": (
                b"<main><p>Source has enough visible words for transform.</p></main>"
            )
        }
    )
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_attempts=2),
        registry,
        store,
        run_id="explore-no-transform",
        clock=lambda: NOW,
    )

    target_result = result.target_results[0]
    assert [artifact.role for artifact in target_result.artifacts] == ["source"]
    assert [attempt.tool_id for attempt in target_result.attempts] == [
        ACQUISITION_MANIFEST.tool_id
    ]
    assert target_result.status is ResultStatus.COMPLETED
    store.close()


def test_site_explore_skips_transform_for_non_html_source(tmp_path: Path) -> None:
    body = b"%PDF-offline"
    acquisition = _Acquisition(
        {"https://example.test/": body},
        mime_types={"https://example.test/": "application/pdf"},
    )
    transform = _TransformSpy()
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition)
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)
    store = ArtifactStore(tmp_path / "artifacts")
    request = _request(max_attempts=2)
    request = replace(
        request,
        scope=replace(request.scope, content_types=(ContentType.FILE,)),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="explore-file",
        clock=lambda: NOW,
    )

    target_result = result.target_results[0]
    assert [artifact.mime_type for artifact in target_result.artifacts] == [
        "application/pdf"
    ]
    assert [attempt.tool_id for attempt in target_result.attempts] == [
        ACQUISITION_MANIFEST.tool_id
    ]
    assert transform.calls == 0
    store.close()


def test_site_explore_attempt_limit_skips_transform_after_acquisition(
    tmp_path: Path,
) -> None:
    body = b"<main><p>Source has enough visible words for transform.</p></main>"
    acquisition = _Acquisition({"https://example.test/": body})
    transform = _TransformSpy()
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition)
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_attempts=1),
        registry,
        store,
        run_id="explore-attempt-limit",
        clock=lambda: NOW,
    )

    target_result = result.target_results[0]
    assert [artifact.role for artifact in target_result.artifacts] == ["source"]
    assert len(target_result.attempts) == 1
    assert target_result.usage.tool_attempts == 1
    assert transform.calls == 0
    assert result.stop_reason == "discovery_failed"
    store.close()


def test_site_explore_transform_quality_ineligible_keeps_source(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition({"https://example.test/": b"<p>too short</p>"})
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition)
    registry.register(
        SIMPLE_HTML_MARKDOWN_MANIFEST,
        SimpleHtmlMarkdownTransform(),
    )
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_attempts=2),
        registry,
        store,
        run_id="explore-ineligible-quality",
        clock=lambda: NOW,
    )

    target_result = result.target_results[0]
    assert [artifact.role for artifact in target_result.artifacts] == ["source"]
    assert target_result.attempts[-1].error is not None
    assert target_result.attempts[-1].error.code == "transform.ineligible_quality"
    assert acquisition.targets == ["https://example.test/"]
    store.close()


def test_site_explore_preserves_truncated_discovery_coverage(tmp_path: Path) -> None:
    candidate_url = "https://example.test/a"
    acquisition = _Acquisition(
        {
            "https://example.test/": b"source page",
            candidate_url: b"candidate page",
        }
    )
    registry = Registry()
    registry.register(
        HTML_LINKS_MANIFEST,
        _StaticDiscovery(candidate_url, HTML_LINKS_MANIFEST, "truncated"),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.discovery[0].coverage == "truncated"
    store.close()


def test_live_budget_shape_completes_seed_discovery_and_two_candidates(
    tmp_path: Path,
) -> None:
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": b"<a href='/a'>a</a><a href='/b'>b</a>",
            "https://example.test/a": b"page a",
            "https://example.test/b": b"page b",
        },
    )
    request = replace(
        _request(),
        budgets=Budgets(20, 8 * 1024 * 1024, 60, 4),
    )

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.usage.tool_attempts == 4
    assert acquisition.targets == [
        "https://example.test/",
        "https://example.test/a",
        "https://example.test/b",
    ]
    store.close()


@pytest.mark.parametrize(
    ("max_requests", "max_bytes"),
    ((1, 4096), (3, len(b"<a href='/a'>a</a>"))),
)
def test_exhausted_acquisition_budget_stops_before_discovery(
    tmp_path: Path, max_requests: int, max_bytes: int
) -> None:
    body = b"<a href='/a'>a</a>"
    acquisition = _Acquisition({"https://example.test/": body})
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    request = replace(
        _request(),
        budgets=Budgets(max_requests, max_bytes, 30, 4),
    )

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert not result.discovery
    assert result.usage.tool_attempts == 1
    assert discovery.calls == 0
    assert acquisition.targets == ["https://example.test/"]
    store.close()


def test_shared_budget_stops_unprocessed_candidates_and_returns_no_candidate(
    tmp_path: Path,
) -> None:
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": b"<a href='/b'>b</a><a href='/a'>a</a>",
            "https://example.test/a": b"page a",
        },
    )

    result = run_site_explore(
        _request(2), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert result.site_state.site_skill_digest is None
    assert acquisition.targets == ["https://example.test/", "https://example.test/a"]
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/a",
    ]
    assert result.usage.requests == 2
    assert [budget.max_requests for budget in acquisition.budgets] == [2, 1]
    assert [budget.max_bytes for budget in acquisition.budgets] == [
        4096,
        4096 - len(b"<a href='/b'>b</a><a href='/a'>a</a>"),
    ]
    assert [budget.max_runtime_seconds for budget in acquisition.budgets] == [30, 29]
    assert [budget.max_tool_attempts_per_target for budget in acquisition.budgets] == [
        4,
        4,
    ]
    store.close()


def test_last_candidate_budget_failure_marks_exploration_incomplete(
    tmp_path: Path,
) -> None:
    acquisition = _ScriptedAcquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "budget.requests",
                requests=1,
            ),
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=2, max_attempts=3),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.site_state.complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert result.usage.requests == 2
    assert {error.code for error in result.errors} >= {
        "budget.requests",
        "budget.exhausted",
    }
    store.close()


def test_seed_budget_failure_returns_incomplete_budget_result(tmp_path: Path) -> None:
    acquisition = _ScriptedAcquisition(
        {
            "https://example.test/": AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "budget.runtime",
                runtime_ms=30_000,
            )
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.site_state.complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert result.usage.runtime_ms == 30_000
    assert {error.code for error in result.errors} >= {
        "budget.runtime",
        "budget.exhausted",
    }
    assert len(result.target_results) == 1
    failed = result.target_results[0]
    assert failed.manifest.run_id == "explore-seed"
    assert failed.status is ResultStatus.FAILED
    assert failed.artifacts == failed.manifest.artifacts == ()
    assert failed.errors[0].code == "budget.runtime"
    store.close()


def test_switching_eligibility_budget_terminal_marks_exploration_incomplete(
    tmp_path: Path,
) -> None:
    candidate_url = "https://example.test/a"
    preferred = _ScriptedAcquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            candidate_url: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
        }
    )
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    alternate = _ScriptedAcquisition(
        {candidate_url: b"alternate candidate"}, alternate_manifest
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        replace(
            _request(max_requests=2, max_attempts=4),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.site_state.complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert preferred.targets == ["https://example.test/", candidate_url]
    assert not alternate.targets
    assert {error.code for error in result.errors} >= {
        "eligibility.request_budget_exhausted",
        "budget.exhausted",
    }
    store.close()


def test_out_of_scope_candidate_is_rejected_before_target_read_or_observation(
    tmp_path: Path,
) -> None:
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": (
                b"<a href='https://outside.test/x'>x</a><a href='/a'>a</a>"
            ),
            "https://example.test/a": b"page a",
        },
    )

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.site_skill_candidate is not None
    assert "https://outside.test/x" not in acquisition.targets
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/a",
    ]
    rejected = next(
        item
        for item in result.target_results
        if item.manifest.requested_url == "https://outside.test/x"
    )
    assert rejected.status is ResultStatus.REJECTED
    assert rejected.artifacts == rejected.manifest.artifacts == ()
    payload = result.to_dict()
    payload["target_results"] = [
        item
        for item in payload["target_results"]
        if item["manifest"]["requested_url"] != "https://outside.test/x"
    ]
    with pytest.raises(ValueError, match="site_explore.target_results_mismatch"):
        site_explore_runtime.site_explore_result_from_mapping(payload)
    store.close()


def test_early_scope_rejections_do_not_consume_acquired_candidate_limit(
    tmp_path: Path,
) -> None:
    outside_urls = ("https://aaa.test/a", "https://bbb.test/b")
    acquisition = _Acquisition(
        {
            "https://example.test/": (
                b"<a href='https://aaa.test/a'>a</a>"
                b"<a href='https://bbb.test/b'>b</a>"
                b"<a href='/inside'>inside</a>"
            ),
            "https://example.test/inside": b"inside page",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.site_skill_candidate is not None
    assert acquisition.targets == [
        "https://example.test/",
        "https://example.test/inside",
    ]
    assert all(url not in acquisition.targets for url in outside_urls)
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/inside",
    ]
    store.close()


def test_runtime_caps_actual_candidate_acquisitions_at_two(tmp_path: Path) -> None:
    candidate_urls = tuple(
        f"https://example.test/{suffix}" for suffix in ("a", "b", "c", "d")
    )
    acquisition = _Acquisition(
        {
            "https://example.test/": b"".join(
                f"<a href='/{suffix}'>{suffix}</a>".encode()
                for suffix in ("a", "b", "c", "d")
            ),
            **{url: f"page {url[-1]}".encode() for url in candidate_urls},
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert acquisition.targets == ["https://example.test/", *candidate_urls[:2]]
    assert result.discovery[0].candidates == candidate_urls
    store.close()


def test_required_file_goal_runs_past_two_html_candidates_under_same_budget(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    candidates = tuple(
        f"{root}{name}" for name in ("a.xhtml", "a.html", "b.html", "z-report.pdf")
    )
    acquisition = _Acquisition(
        {
            root: b"<a href='/a.xhtml'>xhtml</a><a href='/a.html'>a</a>"
            b"<a href='/b.html'>b</a>"
            b"<a href='/z-report.pdf'>report</a>",
            candidates[0]: b"<main>xhtml page</main>",
            candidates[1]: b"page a",
            candidates[2]: b"page b",
            candidates[3]: b"%PDF-1.7 governed evidence",
        },
        mime_types={
            root: "text/html",
            candidates[0]: "application/xhtml+xml",
            candidates[1]: "text/html",
            candidates[2]: "text/html",
            candidates[3]: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    request = replace(
        _request(max_requests=5),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="required-file",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert acquisition.targets == [root, *sorted(candidates)]
    xhtml_target = next(
        target
        for target in result.target_results
        if target.manifest.requested_url == candidates[0]
    )
    assert xhtml_target.manifest.mime_type == "application/xhtml+xml"
    assert result.target_results[-1].manifest.mime_type == "application/pdf"
    assert result.usage.requests == 5
    store.close()


def test_required_file_goal_reaches_pdf_beyond_ordinary_discovery_bound(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    pdf_url = f"{root}z-report.pdf"
    body = (
        "".join(f"<a href=p{index:03}>" for index in range(249))
        + "<a href=z-report.pdf>"
    ).encode()
    acquisition = _Acquisition(
        {root: body, pdf_url: b"%PDF-1.7 governed evidence"},
        mime_types={root: "text/html", pdf_url: "application/pdf"},
    )
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-artifacts")
    request = replace(
        _request(max_requests=3),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="goal-aware",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert acquisition.targets == [root, pdf_url]
    assert result.target_results[-1].manifest.mime_type == "application/pdf"
    assert result.site_skill_candidate is not None
    skill = site_skill_from_mapping(result.site_skill_candidate.to_dict())
    assert skill.discovery is not None
    assert skill.discovery.tool.tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
    assert [item.tool_id for item in result.discovery] == [
        HTML_FILE_LINKS_MANIFEST.tool_id
    ]
    store.close()


def test_required_file_goal_falls_back_when_file_discovery_has_no_file_hint(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    page = f"{root}page"
    acquisition = _Acquisition({root: b"<a href='/page'>page</a>", page: b"page"})
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-fallback")
    request = replace(
        _request(max_requests=2),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="goal-aware-fallback",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert acquisition.targets == [root, page]
    assert [item.outcome for item in result.discovery] == ["succeeded"]
    assert result.site_skill_candidate is not None
    skill = site_skill_from_mapping(result.site_skill_candidate.to_dict())
    assert skill.discovery is not None
    assert skill.discovery.tool.tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
    store.close()


def test_required_file_goal_continues_after_pdf_hint_returns_html(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    false_pdf = f"{root}a.pdf"
    download = f"{root}b"
    acquisition = _Acquisition(
        {
            root: b"<a href='/a.pdf'>false</a><a href='/b' download>real</a>",
            false_pdf: b"<main>not a file</main>",
            download: b"%PDF-1.7 governed evidence",
        },
        mime_types={
            root: "text/html",
            false_pdf: "text/html",
            download: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-false-positive")
    request = replace(
        _request(max_requests=3),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="goal-aware-false-positive",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert acquisition.targets == [root, false_pdf, download]
    assert result.target_results[-1].manifest.mime_type == "application/pdf"
    store.close()


def test_required_file_goal_adopts_complete_fallback_after_goal_failure(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    file_url = f"{root}report.pdf"
    acquisition = _Acquisition(
        {
            root: b"<a href='/report.pdf'>report</a>",
            file_url: b"%PDF-1.7 governed evidence",
        },
        mime_types={root: "text/html", file_url: "application/pdf"},
    )
    registry = Registry()
    registry.register(
        HTML_FILE_LINKS_MANIFEST,
        _FailingDiscovery(HTML_FILE_LINKS_MANIFEST, "registry.tool_exception"),
    )
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-ordinary-fallback")
    request = replace(
        _request(max_requests=2),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="goal-aware-ordinary-fallback",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert acquisition.targets == [root, file_url]
    assert [item.outcome for item in result.discovery] == ["failed", "succeeded"]
    failed = next(item for item in result.discovery if item.outcome == "failed")
    assert failed.error is not None
    assert failed.error.code == "registry.tool_exception"
    failed_attempt = next(
        item
        for item in result.attempts
        if item.tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
    )
    assert failed_attempt.outcome == "failed"
    assert failed_attempt.error == failed.error
    assert "registry.tool_exception" in {error.code for error in result.errors}
    assert result.site_skill_candidate is not None
    skill = site_skill_from_mapping(result.site_skill_candidate.to_dict())
    assert skill.discovery is not None
    assert skill.discovery.tool.tool_id == HTML_LINKS_MANIFEST.tool_id
    assert (
        site_explore_runtime.site_explore_result_from_mapping(
            result.to_dict()
        ).to_dict()
        == result.to_dict()
    )
    store.close()


@pytest.mark.parametrize(
    ("false_path", "hint_markup"),
    (
        ("z.pdf", "<a href='/z.pdf'>false</a>"),
        ("a", "<a href='/a' download>false</a>"),
    ),
)
def test_required_file_goal_continues_from_false_hint_to_unhinted_file(
    tmp_path: Path,
    false_path: str,
    hint_markup: str,
) -> None:
    root = "https://example.test/"
    false_hint = f"{root}{false_path}"
    unhinted_file = f"{root}b"
    acquisition = _Acquisition(
        {
            root: f"{hint_markup}<a href='/b'>real</a>".encode(),
            false_hint: b"<main>not a file</main>",
            unhinted_file: b"%PDF-1.7 governed evidence",
        },
        mime_types={
            root: "text/html",
            false_hint: "text/html",
            unhinted_file: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "goal-aware-unhinted-file")
    request = replace(
        _request(max_requests=3),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="goal-aware-unhinted-file",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.COMPLETED
    assert acquisition.targets == [root, false_hint, unhinted_file]
    file_result = next(
        item
        for item in result.target_results
        if item.manifest.requested_url == unhinted_file
    )
    assert file_result.manifest.mime_type == "application/pdf"
    assert unhinted_file in {page.canonical_url for page in result.site_state.pages}
    store.close()


def test_required_file_goal_stops_at_budget_before_late_file(tmp_path: Path) -> None:
    root = "https://example.test/"
    candidates = tuple(f"{root}{name}" for name in ("a.html", "b.html", "z-report.pdf"))
    acquisition = _Acquisition(
        {
            root: b"<a href='/a.html'>a</a><a href='/b.html'>b</a>"
            b"<a href='/z-report.pdf'>report</a>",
            candidates[0]: b"page a",
            candidates[1]: b"page b",
            candidates[2]: b"%PDF-1.7 governed evidence",
        },
        mime_types={
            root: "text/html",
            candidates[0]: "text/html",
            candidates[1]: "text/html",
            candidates[2]: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    request = replace(
        _request(max_requests=3),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="required-file-budget",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert acquisition.targets == [root, *candidates[:2]]
    assert result.usage.requests == 3
    assert "budget.exhausted" in {error.code for error in result.errors}
    store.close()


@pytest.mark.parametrize(
    "code",
    (
        "scope.content_type_not_allowed",
        "gateway.robots",
        "gateway.https_downgrade",
    ),
)
def test_required_file_goal_stops_on_candidate_policy_rejection(
    tmp_path: Path,
    code: str,
) -> None:
    root = "https://example.test/"
    blocked = f"{root}a-blocked"
    file_url = f"{root}z-report.pdf"
    acquisition = _ScriptedAcquisition(
        {
            root: b"<a href='/a-blocked'>blocked</a>"
            b"<a href='/z-report.pdf'>report</a>",
            blocked: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                code,
                requests=1,
            ),
            file_url: b"unreachable file",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / code.replace(".", "-"))
    request = replace(
        _request(max_requests=4),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="required-file-rejected",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.REJECTED
    assert result.stop_reason == "rejected"
    assert acquisition.targets == [root, blocked]
    assert result.attempts[-1].error is not None
    assert result.attempts[-1].error.code == code
    assert code in {error.code for error in result.errors}
    assert all(
        target.manifest.requested_url != file_url for target in result.target_results
    )
    store.close()


def test_required_file_goal_stops_on_pre_acquisition_scope_rejection(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    blocked = "https://aaa.test/a-blocked"
    file_url = f"{root}z-report.pdf"
    acquisition = _Acquisition(
        {
            root: f"<a href='{blocked}'>blocked</a>".encode()
            + b"<a href='/z-report.pdf'>report</a>",
            file_url: b"%PDF-1.7 unreachable",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "scope-rejected")
    request = replace(
        _request(max_requests=4),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="required-file-scope-rejected",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.REJECTED
    assert result.stop_reason == "rejected"
    assert acquisition.targets == [root]
    rejected = result.target_results[-1]
    assert rejected.manifest.requested_url == blocked
    assert rejected.attempts == ()
    assert rejected.errors[0].code == "scope.origin_not_allowed"
    assert result.usage.requests == 1
    assert all(
        target.manifest.requested_url != file_url for target in result.target_results
    )
    store.close()


def test_required_file_goal_applies_full_scope_before_site_identity(
    tmp_path: Path,
) -> None:
    root = "https://example.test/"
    blocked = "https://aaa.test/blocked"
    file_url = f"{root}allowed/z-report.pdf"
    acquisition = _Acquisition(
        {
            root: f"<a href='{blocked}'>blocked</a>".encode()
            + b"<a href='/allowed/z-report.pdf'>report</a>",
            file_url: b"%PDF-1.7 must remain unreachable",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "path-rejected-before-identity")
    request = replace(
        _request(max_requests=4),
        scope=Scope(
            (root,),
            ("https://aaa.test", "https://example.test"),
            ("/", "/allowed/**"),
            (ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="required-file-path-rejected",
        clock=lambda: NOW,
        require_file=True,
    )

    assert result.status is ResultStatus.REJECTED
    assert result.stop_reason == "rejected"
    assert acquisition.targets == [root]
    assert [item.manifest.requested_url for item in result.target_results] == [
        root,
        blocked,
    ]
    rejected = result.target_results[-1]
    assert rejected.attempts == ()
    assert [error.code for error in rejected.errors] == ["scope.path_not_included"]
    assert "runtime.site_identity_mismatch" not in {
        error.code for error in result.errors
    }
    assert all(
        target.manifest.requested_url != file_url for target in result.target_results
    )
    store.close()


def test_unrepresentable_discovery_url_is_terminal_and_later_candidate_runs(
    tmp_path: Path,
) -> None:
    safe_url = (
        "https://www.ipcc.ch/2026/06/25/"
        "keynote-address-ipcc-chair-jim-skea-world-climate-investment-summit/"
    )
    unrepresentable_url = "https://www.ipcc.ch/private/sk-abcdefghijklmnop"
    seed_body = (
        f"<a href='{unrepresentable_url}'>unsafe</a>" f"<a href='{safe_url}'>safe</a>"
    ).encode()
    request = Request(
        Scope(
            ("https://www.ipcc.ch/",),
            ("https://www.ipcc.ch",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition(
        {
            "https://www.ipcc.ch/": seed_body,
            safe_url: b"safe candidate page",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.site_skill_candidate is not None
    assert acquisition.targets == ["https://www.ipcc.ch/", safe_url]
    assert result.discovery[0].candidates == (safe_url,)
    assert result.discovery[0].discovered_from == ("https://www.ipcc.ch/",)
    assert "runtime.discovery_url_unrepresentable" in {
        error.code for error in result.errors
    }
    assert any(attempt.requested_url == safe_url for attempt in result.attempts)
    serialized = result.canonical_json_bytes()
    assert safe_url.encode() in serialized
    assert unrepresentable_url.encode() not in serialized
    assert seed_body not in serialized
    store.close()


def test_all_unrepresentable_discovery_urls_return_partial_without_candidate(
    tmp_path: Path,
) -> None:
    unrepresentable_url = "https://www.ipcc.ch/private/github_pat_abcdefghijklmnop"
    seed_body = f"<a href='{unrepresentable_url}'>unsafe</a>".encode()
    request = Request(
        Scope(
            ("https://www.ipcc.ch/",),
            ("https://www.ipcc.ch",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition({"https://www.ipcc.ch/": seed_body})
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "discovery_failed"
    assert result.site_skill_candidate is None
    assert acquisition.targets == ["https://www.ipcc.ch/"]
    assert result.discovery[0].outcome == "failed"
    assert result.discovery[0].candidates == ()
    assert result.attempts[-1].outcome == "failed"
    assert "runtime.discovery_url_unrepresentable" in {
        error.code for error in result.errors
    }
    serialized = result.canonical_json_bytes()
    assert unrepresentable_url.encode() not in serialized
    assert seed_body not in serialized
    store.close()


def test_discovery_stops_when_its_source_target_has_no_attempts_remaining(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition({"https://example.test/": b"<a href='/a'>a</a>"})
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=3, max_attempts=1),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.tool_attempts == 1
    assert acquisition.targets == ["https://example.test/"]
    assert discovery.calls == 0
    assert result.site_skill_candidate is None
    assert "discovery.no_candidates" not in {error.code for error in result.errors}
    store.close()


def test_discovery_source_attempt_limit_does_not_block_discovered_candidate(
    tmp_path: Path,
) -> None:
    second_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.second")
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": b"page a",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(
        second_manifest,
        _StaticDiscovery("https://example.test/b", second_manifest),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=2, max_attempts=2),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert [evidence.tool_id for evidence in result.discovery] == [
        HTML_LINKS_MANIFEST.tool_id
    ]
    assert acquisition.targets == [
        "https://example.test/",
        "https://example.test/a",
    ]
    assert result.attempts[-1].requested_url == "https://example.test/a"
    assert result.attempts[-1].outcome == "succeeded"
    store.close()


def test_seed_and_discovery_attempts_do_not_reduce_new_candidate_budget(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": b"page a",
        }
    )
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=3, max_attempts=2),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.stop_reason == "source_exhausted"
    assert result.site_skill_candidate is not None
    assert result.usage.tool_attempts == 3
    assert [attempt.tool_id for attempt in result.attempts] == [
        ACQUISITION_MANIFEST.tool_id,
        HTML_LINKS_MANIFEST.tool_id,
        ACQUISITION_MANIFEST.tool_id,
    ]
    assert acquisition.targets == [
        "https://example.test/",
        "https://example.test/a",
    ]
    assert [budget.max_tool_attempts_per_target for budget in acquisition.budgets] == [
        2,
        2,
    ]
    assert discovery.calls == 1
    store.close()


def test_candidate_attempt_limit_is_independent_and_skips_do_not_consume_it(
    tmp_path: Path,
) -> None:
    candidate_a = "https://example.test/a"
    candidate_b = "https://example.test/b"
    preferred = _ScriptedAcquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a><a href='/b'>b</a>",
            candidate_a: AcquisitionFailure(
                ACQUISITION_MANIFEST.tool_id,
                ACQUISITION_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            ),
            candidate_b: b"page b",
        }
    )
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    alternate = _ScriptedAcquisition(
        {
            candidate_a: AcquisitionFailure(
                alternate_manifest.tool_id,
                alternate_manifest.version,
                "gateway.timeout",
                requests=1,
            )
        },
        alternate_manifest,
    )
    unqualified_manifest = replace(
        ACQUISITION_MANIFEST,
        tool_id="acquisition.unqualified",
        qualification=QualificationStatus.UNQUALIFIED,
    )
    unqualified = _FailingAcquisition(unqualified_manifest)
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    registry.register(unqualified_manifest, unqualified)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        replace(
            _request(max_requests=4, max_attempts=2),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert preferred.targets == ["https://example.test/", candidate_a, candidate_b]
    assert alternate.targets == [candidate_a]
    assert not unqualified.targets
    candidate_a_attempts = tuple(
        attempt for attempt in result.attempts if attempt.requested_url == candidate_a
    )
    assert [attempt.outcome for attempt in candidate_a_attempts] == [
        "failed",
        "skipped",
        "failed",
    ]
    assert sum(attempt.outcome != "skipped" for attempt in candidate_a_attempts) == 2
    assert result.attempts[-1].requested_url == candidate_b
    assert result.attempts[-1].outcome == "succeeded"
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        candidate_b,
    ]
    assert "eligibility.attempt_budget_exhausted" in {
        error.code for error in result.errors
    }
    assert result.usage.requests == 4
    store.close()


def test_exhausted_canonical_candidate_does_not_stop_fresh_candidate(
    tmp_path: Path,
) -> None:
    seed_target = "https://example.test/a"
    source_url = "https://example.test/"
    fresh_candidate = "https://example.test/b"
    acquisition = _Acquisition(
        {
            seed_target: b"<a href='/a'>a</a><a href='/b'>b</a>",
            fresh_candidate: b"page b",
        },
        final_urls={seed_target: source_url},
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    request = replace(
        _request(max_requests=3, max_attempts=1),
        scope=replace(_request().scope, seeds=(seed_target,)),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert acquisition.targets == [seed_target, fresh_candidate]
    assert [attempt.requested_url for attempt in result.attempts] == [
        seed_target,
        source_url,
        fresh_candidate,
    ]
    assert [budget.max_tool_attempts_per_target for budget in acquisition.budgets] == [
        1,
        1,
    ]
    assert result.usage.requests == 3
    store.close()


def test_zero_attempt_budget_candidate_cannot_be_omitted(tmp_path: Path) -> None:
    candidate = "https://example.test/a"
    acquisition, registry, store = _runtime(
        tmp_path,
        {"https://example.test/": b"<a href='/a'>a</a>"},
    )
    prior = tuple(
        Attempt(
            index,
            f"prior-candidate-attempt-{index + 1}",
            "failed",
            ACQUISITION_MANIFEST.tool_id,
            ACQUISITION_MANIFEST.version,
            NOW,
            NOW,
            candidate,
            None,
            None,
            SafeError("gateway.timeout", "Acquisition did not complete."),
            1,
            0,
            0,
        )
        for index in range(2)
    )

    with prior_target_attempts(prior):
        result = run_site_explore(
            _request(max_requests=3, max_attempts=2),
            registry,
            store,
            run_id="explore",
            clock=lambda: NOW,
        )

    blocked = result.target_results[-1]
    assert acquisition.targets == ["https://example.test/"]
    assert blocked.manifest.requested_url == candidate
    assert blocked.attempts == ()
    assert [error.code for error in blocked.errors] == [
        "eligibility.attempt_budget_exhausted"
    ]
    payload = result.to_dict()
    payload["target_results"].pop()
    with pytest.raises(ValueError, match="site_explore.target_results_mismatch"):
        site_explore_runtime.site_explore_result_from_mapping(payload)
    store.close()


def test_slow_discovery_consumes_runtime_and_stops_candidates(
    tmp_path: Path, monkeypatch
) -> None:
    acquisition = _Acquisition({"https://example.test/": b"<a href='/a'>a</a>"})
    discovery = _DiscoverySpy()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    ticks = iter((0, 1_000_000_000))
    monkeypatch.setattr(site_explore_runtime, "monotonic_ns", lambda: next(ticks))

    result = run_site_explore(
        replace(
            _request(max_requests=3, max_attempts=3),
            budgets=Budgets(3, 4096, 1, 3),
        ),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.runtime_ms >= 1_000
    assert result.usage.tool_attempts == 2
    assert acquisition.targets == ["https://example.test/"]
    store.close()


def test_slow_successful_discovery_exhausts_budget_before_identity_terminal(
    tmp_path: Path, monkeypatch
) -> None:
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test", "https://other.test"),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition({"https://example.test/": b"source page"})
    registry = Registry()
    registry.register(
        HTML_LINKS_MANIFEST,
        _StaticDiscovery("https://other.test/a", HTML_LINKS_MANIFEST),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    ticks = iter((0, 31_000_000_000))
    monkeypatch.setattr(site_explore_runtime, "monotonic_ns", lambda: next(ticks))

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.runtime_ms == 31_001
    assert result.discovery[0].outcome == "succeeded"
    assert result.attempts[-1].outcome == "succeeded"
    assert "budget.exhausted" in {error.code for error in result.errors}
    assert acquisition.targets == ["https://example.test/"]
    store.close()


def test_slow_failed_discovery_exhausts_budget_with_failure_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    acquisition = _Acquisition({"https://example.test/": b"source page"})
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, _FailingDiscovery())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    ticks = iter((0, 31_000_000_000))
    monkeypatch.setattr(site_explore_runtime, "monotonic_ns", lambda: next(ticks))

    result = run_site_explore(
        replace(
            _request(max_requests=3, max_attempts=3),
            budgets=Budgets(3, 4096, 30, 3),
        ),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.runtime_ms == 31_001
    assert result.discovery[0].outcome == "failed"
    assert result.attempts[-1].outcome == "failed"
    assert {"budget.exhausted", "discovery.no_candidates"} <= {
        error.code for error in result.errors
    }
    assert acquisition.targets == ["https://example.test/"]
    store.close()


@pytest.mark.parametrize(
    "code",
    (
        "budget.bytes",
        "budget.requests",
        "budget.runtime",
        "eligibility.attempt_budget_exhausted",
        "eligibility.byte_budget_exhausted",
        "eligibility.request_budget_exhausted",
        "eligibility.runtime_budget_exhausted",
    ),
)
def test_discovery_budget_failure_is_budget_terminal(tmp_path: Path, code: str) -> None:
    acquisition = _Acquisition({"https://example.test/": b"source page"})
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, _FailingDiscovery(code=code))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=3, max_attempts=3),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.site_state.complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.site_skill_candidate is None
    assert {error.code for error in result.errors} >= {code, "budget.exhausted"}
    assert result.discovery[0].error is not None
    assert result.discovery[0].error.code == code
    assert result.attempts[-1].error is not None
    assert result.attempts[-1].error.code == code
    store.close()


def test_discovery_cancellation_returns_partial_audited_result(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition({"https://example.test/": b"<a href='/a'>a</a>"})
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, _CancellingDiscovery())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=3, max_attempts=2),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "cancelled"
    assert result.site_skill_candidate is None
    assert result.attempts[-1].tool_id == HTML_LINKS_MANIFEST.tool_id
    assert result.attempts[-1].outcome == "failed"
    assert result.attempts[-1].error is not None
    assert result.attempts[-1].error.code == "runtime.cancelled"
    assert result.usage.tool_attempts == 2
    store.close()


def test_seed_acquisition_cancellation_returns_partial_audited_result(
    tmp_path: Path,
) -> None:
    acquisition = _CancellingAcquisition({}, frozenset({"https://example.test/"}))
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=3, max_attempts=2),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "cancelled"
    assert result.site_skill_candidate is None
    assert len(result.attempts) == 1
    assert result.attempts[0].outcome == "failed"
    assert result.attempts[0].error is not None
    assert result.attempts[0].error.code == "runtime.cancelled"
    assert result.usage.tool_attempts == 1
    store.close()


def test_candidate_acquisition_cancellation_preserves_prior_evidence(
    tmp_path: Path,
) -> None:
    acquisition = _CancellingAcquisition(
        {"https://example.test/": b"<a href='/a'>a</a>"},
        frozenset({"https://example.test/a"}),
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=3, max_attempts=3),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "cancelled"
    assert result.site_skill_candidate is None
    assert [attempt.outcome for attempt in result.attempts] == [
        "succeeded",
        "succeeded",
        "failed",
    ]
    assert result.attempts[-1].error is not None
    assert result.attempts[-1].error.code == "runtime.cancelled"
    assert result.usage.tool_attempts == 3
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/"
    ]
    store.close()


def test_all_terminal_candidate_rejections_can_complete_without_candidate(
    tmp_path: Path,
) -> None:
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": (
                b"<a href='https://outside.test/a'>a</a>"
                b"<a href='https://outside.test/b'>b</a>"
            )
        },
    )

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is True
    assert result.site_state.complete is True
    assert result.site_skill_candidate is None
    assert acquisition.targets == ["https://example.test/"]
    assert {error.code for error in result.errors} == {"scope.origin_not_allowed"}
    store.close()


def test_candidate_redirect_uses_requested_url_as_discovery_proof(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/report'>report</a>",
            "https://example.test/report": b"report body",
        },
        final_urls={"https://example.test/report": "https://example.test/report/"},
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.site_skill_candidate is not None
    assert result.attempts[-1].requested_url == "https://example.test/report"
    assert result.attempts[-1].final_url == "https://example.test/report/"
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/report/",
    ]
    candidate = result.target_results[-1]
    assert candidate.manifest.requested_url == "https://example.test/report"
    assert candidate.manifest.final_url == "https://example.test/report/"
    assert candidate.manifest.mime_type == "text/html"
    assert [item.to_url for item in candidate.manifest.redirects] == [
        "https://example.test/report/"
    ]
    store.close()


def test_redirected_pdf_manifest_is_public_without_parsing_body(
    tmp_path: Path,
) -> None:
    requested = "https://example.test/report.pdf"
    redirected = "https://example.test/download/report.pdf"
    acquisition = _Acquisition(
        {
            "https://example.test/": b"source page",
            requested: b"%PDF-offline",
        },
        final_urls={requested: redirected},
        mime_types={
            "https://example.test/": "text/html",
            requested: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(
        HTML_LINKS_MANIFEST,
        _StaticDiscovery(requested, HTML_LINKS_MANIFEST),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    request = _request()
    request = replace(
        request,
        scope=replace(
            request.scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )
    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    pdf = result.target_results[-1]
    assert pdf.status is ResultStatus.COMPLETED
    assert pdf.manifest.requested_url == requested
    assert pdf.manifest.final_url == redirected
    assert pdf.manifest.http_status == 200
    assert pdf.manifest.mime_type == "application/pdf"
    assert [item.to_url for item in pdf.manifest.redirects] == [redirected]
    assert [item.mime_type for item in pdf.artifacts] == ["application/pdf"]
    assert b"%PDF-offline" not in result.canonical_json_bytes()
    store.close()


def test_seed_redirect_defines_site_identity_from_successful_final_source(
    tmp_path: Path,
) -> None:
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test", "https://www.example.test"),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://www.example.test/a": b"page a",
        },
        final_urls={"https://example.test/": "https://www.example.test/"},
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.site_state.site_key == "www.example.test"
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://www.example.test/",
        "https://www.example.test/a",
    ]
    store.close()


def test_different_allowed_site_candidate_is_safe_terminal_rejection(
    tmp_path: Path,
) -> None:
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test", "https://other.test"),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition(
        {
            "https://example.test/": (
                b"<a href='/a'>a</a>" b"<a href='https://other.test/b'>b</a>"
            ),
            "https://example.test/a": b"page a",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
    assert result.site_skill_candidate is not None
    assert "https://other.test/b" not in acquisition.targets
    assert "runtime.site_identity_mismatch" in {error.code for error in result.errors}
    store.close()


def test_identity_gap_rejects_forged_zero_attempt_candidate(tmp_path: Path) -> None:
    foreign_candidate = "https://aaa.test/b"
    local_candidate = "https://example.test/a"
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://aaa.test", "https://example.test"),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition(
        {
            "https://example.test/": (
                b"<a href='https://aaa.test/b'>b</a><a href='/a'>a</a>"
            ),
            local_candidate: b"page a",
        }
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(request, registry, store, run_id="gap", clock=lambda: NOW)

    assert [item.manifest.run_id for item in result.target_results] == [
        "gap-seed",
        "gap-candidate-2",
    ]
    assert (
        site_explore_runtime.site_explore_result_from_mapping(result.to_dict())
        == result
    )
    identity_error = next(
        error
        for error in result.errors
        if error.code == "runtime.site_identity_mismatch"
    )
    forged = run_single_target(
        request,
        Registry(),
        store,
        run_id="gap-candidate-1",
        clock=lambda: NOW,
        target_url=foreign_candidate,
    )
    assert not forged.attempts
    forged = replace(forged, errors=(identity_error,))
    payload = result.to_dict()
    payload["target_results"].insert(1, forged.to_dict())

    with pytest.raises(ValueError, match="site_explore.target_results_mismatch"):
        site_explore_runtime.site_explore_result_from_mapping(payload)
    store.close()


def test_candidate_final_site_identity_mismatch_is_excluded_but_audited(
    tmp_path: Path,
) -> None:
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test", "https://other.test"),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(3, 4096, 30, 3),
    )
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": b"other page",
        },
        final_urls={"https://example.test/a": "https://other.test/a"},
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is True
    assert result.site_skill_candidate is None
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/"
    ]
    assert result.attempts[-1].requested_url == "https://example.test/a"
    assert result.attempts[-1].final_url == "https://other.test/a"
    identity_error = next(
        error
        for error in result.errors
        if error.code == "runtime.site_identity_mismatch"
    )
    details = dict(identity_error.details)
    assert details["final_url"] == "https://other.test/a"
    assert store.read_artifact(details["artifact_id"]).content == b"other page"
    assert store.get_observation(details["observation_id"]).observation.source_url == (
        "https://other.test/a"
    )
    store.close()


def test_converged_candidate_final_urls_are_deduplicated_in_site_state(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a><a href='/b'>b</a>",
            "https://example.test/a": b"page a",
            "https://example.test/b": b"page b",
        },
        final_urls={
            "https://example.test/a": "https://example.test/final",
            "https://example.test/b": "https://example.test/final",
        },
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        replace(_request(), budgets=Budgets(5, 4096, 30, 4)),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        "https://example.test/final",
    ]
    assert [attempt.final_url for attempt in result.attempts[-2:]] == [
        "https://example.test/final",
        "https://example.test/final",
    ]
    assert result.usage.requests == 5
    store.close()


def test_candidate_requires_one_tool_successful_for_seed_and_candidate(
    tmp_path: Path,
) -> None:
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    seed_only = _SelectiveAcquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
        },
        frozenset({"https://example.test/"}),
    )
    candidate_only = _SelectiveAcquisition(
        {"https://example.test/a": b"page a"},
        frozenset({"https://example.test/a"}),
        alternate_manifest,
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, seed_only)
    registry.register(alternate_manifest, candidate_only)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        replace(
            _request(max_requests=2, max_attempts=4),
            explore_all_tools=True,
        ),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is True
    assert result.site_skill_candidate is None
    assert "runtime.site_skill_tool_unverified" in {
        error.code for error in result.errors
    }
    assert seed_only.targets == ["https://example.test/", "https://example.test/a"]
    assert candidate_only.targets == ["https://example.test/a"]
    store.close()


def test_candidate_recipe_uses_successful_candidate_discovery_provenance(
    tmp_path: Path,
) -> None:
    first_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.first")
    second_manifest = replace(HTML_LINKS_MANIFEST, tool_id="discovery.second")
    acquisition = _SelectiveAcquisition(
        {
            "https://example.test/": b"source page",
            "https://example.test/b-ok": b"candidate page",
        },
        frozenset(
            {
                "https://example.test/",
                "https://example.test/b-ok",
            }
        ),
    )
    registry = Registry()
    registry.register(
        first_manifest,
        _StaticDiscovery("https://example.test/a-fail", first_manifest),
    )
    registry.register(
        second_manifest,
        _StaticDiscovery("https://example.test/b-ok", second_manifest),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        replace(_request(), budgets=Budgets(3, 4096, 30, 5)),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    candidate = result.site_skill_candidate
    assert candidate is not None
    candidate_skill = site_skill_from_mapping(candidate.to_dict())
    assert candidate_skill.discovery is not None
    assert candidate_skill.discovery.tool.tool_id == second_manifest.tool_id
    assert candidate_skill.discovery.source_url == "https://example.test/"
    reused = run_single_target(
        Request(candidate_skill.scope, candidate_skill, False, candidate_skill.budgets),
        registry,
        store,
        run_id="reuse",
        clock=lambda: NOW,
    )
    assert reused.status is ResultStatus.COMPLETED
    store.close()


def test_complete_mixed_html_and_file_builds_replayable_candidate(
    tmp_path: Path,
) -> None:
    file_url = "https://example.test/report.pdf"
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/report.pdf'>report</a>",
            file_url: b"%PDF-1.7 offline evidence",
        },
        mime_types={
            "https://example.test/": "text/html",
            file_url: "application/pdf",
        },
    )
    registry = Registry()
    registry.register(
        HTML_LINKS_MANIFEST,
        _StaticDiscovery(file_url, HTML_LINKS_MANIFEST),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts-mixed-candidate")
    request = replace(
        _request(max_requests=2, max_attempts=3),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="explore-mixed-candidate",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.site_skill_candidate is not None
    assert result.discovery[0].candidates == (file_url,)
    assert [item.manifest.mime_type for item in result.target_results] == [
        "text/html",
        "application/pdf",
    ]
    candidate = site_skill_from_mapping(result.site_skill_candidate.to_dict())
    assert candidate.success_checks.allowed_mime_types == (
        "application/pdf",
        "text/html",
    )
    assert [page.canonical_url for page in result.site_state.pages] == [
        "https://example.test/",
        file_url,
    ]
    store.close()


def test_candidate_body_must_pass_actual_stored_success_checks(tmp_path: Path) -> None:
    acquisition, registry, store = _runtime(
        tmp_path,
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": b"",
        },
    )

    result = run_site_explore(
        _request(max_requests=2, max_attempts=3),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is True
    assert result.site_skill_candidate is None
    assert "runtime.quality_minimum_words" in {error.code for error in result.errors}
    assert acquisition.targets == ["https://example.test/", "https://example.test/a"]
    store.close()


def test_candidate_checks_preserve_observed_seed_and_candidate_mime_types(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": b"candidate page",
        },
        mime_types={
            "https://example.test/": "text/html",
            "https://example.test/a": "application/xhtml+xml",
        },
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    request = replace(
        _request(max_requests=2, max_attempts=3),
        scope=replace(
            _request().scope,
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
    )
    result = run_site_explore(
        request,
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.COMPLETED
    evidence = result.site_skill_candidate
    assert evidence is not None
    parsed = site_skill_from_mapping(evidence.to_dict())
    repository = SiteSkillRepository()
    repository.submit(SiteSkillCandidate(parsed))
    saved = repository.candidate(parsed.site_key, parsed.digest)
    assert saved is not None
    assert saved.success_checks.allowed_mime_types == (
        "application/xhtml+xml",
        "text/html",
    )
    reused = run_single_target(
        Request(saved.scope, saved, False, saved.budgets),
        registry,
        store,
        run_id="reuse",
        clock=lambda: NOW,
    )
    assert reused.status is ResultStatus.COMPLETED
    store.close()


def test_empty_stored_seed_cannot_create_replayable_candidate(tmp_path: Path) -> None:
    acquisition = _Acquisition(
        {
            "https://example.test/": b"",
            "https://example.test/a": b"candidate page",
        }
    )
    registry = Registry()
    registry.register(
        HTML_LINKS_MANIFEST,
        _StaticDiscovery("https://example.test/a", HTML_LINKS_MANIFEST),
    )
    registry.register(ACQUISITION_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_site_explore(
        _request(max_requests=2, max_attempts=3),
        registry,
        store,
        run_id="explore",
        clock=lambda: NOW,
    )

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is True
    assert result.site_skill_candidate is None
    assert "runtime.quality_minimum_words" in {error.code for error in result.errors}
    store.close()


def test_eligible_tool_switching_failures_remain_auditable_on_completed_explore(
    tmp_path: Path,
) -> None:
    alternate_manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.alternate")
    alternate = _Acquisition(
        {
            "https://example.test/": b"<a href='/a'>a</a>",
            "https://example.test/a": b"page a",
        },
        alternate_manifest,
    )
    preferred = _FailingAcquisition()
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool(max_candidates=2))
    registry.register(ACQUISITION_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "switching-artifacts")
    request = replace(_request(max_requests=2, max_attempts=5), explore_all_tools=True)

    result = run_site_explore(
        request, registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "succeeded",
        "succeeded",
        "failed",
        "succeeded",
    ]
    assert result.usage.tool_attempts == 5
    assert {error.code for error in result.errors} == {"gateway.timeout"}
    candidate = result.site_skill_candidate
    assert candidate is not None
    candidate_skill = site_skill_from_mapping(candidate.to_dict())
    assert candidate_skill.tool.tool_id == alternate_manifest.tool_id
    assert (
        preferred.targets
        == alternate.targets
        == [
            "https://example.test/",
            "https://example.test/a",
        ]
    )
    reused = run_single_target(
        Request(candidate_skill.scope, candidate_skill, False, candidate_skill.budgets),
        registry,
        store,
        run_id="reuse",
        clock=lambda: NOW,
    )
    assert reused.status is ResultStatus.COMPLETED
    store.close()
