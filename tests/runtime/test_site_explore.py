"""Deterministic governed site-explore orchestration tests."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-lines

from __future__ import annotations

import hashlib
from asyncio import CancelledError
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import web_listening.runtime.site_explore as site_explore_runtime
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.model import ResultStatus
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.repository import SiteSkillRepository
from web_listening.site_skill.update import SiteSkillCandidate
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_LINKS_MANIFEST,
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
from web_listening.tool_registry.registry import Registry

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

    def discover(self, tool_input) -> DiscoveryOutput:
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            (self.candidate,),
            (tool_input.source_url,),
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
        _request(), registry, store, run_id="explore", clock=lambda: NOW
    )

    assert result.status is ResultStatus.COMPLETED
    assert result.exploration_complete is True
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
    candidate = result.site_skill_candidate
    assert candidate is not None
    candidate_skill = site_skill_from_mapping(candidate.to_dict())
    assert candidate_skill.discovery is not None
    assert candidate_skill.discovery.source_url == "https://example.test/"
    assert result.site_state.site_skill_digest == candidate.digest
    assert result.usage.requests == 3

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


def test_unrepresentable_discovery_url_is_terminal_and_later_candidate_runs(
    tmp_path: Path,
) -> None:
    unrepresentable_url = (
        "https://www.ipcc.ch/2026/06/25/"
        "keynote-address-ipcc-chair-jim-skea-world-climate-investment-summit/"
    )
    safe_url = "https://www.ipcc.ch/reports/overview/"
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
    serialized = result.canonical_json_bytes()
    assert unrepresentable_url.encode() not in serialized
    assert seed_body not in serialized
    store.close()


def test_all_unrepresentable_discovery_urls_return_partial_without_candidate(
    tmp_path: Path,
) -> None:
    unrepresentable_url = (
        "https://www.ipcc.ch/2026/06/25/"
        "keynote-address-ipcc-chair-jim-skea-world-climate-investment-summit/"
    )
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


def test_shared_attempt_ledger_stops_after_seed_without_resetting_per_target(
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
    store.close()


def test_seed_and_discovery_exhaust_attempt_budget_before_candidate(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition({"https://example.test/": b"<a href='/a'>a</a>"})
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

    assert result.status is ResultStatus.PARTIAL
    assert result.exploration_complete is False
    assert result.stop_reason == "budget_exhausted"
    assert result.usage.tool_attempts == 2
    assert [attempt.tool_id for attempt in result.attempts] == [
        ACQUISITION_MANIFEST.tool_id,
        HTML_LINKS_MANIFEST.tool_id,
    ]
    assert acquisition.targets == ["https://example.test/"]
    assert discovery.calls == 1
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
