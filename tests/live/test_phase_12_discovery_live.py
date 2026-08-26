"""Explicitly authorized Phase 12 Discovery canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-locals

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import pytest

import web_listening.tool_registry.acquisition.builtins.web_http as web_http_module
from web_listening.artifact.model import StoredObservation
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Request, Scope
from web_listening.result.model import ResultStatus
from web_listening.runtime.workflow import (
    DiscoveredCandidateResult,
    acquire_discovered_candidates,
    discover_candidates,
)
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.rss import (
    RSS_MANIFEST,
    RssDiscoveryTool,
)
from web_listening.tool_registry.discovery.builtins.sitemap import (
    SITEMAP_MANIFEST,
    SitemapDiscoveryTool,
)
from web_listening.tool_registry.manifest import ToolRegistryError
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryOutput,
    validate_url,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import (
    GatewayEvidence,
    GatewayFailure,
    GatewayResult,
    GovernedAccessGateway,
    PinnedHttpTransport,
    TransportResponse,
)

TARGETS = Path(__file__).with_name("phase_12_site_targets.json")
SOURCE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SITE_SKILLS = Path(__file__).parent / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-13-2026-08-26-user-authorized-iea"
OFFLINE_FEED_URL = "https://www.iea.org/news/feed.xml"


def _newline_canonical_sha256(content: bytes) -> str:
    text = content.decode("utf-8").replace("\r\n", "\n")
    canonical = text.replace("\n", "\r\n").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _expected_target() -> dict[str, object]:
    return {
        "site_key": "iea",
        "display_name": "International Energy Agency",
        "seed_field": "tree_seed_url",
        "seed_url": "https://www.iea.org/news",
        "allowed_origins": ["https://iea.org", "https://www.iea.org"],
        "historical_expectation": "pass_http",
        "site_skill_case": "iea",
        "site_skill_digest": (
            "sha256:4ef9b4cdfa165b09fd81d98681a9253081c5d3fda47c376b2cc419470e236a55"
        ),
        "provenance": {
            "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
            "old_path": "config/smoke_site_catalog.json",
            "old_blob": "e50b2c0d29e1b3c5df6473409c1a33ad4ffee4c4",
            "old_site_key": "iea",
        },
    }


def _load_snapshot() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    payload = json.loads(TARGETS.read_bytes())
    targets = payload.get("targets")
    if not isinstance(targets, list) or targets != [_expected_target()]:
        pytest.fail("Phase 12 must retain the exact audited IEA projection")
    limits = {
        "max_seeds": 1,
        "max_feeds": 2,
        "max_acquired_candidates": 2,
        "max_total_requests": 12,
        "max_total_bytes": 4 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
        "fallback": 0,
    }
    if payload.get("network_limits") != limits:
        pytest.fail("Phase 12 network limits drifted")
    expected_digest = str(payload.get("source_catalog_sha256", "")).lower()
    if _newline_canonical_sha256(SOURCE_CATALOG.read_bytes()) != expected_digest:
        pytest.fail("Phase 12 source catalog digest drifted")
    cases = json.loads(SITE_SKILLS.read_bytes()).get("cases")
    case = next(
        (item for item in cases if item.get("site_key") == "iea"),
        None,
    )
    if not isinstance(case, dict):
        pytest.fail("audited IEA Site Skill is missing")
    return payload, targets[0], case


def _load_authorized_snapshot():
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 12 Discovery live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 12 authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "iea").strip() or "iea"
    if selector != "iea":
        pytest.fail("WEB_LISTENING_LIVE_SITE must be the frozen iea key")
    return _load_snapshot()


class _EndpointParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.endpoints: set[tuple[str, str]] = set()

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.casefold() != "link":
            return
        values = {str(key).casefold(): str(value) for key, value in attrs if value}
        relations = {item.casefold() for item in values.get("rel", "").split()}
        mime_type = values.get("type", "").casefold()
        kind = (
            "rss"
            if "alternate" in relations
            and mime_type in {"application/rss+xml", "application/atom+xml"}
            else None
        )
        if kind and values.get("href"):
            self.endpoints.add(
                (validate_url(urljoin(self.base_url, values["href"])), kind)
            )


def _html_endpoints(body: bytes, source_url: str) -> set[tuple[str, str]]:
    parser = _EndpointParser(source_url)
    parser.feed(body.decode("utf-8", errors="replace"))
    return parser.endpoints


def _selected_html_endpoints(
    request: Request, body: bytes, source_url: str, max_feeds: int
) -> tuple[tuple[str, str], ...]:
    selected = []
    for endpoint in sorted(_html_endpoints(body, source_url)):
        try:
            AcquisitionInput(request, endpoint[0])
        except ToolRegistryError:
            continue
        selected.append(endpoint)
        if len(selected) == max_feeds:
            break
    return tuple(selected)


class _NetworkBudget:  # pylint: disable=too-few-public-methods
    def __init__(self, max_requests: int, max_bytes: int) -> None:
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.requests = 0
        self.bytes = 0


class _CappedResponse:
    def __init__(self, response: TransportResponse, budget: _NetworkBudget) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_bytes - self._budget.bytes
        if remaining <= 0:
            raise TimeoutError
        content = self._response.read(min(max_bytes, remaining))
        self._budget.bytes += len(content)
        return content

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(self, budget: _NetworkBudget) -> None:
        self._budget = budget
        self._transport = PinnedHttpTransport()

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        if self._budget.requests >= self._budget.max_requests:
            raise TimeoutError
        self._budget.requests += 1
        return _CappedResponse(
            self._transport.send(url, timeout=timeout, addresses=addresses),
            self._budget,
        )

    def close(self) -> None:
        self._transport.close()


class _RecordingGateway(GovernedAccessGateway):
    evidence: list[GatewayEvidence] = []

    def read(self, url: str) -> GatewayResult:
        try:
            result = super().read(url)
        except GatewayFailure as exc:
            type(self).evidence.append(exc.evidence)
            raise
        type(self).evidence.append(result.evidence)
        return result


class _CountingStore(ArtifactStore):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.writes = 0

    def commit_observation(self, proposal: ObservationProposal) -> StoredObservation:
        self.writes += 1
        return super().commit_observation(proposal)


class _OfflineCandidateAcquisition:  # pylint: disable=too-few-public-methods
    manifest = WEB_HTTP_MANIFEST

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionOutput:
        body = b"<html><body>" + (b"word " * 201) + b"</body></html>"
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
        )


def _offline_feed() -> AcquisitionOutput:
    body = b"<rss><channel></channel></rss>"
    return AcquisitionOutput(
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        OFFLINE_FEED_URL,
        OFFLINE_FEED_URL,
        200,
        "application/rss+xml",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        1,
    )


def _ignore_feed_evidence(
    _endpoint: str,
    _kind: str,
    _feed: AcquisitionOutput,
    _discovery: DiscoveryOutput | DiscoveryFailure,
) -> None:
    return None


def _acquire(
    registry: Registry, request: Request, url: str
) -> AcquisitionOutput | AcquisitionFailure:
    result = registry.invoke(WEB_HTTP_MANIFEST.tool_id, AcquisitionInput(request, url))
    assert isinstance(result, (AcquisitionOutput, AcquisitionFailure))
    return result


@dataclass(frozen=True, slots=True)
class _SelectedFeedRun:
    outcomes: tuple[DiscoveredCandidateResult, ...]
    outcome: str


def _run_selected_feeds(  # pylint: disable=too-many-arguments
    selected_endpoints: tuple[tuple[str, str], ...],
    *,
    acquire_feed: Callable[[str], AcquisitionOutput | AcquisitionFailure],
    discover_feed: Callable[
        [str, AcquisitionOutput], DiscoveryOutput | DiscoveryFailure
    ],
    acquire_candidates: Callable[
        [DiscoveryOutput], tuple[DiscoveredCandidateResult, ...]
    ],
    record_feed: Callable[
        [
            str,
            str,
            AcquisitionOutput,
            DiscoveryOutput | DiscoveryFailure,
        ],
        None,
    ],
) -> _SelectedFeedRun:
    selected_discovery: DiscoveryOutput | None = None
    for endpoint, kind in selected_endpoints:
        feed = acquire_feed(endpoint)
        assert isinstance(feed, AcquisitionOutput)
        discovery = discover_feed(kind, feed)
        record_feed(endpoint, kind, feed, discovery)
        if isinstance(discovery, DiscoveryFailure):
            assert discovery.code == "discovery.no_candidates"
        else:
            assert isinstance(discovery, DiscoveryOutput)
            if selected_discovery is None:
                selected_discovery = discovery
    if selected_discovery is None:
        outcome = (
            "pytest_pass_valid_empty_candidates"
            if selected_endpoints
            else "pytest_pass_valid_empty_declarations"
        )
        return _SelectedFeedRun((), outcome)
    outcomes = acquire_candidates(selected_discovery)
    assert outcomes
    assert all(outcome.result.status is ResultStatus.COMPLETED for outcome in outcomes)
    return _SelectedFeedRun(outcomes, "pytest_pass_nonempty")


def _request_for_target(target: dict[str, object], case: dict[str, object]) -> Request:
    skill = site_skill_from_mapping(case["site_skill"])
    seed_url = str(target["seed_url"])
    assert seed_url in skill.scope.seeds
    return Request(
        Scope(
            seeds=(seed_url,),
            allowed_origins=skill.scope.allowed_origins,
            include_paths=skill.scope.include_paths,
            content_types=skill.scope.content_types,
        ),
        skill,
        False,
        skill.budgets,
    )


def test_snapshot_is_exact_current_catalog_projection() -> None:
    payload, target, case = _load_snapshot()

    assert payload["phase"] == "12"
    assert target["seed_url"] == "https://www.iea.org/news"
    assert target["site_skill_digest"] == case["site_skill"]["digest"]
    assert target["seed_url"] in case["site_skill"]["scope"]["seeds"]
    assert target["allowed_origins"] == case["site_skill"]["scope"]["allowed_origins"]
    request = _request_for_target(target, case)
    assert request.scope.seeds == (target["seed_url"],)
    assert request.scope.allowed_origins == request.site_skill.scope.allowed_origins
    assert request.scope.include_paths == request.site_skill.scope.include_paths
    assert request.scope.content_types == request.site_skill.scope.content_types
    assert request.budgets == request.site_skill.budgets
    assert payload["endpoint_policy"] == {
        "allowed_sources": [
            "robots_sitemap_declaration",
            "html_link_declaration",
        ],
        "hand_constructed_paths": False,
        "valid_empty_discovery": True,
    }


def test_valid_empty_policy_needs_no_declared_endpoint() -> None:
    payload, target, case = _load_snapshot()
    request = _request_for_target(target, case)

    assert payload["endpoint_policy"]["valid_empty_discovery"] is True
    assert not _selected_html_endpoints(
        request,
        b"<html><head></head><body></body></html>",
        str(target["seed_url"]),
        int(payload["network_limits"]["max_feeds"]),
    )


def test_exact_no_candidates_failure_is_valid_empty() -> None:
    result = DiscoveryFailure(
        RSS_MANIFEST.tool_id,
        RSS_MANIFEST.version,
        "discovery.no_candidates",
    )

    run = _run_selected_feeds(
        ((OFFLINE_FEED_URL, "rss"),),
        acquire_feed=lambda _endpoint: _offline_feed(),
        discover_feed=lambda _kind, _feed: result,
        acquire_candidates=lambda _discovery: (),
        record_feed=_ignore_feed_evidence,
    )

    assert run.outcome == "pytest_pass_valid_empty_candidates"
    assert not run.outcomes


def test_selected_feed_acquisition_failure_is_not_empty() -> None:
    result = AcquisitionFailure(
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        "gateway.timeout",
    )

    with pytest.raises(AssertionError):
        _run_selected_feeds(
            ((OFFLINE_FEED_URL, "rss"),),
            acquire_feed=lambda _endpoint: result,
            discover_feed=lambda _kind, _feed: pytest.fail(
                "Discovery must not run after feed AcquisitionFailure"
            ),
            acquire_candidates=lambda _discovery: (),
            record_feed=_ignore_feed_evidence,
        )


def test_other_discovery_failure_is_not_empty() -> None:
    result = DiscoveryFailure(
        RSS_MANIFEST.tool_id,
        RSS_MANIFEST.version,
        "discovery.mime_not_supported",
    )

    with pytest.raises(AssertionError):
        _run_selected_feeds(
            ((OFFLINE_FEED_URL, "rss"),),
            acquire_feed=lambda _endpoint: _offline_feed(),
            discover_feed=lambda _kind, _feed: result,
            acquire_candidates=lambda _discovery: (),
            record_feed=_ignore_feed_evidence,
        )


def test_mixed_candidate_outcomes_are_not_complete(tmp_path: Path) -> None:
    payload, _target, case = _load_snapshot()
    skill = site_skill_from_mapping(case["site_skill"])
    request = Request(skill.scope, skill, False, skill.budgets)
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, _OfflineCandidateAcquisition())
    store = ArtifactStore(tmp_path / "mixed-candidate-artifacts")
    discovery = DiscoveryOutput(
        RSS_MANIFEST.tool_id,
        RSS_MANIFEST.version,
        (
            "https://www.iea.org/news/in-scope",
            "https://outside.test/out-of-scope",
        ),
        (OFFLINE_FEED_URL, OFFLINE_FEED_URL),
    )
    outcomes = acquire_discovered_candidates(
        request,
        registry,
        store,
        discovery,
        max_candidates=int(payload["network_limits"]["max_acquired_candidates"]),
        run_id="phase-12-offline-mixed",
        clock=lambda: "2026-08-26T00:00:00Z",
    )

    assert isinstance(outcomes, tuple)
    assert all(isinstance(item, DiscoveredCandidateResult) for item in outcomes)
    assert {outcome.result.status for outcome in outcomes} == {
        ResultStatus.COMPLETED,
        ResultStatus.REJECTED,
    }
    with pytest.raises(AssertionError):
        _run_selected_feeds(
            ((OFFLINE_FEED_URL, "rss"),),
            acquire_feed=lambda _endpoint: _offline_feed(),
            discover_feed=lambda _kind, _feed: discovery,
            acquire_candidates=lambda _discovery: outcomes,
            record_feed=_ignore_feed_evidence,
        )
    store.close()


def test_offline_default_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _load_authorized_snapshot()


@pytest.mark.parametrize("selector", ["", "other", "https://www.iea.org/news"])
def test_live_selector_cannot_inject_an_endpoint(
    monkeypatch: pytest.MonkeyPatch, selector: str
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", AUTHORIZED_WINDOW)
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", selector)

    if selector == "":
        assert _load_authorized_snapshot()[1]["site_key"] == "iea"
    else:
        with pytest.raises(pytest.fail.Exception, match="frozen iea key"):
            _load_authorized_snapshot()


@pytest.mark.live
def test_phase_12_discovery_live(  # pylint: disable=too-many-statements
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Scan one real seed for declared feeds; a governed empty result is valid."""
    payload, target, case = _load_authorized_snapshot()
    limits = payload["network_limits"]
    request = _request_for_target(target, case)
    budget = _NetworkBudget(
        int(limits["max_total_requests"]), int(limits["max_total_bytes"])
    )
    monkeypatch.setattr(web_http_module, "GovernedAccessGateway", _RecordingGateway)
    _RecordingGateway.evidence = []
    web_http = WebHttpAcquisitionTool(lambda: _CappedTransport(budget))
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, web_http)
    registry.register(SITEMAP_MANIFEST, SitemapDiscoveryTool())
    registry.register(RSS_MANIFEST, RssDiscoveryTool())
    store = _CountingStore(tmp_path / "artifacts")
    record: dict[str, object] = {
        "schema_version": "phase-12-discovery-live-evidence.v1",
        "snapshot_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
        "seed": target["seed_url"],
        "limits": limits,
        "valid_empty_policy": payload["endpoint_policy"]["valid_empty_discovery"],
        "feeds": [],
        "candidates": [],
        "gateway_reads": [],
        "robots": [],
        "declaration_scan": {
            "html_link_endpoints": [],
            "selected_endpoints": [],
        },
        "observations": 0,
        "outcome": "failure",
    }
    try:
        seed = _acquire(registry, request, str(target["seed_url"]))
        assert isinstance(seed, AcquisitionOutput)
        record["seed_mime_type"] = seed.mime_type
        record["seed_sha256"] = seed.sha256
        record["seed_size_bytes"] = len(seed.body)
        html_endpoints = tuple(sorted(_html_endpoints(seed.body, seed.final_url)))
        selected_endpoints = _selected_html_endpoints(
            request,
            seed.body,
            seed.final_url,
            int(limits["max_feeds"]),
        )
        record["declaration_scan"] = {
            "html_link_endpoints": html_endpoints,
            "selected_endpoints": selected_endpoints,
        }

        def discover_feed(
            kind: str, feed: AcquisitionOutput
        ) -> DiscoveryOutput | DiscoveryFailure:
            return discover_candidates(
                request,
                registry,
                discovery_tool_id=(
                    SITEMAP_MANIFEST.tool_id
                    if kind == "sitemap"
                    else RSS_MANIFEST.tool_id
                ),
                source_url=feed.final_url,
                source_body=feed.body,
                source_mime_type=feed.mime_type,
            )

        def acquire_candidates_for_live(
            discovery: DiscoveryOutput,
        ) -> tuple[DiscoveredCandidateResult, ...]:
            return acquire_discovered_candidates(
                request,
                registry,
                store,
                discovery,
                max_candidates=int(limits["max_acquired_candidates"]),
                run_id="phase-12-live",
                clock=lambda: "2026-08-26T00:00:00Z",
            )

        def record_feed(
            _endpoint: str,
            kind: str,
            feed: AcquisitionOutput,
            candidate_result: DiscoveryOutput | DiscoveryFailure,
        ) -> None:
            record["feeds"].append(
                {
                    "endpoint": feed.final_url,
                    "declared_by": seed.final_url,
                    "kind": kind,
                    "mime_type": feed.mime_type,
                    "sha256": feed.sha256,
                    "size_bytes": len(feed.body),
                    "discovery_code": (
                        candidate_result.code
                        if isinstance(candidate_result, DiscoveryFailure)
                        else "discovery.candidates"
                    ),
                    "candidate_count": (
                        len(candidate_result.candidates)
                        if isinstance(candidate_result, DiscoveryOutput)
                        else 0
                    ),
                }
            )

        run = _run_selected_feeds(
            selected_endpoints,
            acquire_feed=lambda endpoint: _acquire(registry, request, endpoint),
            discover_feed=discover_feed,
            acquire_candidates=acquire_candidates_for_live,
            record_feed=record_feed,
        )
        outcomes = run.outcomes
        completed = [
            outcome
            for outcome in outcomes
            if outcome.result.status is ResultStatus.COMPLETED
        ]
        assert store.writes == len(completed) <= 2
        assert budget.requests <= 12
        assert budget.bytes <= 4 * 1024 * 1024
        record["candidates"] = [
            {
                "url": outcome.candidate_url,
                "discovered_from": outcome.discovered_from,
                "result_status": outcome.result.status.value,
                "reauthorized": any(
                    evidence.requested_url == outcome.candidate_url
                    for evidence in _RecordingGateway.evidence
                ),
            }
            for outcome in outcomes
        ]
        record["outcome"] = run.outcome
    finally:
        record["gateway_reads"] = [
            asdict(evidence) for evidence in _RecordingGateway.evidence
        ]
        record["robots"] = [
            {
                "gateway_requested_url": evidence.requested_url,
                **asdict(robots),
            }
            for evidence in _RecordingGateway.evidence
            for robots in evidence.robots
        ]
        record["observations"] = store.writes
        record["actual_network"] = {
            "seeds": int("seed_sha256" in record),
            "requests": budget.requests,
            "bytes": budget.bytes,
            "feeds": len(record["feeds"]),
            "acquired_candidates": store.writes,
            "retry": 0,
            "fallback": 0,
            "concurrency": 1,
        }
        store.close()
        web_http.close()
        with capsys.disabled():
            print(json.dumps(record, sort_keys=True), flush=True)
