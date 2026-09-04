"""Offline release evidence for new-system delivery and incremental refresh."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-lines,too-many-locals
# pylint: disable=too-many-statements

from __future__ import annotations

import hashlib
import inspect
import json
import runpy
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from phase_20_new_system_delivery import (  # pylint: disable=import-error
    BASELINE_README_BLOB,
    BASELINE_README_LINE_COUNT,
    BASELINE_README_REVISION,
    BASELINE_README_SHA256,
    build_update_feed,
    delivery_record,
    extract_readme_clauses,
    load_frozen_readme,
    load_site_skill,
    load_site_state,
    persist_site_skill,
    persist_site_state,
    readme_evidence_matrix,
    refresh_record,
)

import web_listening.runtime.workflow as workflow_module
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.site_batch import (
    FileDiscoveryGoal,
    SiteBatchPhase,
    SiteBatchRequest,
    SiteBatchSite,
    SiteRefreshContext,
    site_batch_child_scope,
    site_batch_request_from_mapping,
)
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.request.validate import request_from_mapping
from web_listening.result.site_batch import FileDiscoveryStatus
from web_listening.runtime.service import RuntimeService
from web_listening.runtime.site_batch import (
    run_site_batch,
    site_batch_result_from_mapping,
)
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.site_refresh import run_site_refresh
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    validate_site_skill,
)
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_FILE_LINKS_MANIFEST,
    HTML_LINKS_MANIFEST,
    HtmlFileLinksDiscoveryTool,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.manifest import ToolCategory, ToolDistribution
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.subprocess import SubprocessRunner
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

ROOT = "https://example.test/"
HTML = "https://example.test/report.html"
PDF = "https://example.test/report.pdf"
ADDED = "https://example.test/added.html"
MISSING = "https://example.test/missing.pdf"
FAILED = "https://example.test/failed.html"
NOW = "2026-08-30T12:00:00Z"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LIVE_TEST = (
    PROJECT_ROOT / "tests" / "live" / "test_phase_20_new_system_delivery_live.py"
)
LIVE_TARGETS = LIVE_TEST.with_name("phase_20_new_system_delivery_targets.json")


def _html(label: str) -> bytes:
    return (
        f"<!doctype html><html><body><h1>{label}</h1>"
        "<p>five visible words for markdown delivery evidence</p>"
        "</body></html>"
    ).encode()


def test_first_and_refresh_use_independent_fifty_mib_request_budgets() -> None:
    expected_limits = {
        "max_requests": 12,
        "max_bytes": 52_428_800,
        "max_runtime_seconds": 60,
        "concurrency": 1,
        "retry": 0,
    }
    payload = json.loads(LIVE_TARGETS.read_bytes())

    assert payload["network_limits_per_request"] == expected_limits
    assert "network_limits_per_site_first_and_refresh" not in payload

    helpers = runpy.run_path(str(LIVE_TEST))
    assert helpers["EXPECTED_REQUEST_LIMITS"] == expected_limits
    parent = helpers["_batch_parent_request"](
        payload["targets"],
        payload["target_plans"],
        expected_limits,
    )
    frozen_sites = helpers["_batch_sites"](
        payload["targets"],
        payload["target_plans"],
    )
    frozen_batch = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        parent,
        (),
        sites=frozen_sites,
    )
    site_keys = frozen_batch.site_keys
    assert site_keys == (
        "www.soa.org",
        "www.casact.org",
        "actuaries.org",
        "www.ipcc.ch",
    )
    assert tuple(site.file_discovery_goal for site in frozen_batch.sites) == (
        FileDiscoveryGoal.NOT_REQUIRED,
        FileDiscoveryGoal.REQUIRED,
        FileDiscoveryGoal.REQUIRED,
        FileDiscoveryGoal.NOT_REQUIRED,
    )
    first = helpers["_PhaseNetworkBudgets"](site_keys, expected_limits)
    refresh = helpers["_PhaseNetworkBudgets"](site_keys, expected_limits)

    assert first is not refresh
    assert all(first.by_site[key] is not refresh.by_site[key] for key in site_keys)
    assert all(
        budget.requests == budget.response_bytes == 0
        for phase in (first, refresh)
        for budget in phase.by_site.values()
    )
    assert all(
        budget.max_requests == 12 and budget.max_response_bytes == 52_428_800
        for phase in (first, refresh)
        for budget in phase.by_site.values()
    )

    first.by_site[site_keys[0]].requests = 13
    first.by_site[site_keys[0]].response_bytes = 52_428_801
    first_records = first.evidence(expected_limits)
    refresh_records = refresh.evidence(expected_limits)
    combined = helpers["_combined_budget_audit"](
        first_records,
        refresh_records,
    )
    assert first_records[site_keys[0]]["within_budget"] is False
    assert all(row["within_budget"] for row in refresh_records.values())
    assert combined["requests"] == 13
    assert combined["response_bytes"] == 52_428_801
    assert combined["budget_gate"] is False
    assert "within_budget" not in combined
    assert combined["per_site"][site_keys[0]]["requests"] == 13

    now = [0.0]
    serial = helpers["_PhaseNetworkBudgets"](
        ("one.test", "two.test"),
        expected_limits,
        clock=lambda: now[0],
    )
    serial.for_url("https://one.test/")
    now[0] = 5.0
    serial.for_url("https://two.test/")
    now[0] = 8.0
    serial_records = serial.evidence(expected_limits)
    assert serial_records["one.test"]["runtime_seconds"] == 5.0
    assert serial_records["two.test"]["runtime_seconds"] == 3.0

    class _TwoByteResponse:
        status = 200
        headers: dict[str, str] = {}
        peer_ip = "192.0.2.1"

        @staticmethod
        def read(max_bytes: int) -> bytes:
            return b"xy"[:max_bytes]

        @staticmethod
        def set_timeout(_timeout: float) -> None:
            return None

        @staticmethod
        def close() -> None:
            return None

    capped_budget = helpers["_new_request_budget"](expected_limits)
    capped_budget.response_bytes = 52_428_799
    capped_response = helpers["_CappedResponse"](_TwoByteResponse(), capped_budget)

    assert capped_response.read(2) == b"x"
    assert capped_budget.response_bytes == 52_428_800
    with pytest.raises(TimeoutError):
        capped_response.read(2)

    request_capped_budget = helpers["_new_request_budget"](expected_limits)
    request_capped_budget.requests = 12
    capped_transport = helpers["_CappedTransport"](request_capped_budget)
    try:
        with pytest.raises(TimeoutError):
            capped_transport.send(
                "https://example.test/",
                timeout=60,
                addresses=("192.0.2.1",),
            )
    finally:
        capped_transport.close()


def test_phase_budget_starts_before_each_sites_cross_site_pre_send_delay() -> None:
    helpers = runpy.run_path(str(LIVE_TEST))
    expected_limits = helpers["EXPECTED_REQUEST_LIMITS"]
    request = Request(
        Scope(
            (
                "https://one.test/",
                "https://two.test/",
                "https://unknown.test/",
            ),
            (
                "https://one.test",
                "https://two.test",
                "https://unknown.test",
            ),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )

    class _PreSendDelayAcquisition:
        manifest = WEB_HTTP_MANIFEST

        def __init__(self, phase, now: list[float]) -> None:
            self.phase = phase
            self.now = now

        def acquire(self, tool_input: AcquisitionInput) -> AcquisitionFailure:
            host = urlsplit(tool_input.target_url).hostname
            if host == "one.test":
                self.phase.for_url(tool_input.target_url)
                self.now[0] = 1.0
                self.phase.for_url(tool_input.target_url)
                self.now[0] = 2.0
            else:
                self.now[0] = 61.0
                self.phase.for_url(tool_input.target_url)
                self.now[0] = 61.5
                self.phase.for_url(tool_input.target_url)
                self.now[0] = 62.0
            return AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "gateway.transport",
            )

        @staticmethod
        def close() -> None:
            return None

    old_now = [0.0]
    old_phase = helpers["_PhaseNetworkBudgets"](
        ("one.test", "two.test"),
        expected_limits,
        clock=lambda: old_now[0],
    )
    old_acquisition = _PreSendDelayAcquisition(old_phase, old_now)
    old_acquisition.acquire(AcquisitionInput(request, "https://one.test/"))
    old_acquisition.acquire(AcquisitionInput(request, "https://two.test/"))
    old_records = old_phase.evidence(expected_limits)
    assert old_records["one.test"]["runtime_seconds"] == 61.0
    assert old_records["one.test"]["within_budget"] is False
    assert old_records["two.test"]["runtime_seconds"] == 1.0
    assert old_records["two.test"]["within_budget"] is True

    budgeted_type = helpers.get("_PhaseBudgetedAcquisition")
    assert budgeted_type is not None
    for phase_name in ("first", "refresh"):
        now = [0.0]
        phase = helpers["_PhaseNetworkBudgets"](
            ("zero.test", "one.test", "two.test"),
            expected_limits,
            clock=lambda current=now: current[0],
        )
        acquisition = budgeted_type(
            phase,
            lambda _deadline, current_phase=phase, current=now: (
                _PreSendDelayAcquisition(current_phase, current)
            ),
        )

        acquisition.acquire(AcquisitionInput(request, "https://one.test/"))
        acquisition.acquire(AcquisitionInput(request, "https://two.test/"))
        records = phase.evidence(expected_limits)

        assert records["zero.test"]["runtime_seconds"] == 0.0, phase_name
        assert records["one.test"]["runtime_seconds"] == 2.0, phase_name
        assert records["two.test"]["runtime_seconds"] == 60.0, phase_name
        assert all(record["within_budget"] for record in records.values()), phase_name
        unknown = acquisition.acquire(
            AcquisitionInput(request, "https://unknown.test/")
        )
        out_of_order = acquisition.acquire(
            AcquisitionInput(request, "https://one.test/")
        )
        assert (unknown.code, out_of_order.code) == (
            "budget.site_order",
            "budget.site_order",
        )
        acquisition.close()


def test_expired_phase_budget_stops_before_real_gateway_resolver() -> None:
    helpers = runpy.run_path(str(LIVE_TEST))
    limits = helpers["EXPECTED_REQUEST_LIMITS"]
    base = helpers["time"].monotonic()
    now = [base - 61.0]
    phase = helpers["_PhaseNetworkBudgets"](
        ("one.test",),
        limits,
        clock=lambda: now[0],
    )
    request = Request(
        Scope(
            ("https://one.test/",),
            ("https://one.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )
    phase.for_url("https://one.test/")
    now[0] = base
    resolver_calls: list[tuple[str, int]] = []

    def resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        return ("93.184.216.34",)

    def acquisition_factory(deadline: float) -> WebHttpAcquisitionTool:
        return WebHttpAcquisitionTool(
            lambda: helpers["_CappedTransport"](phase),
            resolver=resolver,
            runtime_deadline=deadline,
        )

    acquisition = helpers["_PhaseBudgetedAcquisition"](phase, acquisition_factory)

    result = acquisition.acquire(AcquisitionInput(request, "https://one.test/"))

    assert isinstance(result, AcquisitionFailure)
    assert not resolver_calls
    assert result.code == "budget.runtime"
    acquisition.close()
    closed = acquisition.acquire(AcquisitionInput(request, "https://one.test/"))
    assert closed.code == "gateway.closed"
    assert not resolver_calls


def test_live_delivery_uses_exactly_two_public_site_batch_requests() -> None:
    helpers = runpy.run_path(str(LIVE_TEST))
    source = inspect.getsource(helpers["_batch_run"])
    live_source = inspect.getsource(
        helpers["test_phase_20_new_system_multi_site_delivery_and_refresh_live"]
    )

    assert live_source.count("_batch_run(") == 1
    assert "_site_run(" not in live_source
    assert source.count("run_site_batch(") == 2
    assert source.count("_PhaseBudgetedAcquisition(") == 2
    assert source.count("_batch_sites(") == 2
    assert "sites=first_sites" in source
    assert "sites=refresh_sites" in source
    assert source.count("HTML_FILE_LINKS_MANIFEST") == 2
    assert "WebHttpAcquisitionTool(" not in source
    full_source = LIVE_TEST.read_text(encoding="utf-8")
    assert "runtime_deadline=budget.deadline" in full_source
    assert "acquisition.close()" in full_source
    assert source.index("first_physical = first_network.evidence(") < source.index(
        "_persist_refresh_contexts("
    )


def test_live_batch_consumes_production_continuations_without_fallback() -> None:
    helpers = runpy.run_path(str(LIVE_TEST))
    source = inspect.getsource(helpers["_batch_run"])
    persistence_source = inspect.getsource(helpers["_persist_refresh_contexts"])

    assert "first.next_refresh_contexts" in source
    assert "refresh_sites = _batch_sites(" in source
    assert "SiteRefreshContext(" in persistence_source
    assert "create_candidate(" not in source
    assert "project_current_state(" not in source
    assert "run_site_explore(" not in source
    assert "run_site_refresh(" not in source


def test_site_skill_canonical_persistence_is_strictly_reread(tmp_path: Path) -> None:
    helpers = runpy.run_path(
        str(Path(__file__).with_name("phase_20_new_system_delivery.py"))
    )
    persist_helper = helpers["persist_site_skill"]
    load_helper = helpers["load_site_skill"]
    skill = create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=_request().scope,
        budgets=_request().budgets,
        tool=ToolReference(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            ToolCategory.ACQUISITION,
            WEB_HTTP_MANIFEST.capabilities,
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=DiscoveryRecipe(
            ToolReference(
                HTML_LINKS_MANIFEST.tool_id,
                HTML_LINKS_MANIFEST.version,
                ToolCategory.DISCOVERY,
                HTML_LINKS_MANIFEST.capabilities,
            ),
            ROOT,
        ),
    ).skill
    path = tmp_path / "site-skill.json"

    persist_helper(path, skill)
    loaded = load_helper(path)

    assert loaded == skill
    assert path.read_bytes() == helpers["canonical_site_skill_bytes"](loaded)


@dataclass
class _SequenceAcquisition:
    responses: dict[str, list[tuple[str, bytes] | str]]
    manifest = WEB_HTTP_MANIFEST
    calls: dict[str, int] = field(default_factory=dict)

    def acquire(self, tool_input):
        url = tool_input.target_url
        index = self.calls.get(url, 0)
        self.calls[url] = index + 1
        sequence = self.responses[url]
        item = sequence[min(index, len(sequence) - 1)]
        if isinstance(item, str):
            return AcquisitionFailure(
                self.manifest.tool_id,
                self.manifest.version,
                item,
                requests=1,
            )
        mime_type, body = item
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            url,
            url,
            200,
            mime_type,
            body,
            hashlib.sha256(body).hexdigest(),
            (),
            1,
            requests=1,
            bytes_received=len(body),
        )


@dataclass
class _SequenceDiscovery:
    candidates: list[tuple[str, ...]]
    manifest = HTML_LINKS_MANIFEST
    calls: int = 0

    def discover(self, tool_input):
        index = min(self.calls, len(self.candidates) - 1)
        self.calls += 1
        urls = self.candidates[index]
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            urls,
            (tool_input.source_url,) * len(urls),
            DiscoveryCoverage.COMPLETE,
        )


def _registry(acquisition, discovery) -> Registry:
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(HTML_LINKS_MANIFEST, discovery)
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, SimpleHtmlMarkdownTransform())
    return registry


def test_frozen_file_goals_drive_real_site_batch_candidate_acquisition(
    tmp_path: Path,
) -> None:
    helpers = runpy.run_path(str(LIVE_TEST))
    payload = json.loads(LIVE_TARGETS.read_bytes())
    parent = helpers["_batch_parent_request"](
        payload["targets"],
        payload["target_plans"],
        payload["network_limits_per_request"],
    )
    seeds = parent.scope.seeds
    candidates: dict[str, tuple[str, str, str]] = {}
    responses: dict[str, list[tuple[str, bytes] | str]] = {}
    for seed in seeds:
        origin = f"{urlsplit(seed).scheme}://{urlsplit(seed).netloc}"
        a_html = f"{origin}/a.html"
        b_html = f"{origin}/b.html"
        report_pdf = f"{origin}/z-report.pdf"
        candidates[seed] = (a_html, b_html, report_pdf)
        responses[seed] = [
            (
                "text/html",
                (
                    '<a href="/a.html">a</a>'
                    '<a href="/b.html">b</a>'
                    '<a href="/z-report.pdf">report</a>'
                ).encode(),
            )
        ]
        responses[a_html] = [("text/html", _html("page a"))]
        responses[b_html] = [("text/html", _html("page b"))]
        responses[report_pdf] = [
            ("application/pdf", b"%PDF-1.7\nproduction file goal fixture\n%%EOF")
        ]

    def production_registry() -> Registry:
        registry = Registry()
        registry.register(WEB_HTTP_MANIFEST, _SequenceAcquisition(responses))
        registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
        registry.register(
            HTML_FILE_LINKS_MANIFEST,
            HtmlFileLinksDiscoveryTool(),
        )
        registry.register(
            SIMPLE_HTML_MARKDOWN_MANIFEST,
            SimpleHtmlMarkdownTransform(),
        )
        return registry

    legacy_store = ArtifactStore(tmp_path / "legacy")
    try:
        legacy = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, ()),
            production_registry(),
            legacy_store,
            run_id="legacy-no-file-goal",
            clock=lambda: NOW,
        )
        assert (
            legacy.file_discovery_statuses == (FileDiscoveryStatus.NOT_REQUESTED,) * 4
        )
        for child, seed in zip(legacy.site_results, seeds, strict=True):
            assert [
                result.manifest.requested_url for result in child.target_results
            ] == [seed, *candidates[seed][:2]]
    finally:
        legacy_store.close()

    sites = helpers["_batch_sites"](
        payload["targets"],
        payload["target_plans"],
    )
    request = site_batch_request_from_mapping(
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            parent,
            (),
            sites=sites,
        ).to_dict()
    )
    store = ArtifactStore(tmp_path / "file-goals")
    try:
        result = site_batch_result_from_mapping(
            run_site_batch(
                request,
                production_registry(),
                store,
                run_id="frozen-file-goals",
                clock=lambda: NOW,
            ).to_dict()
        )

        assert request.sites == sites
        assert result.file_discovery_statuses == (
            FileDiscoveryStatus.NOT_REQUESTED,
            FileDiscoveryStatus.SATISFIED,
            FileDiscoveryStatus.SATISFIED,
            FileDiscoveryStatus.NOT_REQUESTED,
        )
        for index in (1, 2):
            child = result.site_results[index]
            assert [
                target.manifest.requested_url for target in child.target_results
            ] == [seeds[index], candidates[seeds[index]][2]]
            assert child.target_results[-1].manifest.mime_type == "application/pdf"
            assert child.discovery[0].tool_id == HTML_FILE_LINKS_MANIFEST.tool_id
        assert site_batch_result_from_mapping(result.to_dict()) == result
    finally:
        store.close()


def _request() -> Request:
    return Request(
        Scope(
            (ROOT,),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )


def _first_run(store, registry):
    request = _request()
    first = run_site_explore(
        request,
        registry,
        store,
        run_id="first",
        clock=lambda: NOW,
    )
    if first.site_skill_candidate is None:
        raise AssertionError("fixture must produce a production continuation")
    skill = site_skill_from_mapping(first.site_skill_candidate.to_dict())
    validate_site_skill(skill)
    skill_path = store.root.parent / "site-skill.json"
    persist_site_skill(skill_path, skill)
    persisted_skill = load_site_skill(skill_path)
    state_path = store.root.parent / "current-site-state.json"
    persist_site_state(state_path, first.site_state)
    persisted_state = load_site_state(state_path)
    return request, first, persisted_skill, persisted_state


def test_first_run_persists_and_strictly_rereads_state_and_skill(
    tmp_path: Path,
) -> None:
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
            PDF: [("application/pdf", b"%PDF-1.7\nstrict persisted fixture\n%%EOF")],
        }
    )
    discovery = _SequenceDiscovery([(HTML, PDF)])
    store = ArtifactStore(tmp_path / "artifacts")

    _request_value, _first, skill, state = _first_run(
        store, _registry(acquisition, discovery)
    )

    skill_path = tmp_path / "site-skill.json"
    state_path = tmp_path / "current-site-state.json"
    assert skill_path.is_file()
    assert state_path.is_file()
    assert load_site_skill(skill_path) == skill
    assert load_site_state(state_path) == state
    store.close()


@pytest.mark.parametrize(
    ("refresh_pdf_body", "expected_artifact_reused"),
    (
        (b"%PDF-1.7\nstrict aggregate fixture\n%%EOF", True),
        (b"%PDF-1.7\nchanged aggregate fixture\n%%EOF", False),
    ),
)
def test_first_and_refresh_are_two_strict_site_batch_request_executions(
    tmp_path: Path,
    refresh_pdf_body: bytes,
    expected_artifact_reused: bool,
) -> None:
    second_root = "https://second.test/"
    second_html = "https://second.test/report.html"
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
            PDF: [
                ("application/pdf", b"%PDF-1.7\nstrict aggregate fixture\n%%EOF"),
                ("application/pdf", refresh_pdf_body),
            ],
            second_root: [("text/html", _html("second root"))],
            second_html: [("text/html", _html("second html"))],
        }
    )
    discovery = _SequenceDiscovery(
        [
            (HTML, PDF),
            (second_html,),
            (HTML, PDF),
            (second_html,),
        ]
    )
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    parent = Request(
        Scope(
            (ROOT, second_root),
            (ROOT.rstrip("/"), second_root.rstrip("/")),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )
    sites = tuple(
        SiteBatchSite(
            site_batch_child_scope(parent.scope, seed),
            (
                FileDiscoveryGoal.REQUIRED
                if index == 0
                else FileDiscoveryGoal.NOT_REQUIRED
            ),
        )
        for index, seed in enumerate(parent.scope.seeds)
    )
    first_request = site_batch_request_from_mapping(
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            parent,
            (),
            sites=sites,
        ).to_dict()
    )
    first = site_batch_result_from_mapping(
        run_site_batch(
            first_request,
            registry,
            store,
            run_id="first-batch",
            clock=lambda: NOW,
        ).to_dict()
    )
    persisted_contexts = []
    for context in first.next_refresh_contexts:
        assert isinstance(context, SiteRefreshContext)
        site_root = tmp_path / context.site_skill.site_key
        site_root.mkdir()
        skill_path = site_root / "site-skill.json"
        state_path = site_root / "current-site-state.json"
        persist_site_skill(skill_path, context.site_skill)
        persist_site_state(state_path, context.previous_state)
        persisted_contexts.append(
            SiteRefreshContext(
                load_site_skill(skill_path),
                load_site_state(state_path),
            )
        )
    refresh_request = site_batch_request_from_mapping(
        SiteBatchRequest(
            SiteBatchPhase.REFRESH,
            parent,
            tuple(persisted_contexts),
            sites=sites,
        ).to_dict()
    )
    refresh = site_batch_result_from_mapping(
        run_site_batch(
            refresh_request,
            registry,
            store,
            run_id="refresh-batch",
            clock=lambda: NOW,
        ).to_dict()
    )
    helpers = runpy.run_path(str(LIVE_TEST))

    def physical(batch) -> dict[str, dict[str, object]]:
        return {
            site_key: {
                "requests": child.usage.requests,
                "response_bytes": child.usage.bytes_received,
                "runtime_seconds": child.usage.runtime_ms / 1000,
                "max_requests": 12,
                "max_bytes": 52_428_800,
                "max_runtime_seconds": 60,
                "concurrency": 1,
                "retry": 0,
                "within_budget": True,
            }
            for site_key, child in zip(
                batch.site_keys,
                batch.site_results,
                strict=True,
            )
        }

    first_physical = physical(first)
    refresh_physical = physical(refresh)
    first_evidence = helpers["_request_evidence"](
        "first-batch",
        first_request,
        first,
        first_physical,
        helpers["_batch_usage_reconciliation"](first, first_physical),
    )
    refresh_evidence = helpers["_request_evidence"](
        "refresh-batch",
        refresh_request,
        refresh,
        refresh_physical,
        helpers["_batch_usage_reconciliation"](refresh, refresh_physical),
    )

    assert first_evidence["request_id"] == first_evidence["run_id"] == "first-batch"
    assert (
        refresh_evidence["request_id"] == refresh_evidence["run_id"] == "refresh-batch"
    )
    assert first_evidence["request_id"] != refresh_evidence["request_id"]
    assert first_evidence["strict_request_round_trip"] is True
    assert refresh_evidence["strict_request_round_trip"] is True
    assert first_evidence["strict_result_round_trip"] is True
    assert refresh_evidence["strict_result_round_trip"] is True
    assert first_evidence["result_usage"] == first.usage.to_dict()
    assert refresh_evidence["result_usage"] == refresh.usage.to_dict()
    assert first_evidence["target_manifest_run_ids"]["example.test"][0] == (
        "first-batch-site-1-seed"
    )
    assert refresh_evidence["target_manifest_run_ids"]["example.test"][0] == (
        "refresh-batch-site-1-source"
    )
    assert first_evidence["request_sha256"] != refresh_evidence["request_sha256"]
    assert all(
        usage
        == {
            "requests": 0,
            "response_bytes": 0,
            "runtime_seconds": 0.0,
        }
        for evidence in (first_evidence, refresh_evidence)
        for usage in evidence["initial_usage_by_site"].values()
    )
    assert all(
        limits
        == {
            "max_requests": 12,
            "max_bytes": 52_428_800,
            "max_runtime_seconds": 60,
            "concurrency": 1,
            "retry": 0,
        }
        for evidence in (first_evidence, refresh_evidence)
        for limits in evidence["limits_per_site"].values()
    )
    assert tuple(persisted_contexts) == refresh_request.refresh_contexts
    assert refresh_request.sites == sites
    assert all(
        context.site_skill.scope == site.scope
        for context, site in zip(persisted_contexts, sites, strict=True)
    )
    assert (
        first.file_discovery_statuses
        == refresh.file_discovery_statuses
        == (
            FileDiscoveryStatus.SATISFIED,
            FileDiscoveryStatus.NOT_REQUESTED,
        )
    )
    assert (
        first.usable_site_keys
        == refresh.usable_site_keys
        == (
            "example.test",
            "second.test",
        )
    )
    for batch in (first, refresh):
        for child in batch.site_results:
            markdown_result = next(
                result
                for result in child.target_results
                if any(
                    artifact.role == "derived" and artifact.mime_type == "text/markdown"
                    for artifact in result.artifacts
                )
            )
            source_artifact = next(
                artifact
                for artifact in markdown_result.artifacts
                if artifact.role == "source"
            )
            derived_artifact = next(
                artifact
                for artifact in markdown_result.artifacts
                if artifact.role == "derived"
            )
            transform_attempt = next(
                attempt
                for attempt in markdown_result.attempts
                if attempt.tool_id == SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
            )
            assert derived_artifact.lineage[0].source_artifact_id == (
                source_artifact.artifact_id
            )
            assert derived_artifact.lineage[0].source_observation_id == (
                source_artifact.observation_id
            )
            assert transform_attempt.outcome == "succeeded"
            assert transform_attempt.requests == transform_attempt.bytes_received == 0
        assert batch.usage.requests == sum(
            child.usage.requests for child in batch.site_results
        )
        assert batch.usage.bytes_received == sum(
            child.usage.bytes_received for child in batch.site_results
        )
        assert batch.usage.tool_attempts == sum(
            child.usage.tool_attempts for child in batch.site_results
        )
    pdf_results = [
        result
        for batch in (first, refresh)
        for child in batch.site_results
        for result in child.target_results
        if any(
            artifact.role == "source" and artifact.mime_type == "application/pdf"
            for artifact in result.artifacts
        )
    ]
    assert len(pdf_results) == 2
    assert all(
        result.manifest.mime_type == "application/pdf"
        and result.manifest.http_status == 200
        for result in pdf_results
    )
    first_pdf = next(
        result
        for result in first.site_results[0].target_results
        if any(
            artifact.role == "source" and artifact.mime_type == "application/pdf"
            for artifact in result.artifacts
        )
    )
    pdf_refresh_proof = helpers["_pdf_refresh_proof"](
        first_pdf,
        refresh.site_results[0],
        persisted_contexts[0],
        store,
    )
    assert pdf_refresh_proof["passed"] is True
    assert pdf_refresh_proof["same_canonical_target"] is True
    assert pdf_refresh_proof["new_observation"] is True
    assert pdf_refresh_proof["artifact_reused"] is expected_artifact_reused
    assert pdf_refresh_proof["content_unchanged"] is expected_artifact_reused
    assert pdf_refresh_proof["artifact_identity_valid"] is True
    assert all(
        evidence["usage_reconciliation"]["matches"] is True
        for evidence in (first_evidence, refresh_evidence)
    )
    for evidence in (first_evidence, refresh_evidence):
        reconciliation = evidence["usage_reconciliation"]
        assert reconciliation["aggregate_audit"]["runtime_comparable"] is False
        assert all(
            row["runtime_comparable"] is False
            and row["logical_runtime_seconds"] >= 0
            and row["physical_runtime_seconds"] >= 0
            for row in reconciliation["per_site"].values()
        )
    store.close()


def test_site_delivery_rejects_refresh_of_a_different_pdf_target(
    tmp_path: Path,
) -> None:
    second_root = "https://second.test/"
    second_html = "https://second.test/report.html"
    replacement_pdf = "https://example.test/replacement.pdf"
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
            PDF: [
                ("application/pdf", b"%PDF-1.7\noriginal governed file\n%%EOF"),
                "gateway.transport",
            ],
            replacement_pdf: [
                ("application/pdf", b"%PDF-1.7\nreplacement file\n%%EOF")
            ],
            second_root: [("text/html", _html("second root"))],
            second_html: [("text/html", _html("second html"))],
        }
    )
    discovery = _SequenceDiscovery(
        [
            (HTML, PDF),
            (second_html,),
            (replacement_pdf,),
            (second_html,),
        ]
    )
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    parent = Request(
        Scope(
            (ROOT, second_root),
            (ROOT.rstrip("/"), second_root.rstrip("/")),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )
    sites = tuple(
        SiteBatchSite(
            site_batch_child_scope(parent.scope, seed),
            (
                FileDiscoveryGoal.REQUIRED
                if index == 0
                else FileDiscoveryGoal.NOT_REQUIRED
            ),
        )
        for index, seed in enumerate(parent.scope.seeds)
    )
    first = site_batch_result_from_mapping(
        run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.FIRST,
                parent,
                (),
                sites=sites,
            ),
            registry,
            store,
            run_id="first-mismatched-pdf",
            clock=lambda: NOW,
        ).to_dict()
    )
    persisted_contexts = []
    context_paths = {}
    for context in first.next_refresh_contexts:
        assert isinstance(context, SiteRefreshContext)
        site_root = tmp_path / context.site_skill.site_key
        site_root.mkdir()
        skill_path = site_root / "site-skill.json"
        state_path = site_root / "current-site-state.json"
        persist_site_skill(skill_path, context.site_skill)
        persist_site_state(state_path, context.previous_state)
        reloaded = SiteRefreshContext(
            load_site_skill(skill_path),
            load_site_state(state_path),
        )
        persisted_contexts.append(reloaded)
        context_paths[context.site_skill.site_key] = {
            "state_relative_path": state_path.relative_to(tmp_path).as_posix(),
            "site_skill_relative_path": skill_path.relative_to(tmp_path).as_posix(),
        }
    refresh = site_batch_result_from_mapping(
        run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                parent,
                tuple(persisted_contexts),
                sites=sites,
            ),
            registry,
            store,
            run_id="refresh-mismatched-pdf",
            clock=lambda: NOW,
        ).to_dict()
    )
    helpers = runpy.run_path(str(LIVE_TEST))

    def physical(batch) -> dict[str, dict[str, object]]:
        return {
            site_key: {
                "requests": child.usage.requests,
                "response_bytes": child.usage.bytes_received,
                "runtime_seconds": child.usage.runtime_ms / 1000,
                "max_requests": 12,
                "max_bytes": 52_428_800,
                "max_runtime_seconds": 60,
                "concurrency": 1,
                "retry": 0,
                "within_budget": True,
            }
            for site_key, child in zip(
                batch.site_keys,
                batch.site_results,
                strict=True,
            )
        }

    first_pdf_urls = {
        artifact.source_url
        for result in first.site_results[0].target_results
        for artifact in result.artifacts
        if artifact.role == "source" and artifact.mime_type == "application/pdf"
    }
    refresh_pdf_urls = {
        artifact.source_url
        for result in refresh.site_results[0].target_results
        for artifact in result.artifacts
        if artifact.role == "source" and artifact.mime_type == "application/pdf"
    }
    assert first.usable_site_keys == refresh.usable_site_keys
    assert first_pdf_urls == {PDF}
    assert refresh_pdf_urls == {replacement_pdf}
    record = helpers["_site_delivery_record"](
        tmp_path,
        {
            "site_key": "example",
            "urls": {"document": ROOT},
        },
        {
            "source_url_field": "document",
            "required_capability": "ordinary_html",
            "file_discovery_goal": "required",
        },
        first,
        refresh,
        {context.site_skill.site_key: context for context in persisted_contexts},
        context_paths,
        physical(first),
        physical(refresh),
        store,
    )

    assert record["status"] == "BLOCKED"
    assert "historical_expectation" not in record
    store.close()


def test_issue_owned_snapshot_is_independent_of_legacy_catalog_changes(
    tmp_path: Path,
) -> None:
    changed_dev = tmp_path / "dev_test_sites.json"
    changed_smoke = tmp_path / "smoke_site_catalog.json"
    changed_dev.write_text(
        json.dumps({"sites": [{"site_key": "soa", "provenance_only": "changed"}]}),
        encoding="utf-8",
    )
    changed_smoke.write_text(
        json.dumps({"sites": [{"site_key": "ipcc", "historical_only": "changed"}]}),
        encoding="utf-8",
    )
    helpers = runpy.run_path(str(LIVE_TEST))
    loader = helpers["_load_snapshot"]
    loader.__globals__["DEV_CATALOG"] = changed_dev
    loader.__globals__["SMOKE_CATALOG"] = changed_smoke

    payload = loader()
    source = LIVE_TEST.read_text(encoding="utf-8")

    assert tuple(target["site_key"] for target in payload["targets"]) == (
        "soa",
        "cas",
        "iaa",
        "ipcc",
    )
    assert set(payload) == {
        "schema_version",
        "phase",
        "network_limits_per_request",
        "target_plans",
        "targets",
    }
    assert all(
        "provenance" not in target and "historical_classification" not in target
        for target in payload["targets"]
    )
    assert "source_catalogs" not in source
    assert "DEV_CATALOG" not in source
    assert "SMOKE_CATALOG" not in source
    assert "historical_expectation" not in source
    assert "historical_classification" not in source


def test_frozen_readme_identity_and_clause_matrix_are_complete() -> None:
    repository_root = Path(__file__).parents[2]
    frozen = load_frozen_readme(repository_root)

    assert frozen.revision == BASELINE_README_REVISION
    assert frozen.blob == BASELINE_README_BLOB
    assert frozen.sha256 == BASELINE_README_SHA256
    assert frozen.line_count == BASELINE_README_LINE_COUNT == 731
    matrix = readme_evidence_matrix(frozen.text)
    assert len(matrix) == 191
    assert len({row.clause_id for row in matrix}) == len(matrix)
    assert {row.section for row in matrix} == {1, 2, *range(4, 18), 19}
    assert sum(row.section == 19 for row in matrix) == 16
    assert all(row.command.startswith("py -3.14 -m pytest -q ") for row in matrix)
    assert all(
        row.clause_text
        and row.test_nodeids
        and row.command
        and row.evidence_fields
        and row.result == "PASS"
        and row.na_reason is None
        for row in matrix
    )
    clause_texts = {row.clause_text for row in matrix}
    assert (
        "The current Web Listening 3.1 product explicitly disables production "
        "target reads through these browser tools."
    ) in clause_texts
    assert not any(
        text.startswith("contract code:")
        or "flowchart TD" in text
        or "src/web_listening/" in text
        or "web-listening acquire" in text
        or "POST /v1/acquisitions" in text
        for text in clause_texts
    )
    non_html = next(
        row for row in matrix if row.clause_text == "Do not transform non-HTML content."
    )
    assert non_html.test_nodeids == (
        "tests/tool_registry/test_simple_html_markdown.py::"
        "test_non_html_low_quality_and_complex_inputs_are_explicitly_skipped",
    )
    browser_disabled = next(
        row for row in matrix if row.clause_id == "README-11-424b58a8"
    )
    assert browser_disabled.test_nodeids == (
        "tests/parity/test_phase_20_new_system_delivery.py::"
        "test_default_runtime_composition_disables_browser_target_reads",
    )
    direct_skill = next(row for row in matrix if row.clause_id == "README-19-04")
    assert direct_skill.test_nodeids == (
        "tests/parity/test_phase_20_new_system_delivery.py::"
        "test_valid_site_skill_uses_preferred_tool_without_rediscovery_or_alternate",
    )


def test_normative_fenced_contracts_are_extracted_without_examples() -> None:
    frozen = load_frozen_readme(Path(__file__).parents[2])
    clause_texts = {
        clause.clause_text for clause in extract_readme_clauses(frozen.text)
    }

    assert {
        "Public Request forbidden caller field: authorized_tool_ids",
        "Public Request forbidden caller field: authorization_reference",
        "explore_all_tools eligible intersection requires: registered",
        "explore_all_tools eligible intersection requires: installed",
        "explore_all_tools eligible intersection requires: qualified",
        "explore_all_tools eligible intersection requires: healthy",
        "explore_all_tools eligible intersection requires: capability-compatible",
        "explore_all_tools eligible intersection requires: policy-compliant",
        "explore_all_tools eligible intersection requires: within budget",
        "First-version built-in Transform identifier: simple_html_markdown",
    }.issubset(clause_texts)
    assert not any(
        "flowchart TD" in text
        or "HTTP → Playwright → CloakBrowser" in text
        or "web-listening acquire" in text
        or "src/web_listening/" in text
        for text in clause_texts
    )


def test_independently_normative_colon_lead_ins_are_preserved_exactly() -> None:
    frozen = load_frozen_readme(Path(__file__).parents[2])
    clauses = extract_readme_clauses(frozen.text)
    clause_texts = {clause.clause_text for clause in clauses}

    assert {
        "The product is organized around five business modules:",
        "Two small supporting layers are allowed:",
        "The common Request should expose only four important inputs:",
        "CLI, REST, and MCP should return the same logical Result:",
        (
            "If it does not implement the Web Listening protocol natively, a "
            "thin Adapter translates between the two systems:"
        ),
    }.issubset(clause_texts)
    assert {
        "A caller tells it:",
        "Web Listening then:",
        "Example:",
        "Rules:",
        "The recommended relationship is:",
        "The public contract should not require callers to provide:",
        "Fallback is not a hard-coded chain such as:",
        "The first version should include one built-in Transform:",
        "Start the new repository with:",
    }.isdisjoint(clause_texts)
    matrix_by_text = {
        row.clause_text: row for row in readme_evidence_matrix(frozen.text)
    }
    expected = {
        "The product is organized around five business modules:": (
            "README-02-7266bc92",
            "tests/test_package_smoke.py::test_readme_module_boundaries_are_importable",
        ),
        "Two small supporting layers are allowed:": (
            "README-02-c56fa1ee",
            "tests/test_package_smoke.py::test_readme_module_boundaries_are_importable",
        ),
        "The common Request should expose only four important inputs:": (
            "README-05-294f18ae",
            "tests/request/test_request_validation.py::test_minimal_request_fixture_is_accepted",
        ),
        "CLI, REST, and MCP should return the same logical Result:": (
            "README-06-6519f1aa",
            "tests/interfaces/test_cli.py::"
            "test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
        ),
        (
            "If it does not implement the Web Listening protocol natively, a "
            "thin Adapter translates between the two systems:"
        ): (
            "README-10-9b5397bf",
            "tests/tool_registry/test_subprocess_runner.py::"
            "test_versioned_round_trip_rebuilds_all_three_protocol_results",
        ),
    }
    for clause_text, (clause_id, representative_node) in expected.items():
        row = matrix_by_text[clause_text]
        assert row.clause_id == clause_id
        assert representative_node in row.test_nodeids
        assert row.evidence_fields


@pytest.mark.parametrize(
    "forbidden_field",
    ("authorized_tool_ids", "authorization_reference"),
)
def test_public_request_rejects_fenced_forbidden_authority_fields(
    forbidden_field: str,
) -> None:
    payload = {
        "scope": {
            "seeds": ["https://example.test/"],
            "allowed_origins": ["https://example.test"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": None,
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 1,
            "max_bytes": 1024,
            "max_runtime_seconds": 1,
            "max_tool_attempts_per_target": 1,
        },
        forbidden_field: "forbidden",
    }

    with pytest.raises(RequestValidationError, match="request.unknown_field"):
        request_from_mapping(payload)


def test_default_runtime_composition_disables_browser_target_reads(
    tmp_path: Path,
) -> None:
    service = RuntimeService.open(tmp_path / "runtime")
    try:
        acquisitions = service._registry.query(  # pylint: disable=protected-access
            category=ToolCategory.ACQUISITION
        )
    finally:
        service.close()

    browser_tool_ids = frozenset(
        {
            "acquisition.playwright",
            "acquisition.cloakbrowser",
            "acquisition.browseract",
        }
    )
    registered_ids = frozenset(manifest.tool_id for manifest in acquisitions)
    runtime_run_source = inspect.getsource(RuntimeService.run)
    target_read_source = inspect.getsource(workflow_module.run_single_target)

    assert acquisitions == (WEB_HTTP_MANIFEST,)
    assert registered_ids.isdisjoint(browser_tool_ids)
    assert "run_single_target(" in runtime_run_source
    assert "run_agent_assisted_exploration" not in runtime_run_source
    assert "registry.query(category=ToolCategory.ACQUISITION)" in target_read_source


def test_valid_site_skill_uses_preferred_tool_without_rediscovery_or_alternate(
    tmp_path: Path,
) -> None:
    base_request = _request()
    skill = create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=base_request.scope,
        budgets=base_request.budgets,
        tool=ToolReference(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            ToolCategory.ACQUISITION,
            WEB_HTTP_MANIFEST.capabilities,
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=DiscoveryRecipe(
            ToolReference(
                HTML_LINKS_MANIFEST.tool_id,
                HTML_LINKS_MANIFEST.version,
                ToolCategory.DISCOVERY,
                HTML_LINKS_MANIFEST.capabilities,
            ),
            ROOT,
        ),
    ).skill
    validate_site_skill(skill)
    request = Request(
        base_request.scope,
        skill,
        True,
        base_request.budgets,
    )
    preferred = _SequenceAcquisition({ROOT: [("text/html", _html("preferred"))]})
    alternate = _SequenceAcquisition(
        {ROOT: [("text/html", _html("unexpected alternate"))]}
    )
    alternate.manifest = replace(
        WEB_HTTP_MANIFEST,
        tool_id="acquisition.round3_alternate",
    )
    discovery = _SequenceDiscovery([(HTML,)])
    registry = _registry(preferred, discovery)
    registry.register(alternate.manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")

    result = run_single_target(
        request,
        registry,
        store,
        run_id="validated-skill",
        clock=lambda: NOW,
    )

    acquisition_attempts = tuple(
        attempt
        for attempt in result.attempts
        if attempt.tool_id.startswith("acquisition.")
    )
    assert result.status.value == "completed"
    assert result.site_skill_used is not None
    assert result.site_skill_used.to_dict() == {
        "version": "1",
        "sha256": skill.digest.removeprefix("sha256:"),
    }
    assert [attempt.tool_id for attempt in acquisition_attempts] == [
        WEB_HTTP_MANIFEST.tool_id
    ]
    assert preferred.calls == {ROOT: 1}
    assert discovery.calls == 0
    assert not alternate.calls
    assert all(
        attempt.tool_id not in {HTML_LINKS_MANIFEST.tool_id, alternate.manifest.tool_id}
        for attempt in result.attempts
    )
    store.close()


def test_external_success_preserves_acquisition_contract_fields() -> None:
    manifest = replace(
        WEB_HTTP_MANIFEST,
        tool_id="external.fake",
        distribution=ToolDistribution.INSTALLED,
    )
    fake_tool = (
        Path(__file__).parents[2] / "tests/fixtures/tools/fake_external_tool/v1.py"
    )
    result = SubprocessRunner(
        manifest,
        (sys.executable, str(fake_tool), "content_success"),
    ).invoke(AcquisitionInput(_request(), ROOT))

    assert isinstance(result, AcquisitionOutput)
    assert result.requested_url == result.final_url == ROOT
    assert result.status_code == 200
    assert result.mime_type == "text/html"
    assert result.redirects == ()
    assert (result.tool_id, result.tool_version) == (
        manifest.tool_id,
        manifest.version,
    )
    assert 0 <= result.runtime_ms <= manifest.limits.max_runtime_seconds * 1000


def test_readme_clause_matrix_fails_closed_for_an_unmapped_normative_clause() -> None:
    repository_root = Path(__file__).parents[2]
    frozen = load_frozen_readme(repository_root)
    modified = frozen.text.replace(
        "Rules:\n\n1. Do not transform non-HTML content.",
        (
            "Rules:\n\nA newly invented transform rule must be enforced.\n\n"
            "1. Do not transform non-HTML content."
        ),
        1,
    )

    with pytest.raises(ValueError, match="baseline_readme.unmapped_clause"):
        readme_evidence_matrix(modified)


def test_readme_rows_bind_only_direct_contract_evidence() -> None:
    frozen = load_frozen_readme(Path(__file__).parents[2])
    by_id = {row.clause_id: row for row in readme_evidence_matrix(frozen.text)}
    expected = {
        "README-01-ddc80093": (
            (
                "tests/runtime/test_service.py::"
                "test_no_ai_fake_transport_completes_one_exact_acquisition",
                "tests/parity/test_phase_20_new_system_delivery.py::"
                "test_first_state_projects_only_real_results_and_strictly_persists",
            ),
            ("source HTML Artifact/Observation", "source PDF Artifact/Observation"),
        ),
        "README-10-025191e7": (
            (
                "tests/tool_registry/test_subprocess_runner.py::"
                "test_versioned_round_trip_rebuilds_all_three_protocol_results",
                "tests/tool_registry/test_subprocess_runner.py::"
                "test_external_safe_failure_reuses_category_protocol",
                "tests/tool_registry/test_subprocess_runner.py::"
                "test_external_rejection_reuses_category_failure_and_safe_code",
            ),
            ("external success", "external failed", "external rejected"),
        ),
        "README-10-42469e95": (
            (
                "tests/parity/test_phase_20_new_system_delivery.py::"
                "test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.requested_url/final_url",),
        ),
        "README-10-4b337c01": (
            (
                "tests/parity/test_phase_20_new_system_delivery.py::"
                "test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.status_code",),
        ),
        "README-10-06db4986": (
            (
                "tests/parity/test_phase_20_new_system_delivery.py::"
                "test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.mime_type",),
        ),
        "README-10-181f83da": (
            (
                "tests/parity/test_phase_20_new_system_delivery.py::"
                "test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.redirects",),
        ),
        "README-10-f7560b6f": (
            (
                "tests/parity/test_phase_20_new_system_delivery.py::"
                "test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.tool_id/tool_version/runtime_ms",),
        ),
        "README-10-9650f26a": (
            (
                "tests/tool_registry/test_subprocess_runner.py::"
                "test_external_safe_failure_reuses_category_protocol",
                "tests/tool_registry/test_subprocess_runner.py::"
                "test_external_rejection_reuses_category_failure_and_safe_code",
            ),
            ("external.unavailable", "external.unsupported"),
        ),
        "README-12-884cf8e2": (
            (
                "tests/runtime/test_transform_flow.py::"
                "test_success_stores_derived_markdown_lineage_and_tool_attempt",
            ),
            ("eligible HTML", "derived Markdown", "Transform Attempt"),
        ),
        "README-19-03": (
            (
                "tests/interfaces/test_mcp.py::"
                "test_complete_client_stdio_server_boundary",
            ),
            ("real MCP client", "governed Result"),
        ),
        "README-19-07": (
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::"
                "test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("full eligible intersection", "stable eligibility reasons"),
        ),
        "README-19-16": (
            (
                "tests/tool_registry/test_registry.py::"
                "test_registration_does_not_change_public_request_shape_or_source",
                "tests/interfaces/test_cli.py::"
                "test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
                "tests/interfaces/test_rest.py::"
                "test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema",
                "tests/interfaces/test_mcp.py::"
                "test_complete_client_stdio_server_boundary",
            ),
            (
                "registration before/after Request shape",
                "CLI Request contract",
                "REST Request contract",
                "MCP Request contract",
            ),
        ),
    }

    for clause_id, (nodeids, evidence_fields) in expected.items():
        row = by_id[clause_id]
        assert row.test_nodeids == nodeids
        assert row.evidence_fields == evidence_fields


def test_first_state_projects_only_real_results_and_strictly_persists(
    tmp_path: Path,
) -> None:
    pdf_body = b"%PDF-1.7\nfirst fixture document\n%%EOF"
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
            PDF: [("application/pdf", pdf_body)],
        }
    )
    discovery = _SequenceDiscovery([(HTML, PDF)])
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    _request_value, first, skill, state = _first_run(store, registry)
    results = first.target_results

    state_path = tmp_path / "current-site-state.json"
    persist_site_state(state_path, state)
    loaded = load_site_state(state_path)
    assert loaded == state
    assert loaded.site_skill_digest == skill.digest
    assert len(loaded.pages) == 3
    by_url = {page.canonical_url: page for page in loaded.pages}
    for result in results:
        source = next(item for item in result.artifacts if item.role == "source")
        page = by_url[source.source_url]
        stored = store.get_observation(source.observation_id)
        assert (page.artifact_id, page.observation_id, page.content_digest) == (
            source.artifact_id,
            source.observation_id,
            f"sha256:{source.sha256}",
        )
        assert stored.artifact.artifact_id == source.artifact_id
        assert stored.observation.source_url == source.source_url
        assert stored.blob.sha256 == source.sha256

    records = tuple(delivery_record(result) for result in results)
    assert any(
        any(item["mime_type"] == "text/markdown" for item in record["artifacts"])
        for record in records
    )
    pdf_record = next(
        record
        for record in records
        if any(item["mime_type"] == "application/pdf" for item in record["artifacts"])
    )
    assert len(pdf_record["artifacts"]) == 1
    pdf_artifact = pdf_record["artifacts"][0]
    assert (
        pdf_artifact["role"],
        pdf_artifact["mime_type"],
        pdf_artifact["size_bytes"],
        pdf_artifact["sha256"],
        pdf_artifact["tool_id"],
        pdf_artifact["tool_version"],
        pdf_artifact["observed_at"],
        pdf_artifact["lineage"],
    ) == (
        "source",
        "application/pdf",
        len(pdf_body),
        hashlib.sha256(pdf_body).hexdigest(),
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        NOW,
        [],
    )
    assert str(pdf_artifact["artifact_id"]).startswith("artifact-")
    assert str(pdf_artifact["observation_id"]).startswith("observation-")
    pdf_result = next(
        result
        for result in results
        if any(item.mime_type == "application/pdf" for item in result.artifacts)
    )
    pdf_source = next(item for item in pdf_result.artifacts if item.role == "source")
    assert store.get_observation(pdf_source.observation_id).content == pdf_body
    assert ROOT not in json.dumps(records, sort_keys=True)
    store.close()


def test_first_acquisition_uses_only_the_actual_discovery_output(
    tmp_path: Path,
) -> None:
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
            PDF: [("application/pdf", b"%PDF-1.7\nnot discovered\n%%EOF")],
        }
    )
    discovery = _SequenceDiscovery([(HTML,)])
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")

    _first_run(store, registry)

    assert acquisition.calls == {ROOT: 1, HTML: 1}
    assert discovery.calls == 1
    store.close()


def test_unchanged_refresh_emits_empty_update_feed_and_reuses_blob(
    tmp_path: Path,
) -> None:
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
            PDF: [("application/pdf", b"%PDF-1.7\nstable bytes fixture\n%%EOF")],
        }
    )
    discovery = _SequenceDiscovery([(HTML, PDF)])
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    request, _first, skill, first_state = _first_run(store, registry)

    refresh = run_site_refresh(
        SiteRefreshRequest(
            request.scope,
            skill,
            first_state,
            False,
            request.budgets,
        ),
        registry,
        store,
        run_id="refresh-unchanged",
        clock=lambda: NOW,
    )
    feed = build_update_feed(refresh)
    record = refresh_record(refresh, store)

    assert refresh.refresh_complete is True
    assert not refresh.added + refresh.changed + refresh.missing + refresh.failed
    assert len(refresh.unchanged) == 3
    assert feed["updates"] == []
    assert feed["audit"]["unchanged_count"] == 3
    assert record["target_results"] == [
        delivery_record(result) for result in refresh.target_results
    ]
    assert [item["manifest"]["run_id"] for item in record["target_results"]] == [
        result.manifest.run_id for result in refresh.target_results
    ]
    for target_record, target_result in zip(
        record["target_results"], refresh.target_results, strict=True
    ):
        assert target_record["request_identity"]["run_id"] == (
            target_result.manifest.run_id
        )
        assert target_record["http"]["http_status"] == (
            target_result.manifest.http_status
        )
        assert target_record["http"]["mime_type"] == target_result.manifest.mime_type
        assert len(target_record["http"]["redirects"]) == len(
            target_result.manifest.redirects
        )
    encoded_record = json.dumps(record, sort_keys=True)
    assert all(url not in encoded_record for url in (ROOT, HTML, PDF))
    for url in (ROOT, HTML, PDF):
        previous = next(page for page in first_state.pages if page.canonical_url == url)
        current = next(
            page for page in refresh.current_state.pages if page.canonical_url == url
        )
        assert previous.observation_id != current.observation_id
        assert previous.artifact_id == current.artifact_id
        assert previous.content_digest == current.content_digest
    store.close()


def test_html_and_pdf_byte_changes_emit_only_the_corresponding_changed_updates(
    tmp_path: Path,
) -> None:
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [
                ("text/html", _html("html-first")),
                ("text/html", _html("html-second")),
            ],
            PDF: [
                ("application/pdf", b"%PDF-1.7\nfirst pdf bytes\n%%EOF"),
                ("application/pdf", b"%PDF-1.7\nsecond pdf bytes\n%%EOF"),
            ],
        }
    )
    discovery = _SequenceDiscovery([(HTML, PDF)])
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    request, _first, skill, first_state = _first_run(store, registry)

    refresh = run_site_refresh(
        SiteRefreshRequest(
            request.scope,
            skill,
            first_state,
            False,
            request.budgets,
        ),
        registry,
        store,
        run_id="refresh-changed",
        clock=lambda: NOW,
    )
    feed = build_update_feed(refresh)

    assert {change.url for change in refresh.changed} == {HTML, PDF}
    assert {change.url for change in refresh.unchanged} == {ROOT}
    assert {item["change_type"] for item in feed["updates"]} == {"changed"}
    assert {item["url_id"] for item in feed["updates"]} == {
        f"sha256:{hashlib.sha256(url.encode()).hexdigest()}" for url in (HTML, PDF)
    }
    for url in (HTML, PDF):
        previous = next(page for page in first_state.pages if page.canonical_url == url)
        current = next(
            page for page in refresh.current_state.pages if page.canonical_url == url
        )
        assert previous.observation_id != current.observation_id
        assert previous.artifact_id != current.artifact_id
        assert previous.content_digest != current.content_digest
    store.close()


def test_added_missing_and_failed_are_never_reported_as_unchanged(
    tmp_path: Path,
) -> None:
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            MISSING: [("application/pdf", b"%PDF-1.7\nmissing later\n%%EOF")],
            FAILED: [
                ("text/html", _html("initial success")),
                "gateway.transport",
            ],
            ADDED: [("text/html", _html("newly added"))],
        }
    )
    discovery = _SequenceDiscovery([(FAILED, MISSING), (ADDED, FAILED)])
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    request, _first, skill, first_state = _first_run(store, registry)

    refresh = run_site_refresh(
        SiteRefreshRequest(
            request.scope,
            skill,
            first_state,
            False,
            request.budgets,
        ),
        registry,
        store,
        run_id="refresh-mixed",
        clock=lambda: NOW,
    )
    feed = build_update_feed(refresh)

    assert {change.url for change in refresh.added} == {ADDED}
    assert {change.url for change in refresh.missing} == {MISSING}
    assert {change.url for change in refresh.failed} == {FAILED}
    assert {change.url for change in refresh.unchanged} == {ROOT}
    assert [item["change_type"] for item in feed["updates"]] == [
        "added",
        "missing",
        "failed",
    ]
    assert all(item["change_type"] != "unchanged" for item in feed["updates"])
    assert feed["audit"]["counts"] == {
        "added": 1,
        "changed": 0,
        "unchanged": 1,
        "missing": 1,
        "failed": 1,
        "unresolved": 0,
    }
    store.close()


def test_delivery_record_has_complete_safe_result_manifest_and_artifact_fields(
    tmp_path: Path,
) -> None:
    acquisition = _SequenceAcquisition(
        {
            ROOT: [("text/html", _html("root"))],
            HTML: [("text/html", _html("html"))],
        }
    )
    discovery = _SequenceDiscovery([(HTML,)])
    registry = _registry(acquisition, discovery)
    store = ArtifactStore(tmp_path / "artifacts")
    _request_value, first, _skill, _state = _first_run(store, registry)
    record = delivery_record(first.target_results[0])

    assert set(record["result"]) == {
        "status",
        "site_skill_used",
        "site_skill_update",
        "attempts",
        "usage",
        "errors",
    }
    assert set(record["http"]) == {
        "requested_url_id",
        "final_url_id",
        "http_status",
        "mime_type",
        "redirects",
    }
    assert set(record["manifest"]) == {
        "schema_version",
        "run_id",
        "site_skill",
        "usage",
    }
    assert set(record["artifacts"][0]) == {
        "artifact_id",
        "observation_id",
        "role",
        "mime_type",
        "size_bytes",
        "sha256",
        "tool_id",
        "tool_version",
        "observed_at",
        "lineage",
    }
    encoded = json.dumps(record, sort_keys=True)
    assert ROOT not in encoded
    assert "five visible words" not in encoded
    assert "authorization" not in encoded.casefold()
    store.close()
