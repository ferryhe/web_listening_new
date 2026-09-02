"""Required file-discovery goal evidence for fixed CAS/IAA seeds."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-locals
# pylint: disable=too-many-statements

from __future__ import annotations

import hashlib
import json
import os
import runpy
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.site_batch import (
    FileDiscoveryGoal,
    SiteBatchPhase,
    SiteBatchRequest,
    SiteBatchSite,
    site_batch_child_scope,
    site_batch_request_from_mapping,
)
from web_listening.result.model import ResultStatus
from web_listening.result.site_batch import FileDiscoveryStatus
from web_listening.runtime.site_batch import (
    run_site_batch,
    site_batch_result_from_mapping,
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
from web_listening.tool_registry.manifest import ToolCategory
from web_listening.tool_registry.registry import Registry

TARGETS = Path(__file__).with_name("phase_20_discovery_goal_targets.json")
CATALOG = Path(__file__).parent / "catalog" / "dev_test_sites.json"
SITE_KEYS = ("cas", "iaa")
_AVAILABILITY = runpy.run_path(
    str(Path(__file__).with_name("test_phase_20_availability_first_batch_live.py"))
)
_PhaseNetworkBudgets = _AVAILABILITY["_PhaseNetworkBudgets"]
_CappedTransport = _AVAILABILITY["_CappedTransport"]
_request = _AVAILABILITY["_request"]
_now = _AVAILABILITY["_now"]


def _catalog_sha256(content: bytes) -> str:
    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest().upper()


def _projection(row: dict[str, object], goal: str) -> dict[str, object]:
    urls = row["urls"]
    historical = row["historical_classification"]
    assert isinstance(urls, dict) and isinstance(historical, dict)
    return {
        "site_key": row["site_key"],
        "monitor_url": urls["monitor"],
        "document_url": urls["document"],
        "allowed_origins": row["allowed_origins"],
        "historical_expectation": historical["expectation"],
        "file_discovery_goal": goal,
        "provenance": row["provenance"],
    }


def _snapshot() -> dict[str, object]:
    payload = json.loads(TARGETS.read_text(encoding="utf-8"))
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "phase-20-discovery-goal-targets.v1"
    assert payload["source_catalog_path"] == "tests/live/catalog/dev_test_sites.json"
    assert payload["source_catalog_sha256"] == _catalog_sha256(CATALOG.read_bytes())
    rows = {
        row["site_key"]: row for row in catalog["sites"] if row["site_key"] in SITE_KEYS
    }
    expected = [
        _projection(rows["cas"], "required"),
        _projection(rows["iaa"], "not_required"),
    ]
    assert payload["targets"] == expected
    assert tuple(row["site_key"] for row in payload["targets"]) == SITE_KEYS
    assert all("file_url" not in row and "pdf_url" not in row for row in expected)
    return payload


def _authorized_snapshot() -> dict[str, object]:
    payload = _snapshot()
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("discovery-goal live batch is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.skip("an explicit live authorization window is required")
    return payload


def _sites(parent, payload: dict[str, object]) -> tuple[SiteBatchSite, ...]:
    targets = payload["targets"]
    assert isinstance(targets, list)
    return tuple(
        SiteBatchSite(
            site_batch_child_scope(parent.scope, seed),
            row["file_discovery_goal"],
        )
        for seed, row in zip(parent.scope.seeds, targets, strict=True)
    )


def _registry(
    budgets: object,
) -> tuple[Registry, WebHttpAcquisitionTool]:
    acquisition = WebHttpAcquisitionTool(lambda: _CappedTransport(budgets))
    registry = Registry()
    registry.register(HTML_FILE_LINKS_MANIFEST, HtmlFileLinksDiscoveryTool())
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    return registry, acquisition


def _required_file_urls(batch) -> frozenset[str]:
    urls: set[str] = set()
    for child, status in zip(
        batch.site_results,
        batch.file_discovery_statuses,
        strict=True,
    ):
        if status is not FileDiscoveryStatus.SATISFIED:
            continue
        for target in child.target_results[1:]:
            source = next(
                (
                    artifact
                    for artifact in target.artifacts
                    if artifact.role == "source"
                ),
                None,
            )
            if source is not None and source.mime_type not in {
                "application/xhtml+xml",
                "text/html",
            }:
                urls.add(source.source_url)
    return frozenset(urls)


def test_required_file_urls_accepts_partial_file_but_not_partial_xhtml() -> None:
    xhtml_source = SimpleNamespace(
        role="source",
        mime_type="application/xhtml+xml",
        source_url="https://example.test/a.xhtml",
    )
    pdf_source = SimpleNamespace(
        role="source",
        mime_type="application/pdf",
        source_url="https://example.test/report.pdf",
    )
    child = SimpleNamespace(
        target_results=(
            SimpleNamespace(status=ResultStatus.COMPLETED, artifacts=()),
            SimpleNamespace(
                status=ResultStatus.PARTIAL,
                artifacts=(xhtml_source,),
            ),
            SimpleNamespace(status=ResultStatus.PARTIAL, artifacts=(pdf_source,)),
        )
    )
    batch = SimpleNamespace(
        site_results=(child,),
        file_discovery_statuses=(FileDiscoveryStatus.SATISFIED,),
    )

    assert _required_file_urls(batch) == frozenset({pdf_source.source_url})


def test_phase_20_discovery_goal_snapshot_is_exact_and_bounded() -> None:
    payload = _snapshot()
    limits = payload["limits_per_site_per_phase"]

    assert limits == {
        "max_requests": 12,
        "max_response_bytes": 52_428_800,
        "timeout_seconds": 60,
        "max_tool_attempts_per_target": 4,
        "concurrency": 1,
        "retry": 0,
    }
    parent = _request(payload)
    sites = _sites(parent, payload)
    assert sites[0].file_discovery_goal is FileDiscoveryGoal.REQUIRED
    assert sites[1].file_discovery_goal is FileDiscoveryGoal.NOT_REQUIRED
    assert (
        site_batch_request_from_mapping(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites).to_dict()
        ).sites
        == sites
    )
    source = Path(__file__).read_text(encoding="utf-8")
    assert "WEB_LISTENING_" + "LIVE_URL" not in source
    assert "WEB_LISTENING_" + "LIVE_SITE" not in source
    assert source.count("run_site_" + "batch(") == 2
    assert source.count("@pytest.mark." + "live") == 1
    assert '_AVAILABILITY["_' + 'registry"]' not in source
    assert "_DocumentLinks" + "Discovery" not in source
    assert "FILE_" + "SUFFIXES" not in source
    offline_network = _PhaseNetworkBudgets(
        tuple(urlsplit(seed).hostname or "invalid" for seed in parent.scope.seeds),
        limits,
    )
    registry, acquisition = _registry(offline_network)
    try:
        assert registry.query(category=ToolCategory.DISCOVERY) == (
            HTML_FILE_LINKS_MANIFEST,
            HTML_LINKS_MANIFEST,
        )
    finally:
        acquisition.close()


@pytest.mark.live
def test_phase_20_discovery_goal_live(tmp_path: Path) -> None:
    payload = _authorized_snapshot()
    parent = _request(payload)
    sites = _sites(parent, payload)
    limits = payload["limits_per_site_per_phase"]
    assert isinstance(limits, dict)
    hosts = tuple(urlsplit(seed).hostname or "invalid" for seed in parent.scope.seeds)
    first_network = _PhaseNetworkBudgets(hosts, limits)
    refresh_network = _PhaseNetworkBudgets(hosts, limits)
    first_registry, first_acquisition = _registry(first_network)
    refresh_registry, refresh_acquisition = _registry(refresh_network)
    store = ArtifactStore(tmp_path / "phase-20-discovery-goal")

    try:
        first_request = site_batch_request_from_mapping(
            SiteBatchRequest(
                SiteBatchPhase.FIRST,
                parent,
                (),
                sites=sites,
            ).to_dict()
        )
        first = run_site_batch(
            first_request,
            first_registry,
            store,
            run_id="phase-20-discovery-goal-first",
            clock=_now,
        )
        persisted_first = site_batch_result_from_mapping(
            json.loads(first.canonical_json_bytes())
        )
        assert persisted_first == first
        assert first.file_discovery_statuses[0] is FileDiscoveryStatus.SATISFIED
        assert first.file_discovery_statuses[1] is (FileDiscoveryStatus.NOT_REQUESTED)
        first_files = _required_file_urls(first)
        assert first_files
        assert len(first.next_refresh_contexts) == len(first.site_keys)

        refresh_request = site_batch_request_from_mapping(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                parent,
                first.next_refresh_contexts,
                sites=sites,
            ).to_dict()
        )
        refresh = run_site_batch(
            refresh_request,
            refresh_registry,
            store,
            run_id="phase-20-discovery-goal-refresh",
            clock=_now,
        )
        persisted_refresh = site_batch_result_from_mapping(
            json.loads(refresh.canonical_json_bytes())
        )
        assert persisted_refresh == refresh
        assert refresh.file_discovery_statuses[0] is (FileDiscoveryStatus.SATISFIED)
        assert refresh.file_discovery_statuses[1] is (FileDiscoveryStatus.NOT_REQUESTED)
        refresh_files = _required_file_urls(refresh)
        reauthorized = first_files & refresh_files
        assert reauthorized
        assert all(
            context.site_skill.scope == site.scope
            for context, site in zip(
                refresh.next_refresh_contexts,
                sites,
                strict=True,
            )
        )
        assert first.usage.requests == sum(
            child.usage.requests for child in first.site_results
        )
        assert refresh.usage.requests == sum(
            child.usage.requests for child in refresh.site_results
        )
    finally:
        first_acquisition.close()
        refresh_acquisition.close()
        store.close()

    for phase in (first_network, refresh_network):
        assert all(
            row["requests"] <= limits["max_requests"]
            and row["response_bytes"] <= limits["max_response_bytes"]
            and row["timeout_seconds"] == limits["timeout_seconds"]
            for row in phase.evidence().values()
        )
    print(
        json.dumps(
            {
                "authorized_window": os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"],
                "first": first.to_dict(),
                "refresh": refresh.to_dict(),
                "reauthorized_file_urls": sorted(reauthorized),
                "first_physical_network": first_network.evidence(),
                "refresh_physical_network": refresh_network.evidence(),
            },
            sort_keys=True,
        )
    )
