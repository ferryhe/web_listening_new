"""Availability-first SOA/CAS/IAA batch evidence; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,too-few-public-methods
# pylint: disable=too-many-locals,too-many-statements

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.request.site_batch import (
    SiteBatchPhase,
    SiteBatchRequest,
    site_batch_request_from_mapping,
)
from web_listening.result.site_batch import SiteBatchMode
from web_listening.runtime.site_batch import (
    run_site_batch,
    site_batch_result_from_mapping,
)
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_LINKS_MANIFEST,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.eligibility import EligibilityRequirements
from web_listening.tool_registry.manifest import ToolCategory
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

ROOT = Path(__file__).resolve().parents[2]
TARGETS = Path(__file__).with_name("phase_20_availability_first_batch_targets.json")
CATALOG = Path(__file__).parent / "catalog" / "dev_test_sites.json"
SITE_KEYS = ("soa", "cas", "iaa")
FILE_SUFFIXES = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip")
DISCOVERY_MANIFEST = replace(
    HTML_LINKS_MANIFEST,
    tool_id="discovery.live_document_links",
    capabilities=HTML_LINKS_MANIFEST.capabilities | {"document_links"},
)


def _catalog_sha256(content: bytes) -> str:
    normalized = content.replace(b"\r\n", b"\n")
    return hashlib.sha256(normalized).hexdigest().upper()


def _projection(row: dict[str, object]) -> dict[str, object]:
    urls = row["urls"]
    assert isinstance(urls, dict)
    historical = row["historical_classification"]
    assert isinstance(historical, dict)
    return {
        "site_key": row["site_key"],
        "monitor_url": urls["monitor"],
        "document_url": urls["document"],
        "allowed_origins": row["allowed_origins"],
        "historical_expectation": historical["expectation"],
        "provenance": row["provenance"],
    }


def _snapshot() -> dict[str, object]:
    payload = json.loads(TARGETS.read_text(encoding="utf-8"))
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    assert payload["schema_version"] == ("phase-20-availability-first-batch-targets.v1")
    assert payload["source_catalog_path"] == ("tests/live/catalog/dev_test_sites.json")
    assert payload["source_catalog_sha256"] == _catalog_sha256(CATALOG.read_bytes())
    rows = catalog["sites"]
    expected = [_projection(row) for row in rows if row["site_key"] in SITE_KEYS]
    assert payload["targets"] == expected
    assert tuple(row["site_key"] for row in payload["targets"]) == SITE_KEYS
    return payload


def _authorized_snapshot() -> dict[str, object]:
    payload = _snapshot()
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("availability-first live batch is offline by default")
    window = os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip()
    if not window:
        pytest.skip("an explicit live authorization window is required")
    return payload


class _DocumentLinksDiscovery:
    """Select real file/download links, with HTML fallback, from one HTML page."""

    manifest = DISCOVERY_MANIFEST

    def __init__(self) -> None:
        self._delegate = HtmlLinksDiscoveryTool()

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        output = self._delegate.discover(tool_input)
        if isinstance(output, DiscoveryFailure):
            return DiscoveryFailure(
                self.manifest.tool_id,
                self.manifest.version,
                output.code,
            )
        assert output.discovered_from is not None
        by_url = dict(zip(output.candidates, output.discovered_from, strict=True))
        files = tuple(
            url
            for url in sorted(by_url)
            if urlsplit(url).path.casefold().endswith(FILE_SUFFIXES)
            or "/download" in urlsplit(url).path.casefold()
        )
        selected = files or tuple(sorted(by_url))
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            selected,
            tuple(by_url[url] for url in selected),
            output.coverage,
        )


class _SiteNetworkBudget:
    def __init__(self, requests: int, response_bytes: int, timeout: int) -> None:
        self.max_requests = requests
        self.max_response_bytes = response_bytes
        self.timeout_seconds = timeout
        self.requests = 0
        self.response_bytes = 0
        self.deadline: float | None = None

    def start(self) -> None:
        if self.deadline is None:
            self.deadline = time.monotonic() + self.timeout_seconds

    @property
    def remaining_seconds(self) -> float:
        self.start()
        assert self.deadline is not None
        return max(0.0, self.deadline - time.monotonic())


class _PhaseNetworkBudgets:
    def __init__(self, site_keys: tuple[str, ...], limits: dict[str, int]) -> None:
        self.by_site = {
            site_key: _SiteNetworkBudget(
                limits["max_requests"],
                limits["max_response_bytes"],
                limits["timeout_seconds"],
            )
            for site_key in site_keys
        }

    def for_url(self, url: str) -> _SiteNetworkBudget:
        host = urlsplit(url).hostname or "invalid"
        return self.by_site[host]

    def evidence(self) -> dict[str, dict[str, int]]:
        return {
            site_key: {
                "requests": budget.requests,
                "response_bytes": budget.response_bytes,
                "timeout_seconds": budget.timeout_seconds,
            }
            for site_key, budget in self.by_site.items()
        }


class _CappedResponse:
    def __init__(
        self,
        response: TransportResponse,
        budget: _SiteNetworkBudget,
    ) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_response_bytes - self._budget.response_bytes
        if self._budget.remaining_seconds <= 0 or remaining <= 0:
            raise TimeoutError
        content = self._response.read(min(max_bytes, remaining))
        self._budget.response_bytes += len(content)
        return content

    def set_timeout(self, timeout: float) -> None:
        remaining = self._budget.remaining_seconds
        if remaining <= 0:
            raise TimeoutError
        self._response.set_timeout(min(timeout, remaining))

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(self, budgets: _PhaseNetworkBudgets) -> None:
        self._budgets = budgets
        self._transport = PinnedHttpTransport()

    def send(
        self,
        url: str,
        *,
        timeout: float,
        addresses: tuple[str, ...],
    ) -> _CappedResponse:
        budget = self._budgets.for_url(url)
        if budget.remaining_seconds <= 0 or budget.requests >= budget.max_requests:
            raise TimeoutError
        budget.requests += 1
        response = self._transport.send(
            url,
            timeout=min(timeout, budget.remaining_seconds),
            addresses=addresses,
        )
        return _CappedResponse(response, budget)

    def close(self) -> None:
        self._transport.close()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _request(payload: dict[str, object]) -> Request:
    targets = payload["targets"]
    limits = payload["limits_per_site_per_phase"]
    assert isinstance(targets, list) and isinstance(limits, dict)
    return Request(
        Scope(
            tuple(str(row["document_url"]) for row in targets),
            tuple(origin for row in targets for origin in row["allowed_origins"]),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        True,
        Budgets(
            limits["max_requests"],
            limits["max_response_bytes"],
            limits["timeout_seconds"],
            limits["max_tool_attempts_per_target"],
        ),
    )


def _registry(
    budgets: _PhaseNetworkBudgets,
) -> tuple[Registry, WebHttpAcquisitionTool]:
    acquisition = WebHttpAcquisitionTool(lambda: _CappedTransport(budgets))
    registry = Registry()
    registry.register(DISCOVERY_MANIFEST, _DocumentLinksDiscovery())
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(
        SIMPLE_HTML_MARKDOWN_MANIFEST,
        SimpleHtmlMarkdownTransform(),
    )
    return registry, acquisition


def test_phase_20_document_discovery_is_eligible_for_html() -> None:
    registry = Registry()
    registry.register(DISCOVERY_MANIFEST, _DocumentLinksDiscovery())
    requirements = EligibilityRequirements(
        ToolCategory.DISCOVERY,
        frozenset({"html_links"}),
    )

    (decision,) = registry.eligibility(requirements)
    assert decision.eligible, decision.reasons
    assert decision.reasons == ()
    assert registry.eligible(requirements) == (DISCOVERY_MANIFEST,)


def _artifacts(batch) -> tuple[object, ...]:
    return tuple(
        artifact
        for child in batch.site_results
        for target in child.target_results
        for artifact in target.artifacts
    )


def test_phase_20_availability_first_snapshot_is_exact_and_bounded() -> None:
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
    source = Path(__file__).read_text(encoding="utf-8")
    assert "WEB_LISTENING_" + "LIVE_URL" not in source
    assert source.count("run_site_" + "batch(") == 2
    assert source.count("@pytest.mark." + "live") == 1
    assert 'os.environ.get("WEB_LISTENING_' + 'RUN_LIVE")' in source
    assert "WEB_LISTENING_" + "LIVE_AUTHORIZED_WINDOW" in source


@pytest.mark.live
def test_phase_20_availability_first_batch_live(tmp_path: Path) -> None:
    payload = _authorized_snapshot()
    parent = _request(payload)
    limits = payload["limits_per_site_per_phase"]
    assert isinstance(limits, dict)
    hosts = tuple(urlsplit(seed).hostname or "invalid" for seed in parent.scope.seeds)
    first_network = _PhaseNetworkBudgets(hosts, limits)
    refresh_network = _PhaseNetworkBudgets(hosts, limits)
    first_registry, first_acquisition = _registry(first_network)
    refresh_registry, refresh_acquisition = _registry(refresh_network)
    store = ArtifactStore(tmp_path / "phase-20-availability-first")

    try:
        first = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, ()),
            first_registry,
            store,
            run_id="phase-20-availability-first",
            clock=_now,
        )
        persisted_first = site_batch_result_from_mapping(
            json.loads(first.canonical_json_bytes())
        )
        refresh_request = site_batch_request_from_mapping(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                parent,
                persisted_first.next_refresh_contexts,
            ).to_dict()
        )
        refresh = run_site_batch(
            refresh_request,
            refresh_registry,
            store,
            run_id="phase-20-availability-refresh",
            clock=_now,
        )
        persisted_refresh = site_batch_result_from_mapping(
            json.loads(refresh.canonical_json_bytes())
        )

        assert len(first.usable_site_keys) >= 3
        assert first.usable_site_keys == first.site_keys
        assert len(first.next_refresh_contexts) == len(first.site_keys)
        assert persisted_first.next_refresh_contexts == first.next_refresh_contexts
        assert refresh.usable_site_keys == refresh.site_keys
        assert len(refresh.next_refresh_contexts) == len(refresh.site_keys)
        assert persisted_refresh == refresh
        assert all(mode is not SiteBatchMode.FAILED for mode in refresh.site_modes)

        first_artifacts = _artifacts(first)
        assert any(
            item.role == "source" and item.mime_type == "text/html"
            for item in first_artifacts
        )
        markdown = tuple(
            item
            for item in first_artifacts
            if item.role == "derived" and item.mime_type == "text/markdown"
        )
        assert markdown and all(item.lineage for item in markdown)
        files = tuple(
            item
            for item in first_artifacts
            if item.role == "source"
            and item.mime_type not in {"application/xhtml+xml", "text/html"}
        )
        assert files
        discovered = {
            url
            for child in first.site_results
            for evidence in child.discovery
            for url in evidence.candidates
        }
        acquired = {
            attempt.requested_url
            for child in first.site_results
            for attempt in child.attempts
            if attempt.outcome == "succeeded" and attempt.final_url is not None
        }
        assert {item.source_url for item in files}.issubset(discovered & acquired)

        previous_observations = {
            page.observation_id
            for child in refresh.site_results
            for page in child.previous_state.pages
        }
        current_observations = {
            page.observation_id
            for child in refresh.site_results
            for page in child.current_state.pages
        }
        assert previous_observations.isdisjoint(current_observations)
        unchanged = tuple(
            change for child in refresh.site_results for change in child.unchanged
        )
        assert unchanged
        for change in unchanged:
            assert change.previous is not None and change.current is not None
            previous = store.get_observation(
                next(
                    page.observation_id
                    for child in refresh.site_results
                    for page in child.previous_state.pages
                    if page.canonical_url == change.url
                )
            )
            current = store.get_observation(
                next(
                    page.observation_id
                    for child in refresh.site_results
                    for page in child.current_state.pages
                    if page.canonical_url == change.url
                )
            )
            assert previous.blob.sha256 == current.blob.sha256

        delivery = tuple(
            change.url
            for child in refresh.site_results
            for name in ("added", "changed", "missing", "failed", "unresolved")
            for change in getattr(child, name)
        )
        assert not {change.url for change in unchanged}.intersection(delivery)
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
            for row in phase.evidence().values()
        )
    print(
        json.dumps(
            {
                "authorized_window": os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"],
                "first": first.to_dict(),
                "refresh": refresh.to_dict(),
                "first_physical_network": first_network.evidence(),
                "refresh_physical_network": refresh_network.evidence(),
                "update_feed": delivery,
            },
            sort_keys=True,
        )
    )
