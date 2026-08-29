"""Generic Runtime wiring for governed Discovery candidates."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass
from pathlib import Path

import web_listening.runtime.workflow as workflow_module
import web_listening.tool_registry.protocols.discovery as protocol_module
import web_listening.tool_registry.registry as registry_module
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.model import ResultStatus
from web_listening.runtime.workflow import (
    acquire_discovered_candidates,
    discover_candidates,
)
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.registry import Registry

NOW = "2026-08-26T00:00:00Z"
SOURCE_URL = "https://example.test/feed.xml"
DISCOVERY_MANIFEST = ToolManifest(
    "discovery.fake",
    "1.0.0",
    ToolCategory.DISCOVERY,
    ToolDistribution.BUILTIN,
    frozenset({"fixture"}),
    ToolLimits(10, 4096, 4096),
    HealthStatus.HEALTHY,
    QualificationStatus.QUALIFIED,
)
ACQUISITION_MANIFEST = ToolManifest(
    "acquisition.fake",
    "1.0.0",
    ToolCategory.ACQUISITION,
    ToolDistribution.BUILTIN,
    frozenset({"http_get"}),
    ToolLimits(10, 4096, 4096),
    HealthStatus.HEALTHY,
    QualificationStatus.QUALIFIED,
)


@dataclass
class _DiscoveryFake:
    manifest: ToolManifest = DISCOVERY_MANIFEST
    calls: int = 0

    def discover(self, tool_input: DiscoveryInput) -> DiscoveryOutput:
        self.calls += 1
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            (
                "https://outside.test/not-authorized",
                "https://example.test/z",
                "https://example.test/a",
                "https://example.test/z",
            ),
            (tool_input.source_url,) * 4,
            "truncated",
        )


@dataclass
class _AcquisitionFake:
    manifest: ToolManifest = ACQUISITION_MANIFEST
    targets: list[str] | None = None
    budgets: list[Budgets] | None = None

    def __post_init__(self) -> None:
        self.targets = []
        self.budgets = []

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionOutput:
        assert self.targets is not None
        assert self.budgets is not None
        self.targets.append(tool_input.target_url)
        self.budgets.append(tool_input.request.budgets)
        body = tool_input.target_url.encode()
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


def _request(
    budgets: Budgets | None = None,
    *,
    acquisition_manifest: ToolManifest = ACQUISITION_MANIFEST,
) -> Request:
    budgets = budgets or Budgets(12, 4096, 30, 1)
    scope = Scope(
        seeds=("https://example.test/",),
        allowed_origins=("https://example.test",),
        include_paths=("/**",),
        content_types=(ContentType.HTML,),
    )
    skill = create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=ToolReference(
            acquisition_manifest.tool_id,
            acquisition_manifest.version,
            acquisition_manifest.category,
            acquisition_manifest.capabilities,
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, False, budgets)


def test_discovery_is_pure_then_candidates_reauthorize_before_acquisition(
    tmp_path: Path,
) -> None:
    discovery_tool = _DiscoveryFake()
    acquisition_tool = _AcquisitionFake()
    registry = Registry()
    registry.register(DISCOVERY_MANIFEST, discovery_tool)
    registry.register(ACQUISITION_MANIFEST, acquisition_tool)
    store = ArtifactStore(tmp_path / "artifacts")
    commits = 0
    real_commit = store.commit_observation

    def count_commit(proposal):
        nonlocal commits
        commits += 1
        return real_commit(proposal)

    store.commit_observation = count_commit  # type: ignore[method-assign]
    discovery = discover_candidates(
        _request(),
        registry,
        discovery_tool_id=DISCOVERY_MANIFEST.tool_id,
        source_url=SOURCE_URL,
        source_body=b"<fixture/>",
        source_mime_type="application/xml",
    )

    assert isinstance(discovery, DiscoveryOutput)
    assert discovery.coverage == "truncated"
    assert discovery_tool.calls == 1
    assert commits == 0

    outcomes = acquire_discovered_candidates(
        _request(),
        registry,
        store,
        discovery,
        max_candidates=3,
        run_id="discovery-run",
        clock=lambda: NOW,
    )

    assert [outcome.candidate_url for outcome in outcomes] == [
        "https://example.test/a",
        "https://example.test/z",
        "https://outside.test/not-authorized",
    ]
    assert [outcome.discovered_from for outcome in outcomes] == [SOURCE_URL] * 3
    assert [outcome.result.status for outcome in outcomes] == [
        ResultStatus.COMPLETED,
        ResultStatus.COMPLETED,
        ResultStatus.REJECTED,
    ]
    assert acquisition_tool.targets == [
        "https://example.test/a",
        "https://example.test/z",
    ]
    assert commits == 2
    store.close()


def test_candidates_are_sorted_deduplicated_and_max_candidates_bounded(
    tmp_path: Path,
) -> None:
    acquisition_tool = _AcquisitionFake()
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition_tool)
    store = ArtifactStore(tmp_path / "bounded-artifacts")
    discovery = DiscoveryOutput(
        DISCOVERY_MANIFEST.tool_id,
        DISCOVERY_MANIFEST.version,
        tuple(f"https://example.test/{name}" for name in ("d", "b", "a", "b")),
        (SOURCE_URL,) * 4,
        "complete",
    )

    outcomes = acquire_discovered_candidates(
        _request(),
        registry,
        store,
        discovery,
        max_candidates=2,
        run_id="bounded-run",
        clock=lambda: NOW,
    )

    assert [outcome.candidate_url for outcome in outcomes] == [
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert acquisition_tool.targets == [
        "https://example.test/a",
        "https://example.test/b",
    ]
    store.close()


def test_missing_resolved_manifest_rejects_all_candidates_without_gateway_io(
    tmp_path: Path,
) -> None:
    missing_manifest = ToolManifest(
        "acquisition.missing",
        "1.0.0",
        ToolCategory.ACQUISITION,
        ToolDistribution.BUILTIN,
        frozenset({"http_get"}),
        ToolLimits(10, 4096, 4096),
        HealthStatus.HEALTHY,
        QualificationStatus.QUALIFIED,
    )
    acquisition_tool = _AcquisitionFake()
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition_tool)
    store = ArtifactStore(tmp_path / "missing-manifest-artifacts")
    commits = 0
    real_commit = store.commit_observation

    def count_commit(proposal):
        nonlocal commits
        commits += 1
        return real_commit(proposal)

    store.commit_observation = count_commit  # type: ignore[method-assign]

    outcomes = acquire_discovered_candidates(
        _request(acquisition_manifest=missing_manifest),
        registry,
        store,
        DiscoveryOutput(
            DISCOVERY_MANIFEST.tool_id,
            DISCOVERY_MANIFEST.version,
            ("https://example.test/b", "https://example.test/a"),
            (SOURCE_URL, SOURCE_URL),
            "complete",
        ),
        max_candidates=2,
        run_id="missing-manifest-run",
        clock=lambda: NOW,
    )

    assert [outcome.candidate_url for outcome in outcomes] == [
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert [outcome.result.status for outcome in outcomes] == [
        ResultStatus.REJECTED,
        ResultStatus.REJECTED,
    ]
    assert [outcome.result.errors[0].code for outcome in outcomes] == [
        "site_skill.tool_unknown",
        "site_skill.tool_unknown",
    ]
    assert acquisition_tool.targets == []
    assert commits == 0
    store.close()


def test_candidate_outcomes_preserve_sorted_deduplicated_provenance_pairing(
    tmp_path: Path,
) -> None:
    acquisition_tool = _AcquisitionFake()
    registry = Registry()
    registry.register(ACQUISITION_MANIFEST, acquisition_tool)
    store = ArtifactStore(tmp_path / "pairing-artifacts")
    discovery = DiscoveryOutput(
        DISCOVERY_MANIFEST.tool_id,
        DISCOVERY_MANIFEST.version,
        (
            "https://example.test/z",
            "https://example.test/a",
            "https://example.test/z",
        ),
        (
            "https://example.test/source-z-2.xml",
            "https://example.test/source-a.xml",
            "https://example.test/source-z-1.xml",
        ),
        "unknown",
    )

    outcomes = acquire_discovered_candidates(
        _request(),
        registry,
        store,
        discovery,
        max_candidates=3,
        run_id="pairing-run",
        clock=lambda: NOW,
    )

    assert [
        (outcome.candidate_url, outcome.discovered_from) for outcome in outcomes
    ] == [
        ("https://example.test/a", "https://example.test/source-a.xml"),
        ("https://example.test/z", "https://example.test/source-z-1.xml"),
    ]
    assert [outcome.result.manifest.requested_url for outcome in outcomes] == [
        "https://example.test/a",
        "https://example.test/z",
    ]
    store.close()


def test_protocol_registry_and_runtime_wiring_are_feed_kind_agnostic() -> None:
    for module in (protocol_module, registry_module, workflow_module):
        source = inspect.getsource(module).casefold()
        assert "sitemap" not in source
        assert "rss" not in source
