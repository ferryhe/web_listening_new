"""Availability-first serial multi-site Runtime tests."""

# pylint: disable=duplicate-code,missing-function-docstring,too-few-public-methods
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals,too-many-statements

from __future__ import annotations

import hashlib
import json
from asyncio import CancelledError
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from web_listening.artifact.site_state import SiteStatePage
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.request.site_batch import (
    FileDiscoveryGoal,
    SiteBatchPhase,
    SiteBatchRequest,
    SiteBatchSite,
    site_batch_child_scope,
    site_batch_request_from_mapping,
)
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.result.errors import ResultValidationError
from web_listening.result.manifest import Usage
from web_listening.result.model import ResultStatus
from web_listening.result.site_batch import FileDiscoveryStatus, SiteBatchMode
from web_listening.runtime.site_batch import (
    run_site_batch,
    site_batch_result_from_mapping,
)
from web_listening.runtime.site_refresh import run_site_refresh
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.acquisition.builtins.web_http import WEB_HTTP_MANIFEST
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_LINKS_MANIFEST,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.manifest import ToolManifest
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

NOW = "2026-09-01T00:00:00Z"
LIMITS = Budgets(4, 52_428_800, 60, 4)
SEEDS = ("https://one.test/", "https://two.test/", "https://three.test/")
RECOVERY_MANIFEST = replace(
    HTML_LINKS_MANIFEST,
    tool_id="discovery.recovery_links",
)
FIXTURES = Path(__file__).parents[1] / "result" / "fixtures"


@dataclass
class _Acquisition:
    bodies: dict[str, bytes | AcquisitionFailure | type[CancelledError]]
    mime_types: dict[str, str] | None = None
    final_urls: dict[str, str] | None = None
    manifest: ToolManifest = WEB_HTTP_MANIFEST

    def __post_init__(self) -> None:
        self.targets: list[str] = []
        self.budgets: list[Budgets] = []
        self.scopes: list[Scope] = []

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.targets.append(tool_input.target_url)
        self.budgets.append(tool_input.request.budgets)
        self.scopes.append(tool_input.request.scope)
        outcome = self.bodies.get(tool_input.target_url)
        if outcome is CancelledError:
            raise CancelledError
        if outcome is None:
            return AcquisitionFailure(
                self.manifest.tool_id,
                self.manifest.version,
                "gateway.timeout",
            )
        if isinstance(outcome, AcquisitionFailure):
            return outcome
        mime_type = (
            "text/html"
            if self.mime_types is None
            else self.mime_types.get(tool_input.target_url, "text/html")
        )
        final_url = (
            tool_input.target_url
            if self.final_urls is None
            else self.final_urls.get(tool_input.target_url, tool_input.target_url)
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
            mime_type,
            outcome,
            hashlib.sha256(outcome).hexdigest(),
            redirects,
            1,
            len(redirects) + 1,
            len(outcome),
        )


@dataclass
class _StaticDiscovery:
    candidates: dict[str, tuple[str, ...]]
    coverage: str
    manifest: ToolManifest = RECOVERY_MANIFEST

    def discover(self, tool_input: DiscoveryInput) -> DiscoveryOutput:
        candidates = self.candidates[tool_input.source_url]
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            candidates,
            (tool_input.source_url,) * len(candidates),
            self.coverage,
        )


def _parent(*, limits: Budgets = LIMITS, count: int = 3) -> Request:
    seeds = SEEDS[:count]
    return Request(
        Scope(
            seeds,
            tuple(seed.rstrip("/") for seed in seeds),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        True,
        limits,
    )


def _standard_bodies(count: int = 3) -> dict[str, bytes]:
    bodies: dict[str, bytes] = {}
    for seed in SEEDS[:count]:
        bodies[seed] = b"<main>seed words <a href='/a'>a</a></main>"
        bodies[f"{seed}a"] = b"<main>candidate words</main>"
    return bodies


def _registry(
    acquisition: _Acquisition,
    *,
    discovery_manifest: ToolManifest = HTML_LINKS_MANIFEST,
    discovery: object | None = None,
    transform: bool = False,
) -> Registry:
    registry = Registry()
    registry.register(
        discovery_manifest,
        HtmlLinksDiscoveryTool() if discovery is None else discovery,
    )
    registry.register(acquisition.manifest, acquisition)
    if transform:
        registry.register(
            SIMPLE_HTML_MARKDOWN_MANIFEST,
            SimpleHtmlMarkdownTransform(),
        )
    return registry


def _first_batch(
    tmp_path: Path,
    *,
    count: int = 3,
    limits: Budgets = LIMITS,
):
    acquisition = _Acquisition(_standard_bodies(count))
    store = ArtifactStore(tmp_path / "artifacts")
    result = run_site_batch(
        SiteBatchRequest(SiteBatchPhase.FIRST, _parent(limits=limits, count=count), ()),
        _registry(acquisition),
        store,
        run_id="first-batch",
        clock=lambda: NOW,
    )
    return result, acquisition, store


def test_first_batch_is_stable_and_resets_each_site_budget(tmp_path: Path) -> None:
    first, acquisition, store = _first_batch(tmp_path)
    try:
        assert first.status is ResultStatus.COMPLETED
        assert first.site_keys == ("one.test", "two.test", "three.test")
        assert first.site_modes == (SiteBatchMode.RECOVERED,) * 3
        assert first.usable_site_keys == first.site_keys
        assert len(first.next_refresh_contexts) == 3
        assert acquisition.targets == [
            "https://one.test/",
            "https://one.test/a",
            "https://two.test/",
            "https://two.test/a",
            "https://three.test/",
            "https://three.test/a",
        ]
        assert [budget.max_requests for budget in acquisition.budgets] == [
            4,
            3,
            4,
            3,
            4,
            3,
        ]
        assert first.usage.requests == sum(
            child.usage.requests for child in first.site_results
        )
        assert [
            child.target_results[0].manifest.run_id for child in first.site_results
        ] == [
            "first-batch-site-1-seed",
            "first-batch-site-2-seed",
            "first-batch-site-3-seed",
        ]
    finally:
        store.close()


def test_required_file_goal_reaches_file_after_two_early_html_candidates(
    tmp_path: Path,
) -> None:
    parent = _parent(count=2, limits=Budgets(12, 52_428_800, 60, 4))
    file_url = "https://one.test/z-report.pdf"
    xhtml_url = "https://one.test/a.xhtml"
    candidates = {
        SEEDS[0]: (
            xhtml_url,
            "https://one.test/a.html",
            "https://one.test/b.html",
            file_url,
        ),
        SEEDS[1]: ("https://two.test/a.html",),
    }
    acquisition = _Acquisition(
        {
            SEEDS[0]: b"<main>one seed</main>",
            xhtml_url: b"<main>xhtml candidate</main>",
            "https://one.test/a.html": b"<main>page a</main>",
            "https://one.test/b.html": b"<main>page b</main>",
            file_url: b"%PDF-1.7 governed file evidence",
            SEEDS[1]: b"<main>two seed</main>",
            "https://two.test/a.html": b"<main>page a</main>",
        },
        mime_types={
            xhtml_url: "application/xhtml+xml",
            file_url: "application/pdf",
        },
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
    store = ArtifactStore(tmp_path / "required-file")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            _registry(
                acquisition,
                discovery_manifest=RECOVERY_MANIFEST,
                discovery=_StaticDiscovery(candidates, "complete"),
            ),
            store,
            run_id="required-file",
            clock=lambda: NOW,
        )

        first = result.site_results[0]
        assert [target.manifest.requested_url for target in first.target_results] == [
            SEEDS[0],
            *sorted(candidates[SEEDS[0]]),
        ]
        xhtml_target = next(
            target
            for target in first.target_results
            if target.manifest.requested_url == xhtml_url
        )
        assert xhtml_target.manifest.mime_type == "application/xhtml+xml"
        assert first.target_results[-1].manifest.mime_type == "application/pdf"
        pdf_source = next(
            artifact
            for artifact in first.target_results[-1].artifacts
            if artifact.role == "source"
        )
        pdf_page = next(
            page for page in first.site_state.pages if page.canonical_url == file_url
        )
        assert (
            pdf_page.canonical_url,
            pdf_page.observation_id,
            pdf_page.artifact_id,
            pdf_page.content_digest,
        ) == (
            pdf_source.source_url,
            pdf_source.observation_id,
            pdf_source.artifact_id,
            f"sha256:{pdf_source.sha256}",
        )
        assert result.file_discovery_statuses == (
            FileDiscoveryStatus.SATISFIED,
            FileDiscoveryStatus.NOT_REQUESTED,
        )
        assert (
            tuple(
                context.site_skill.site_key for context in result.next_refresh_contexts
            )
            == result.site_keys
        )
        assert site_batch_result_from_mapping(result.to_dict()) == result

        refresh_acquisition = _Acquisition(
            dict(acquisition.bodies),
            mime_types={
                xhtml_url: "application/xhtml+xml",
                file_url: "application/pdf",
            },
        )
        refresh_request = SiteBatchRequest(
            SiteBatchPhase.REFRESH,
            parent,
            result.next_refresh_contexts,
            sites=sites,
        )
        refresh = run_site_batch(
            refresh_request,
            _registry(
                refresh_acquisition,
                discovery_manifest=HTML_LINKS_MANIFEST,
                discovery=_StaticDiscovery(
                    candidates,
                    "complete",
                    HTML_LINKS_MANIFEST,
                ),
            ),
            store,
            run_id="required-file-refresh",
            clock=lambda: NOW,
        )

        assert refresh.file_discovery_statuses == result.file_discovery_statuses
        assert refresh_acquisition.targets[:6] == [
            SEEDS[0],
            SEEDS[0],
            *sorted(candidates[SEEDS[0]]),
        ]
        assert refresh.site_results[0].target_results[-1].manifest.requested_url == (
            file_url
        )
        assert refresh.site_results[0].target_results[-1].manifest.run_id == (
            "required-file-refresh-site-1-recovery-candidate-4"
        )
        assert result.request_sha256 != refresh.request_sha256
        assert (
            refresh_acquisition.budgets[refresh_acquisition.targets.index(SEEDS[1])]
            == parent.budgets
        )
        assert tuple(
            context.site_skill.scope for context in refresh.next_refresh_contexts
        ) == tuple(site.scope for site in sites)
        assert site_batch_result_from_mapping(refresh.to_dict()) == refresh

        for batch, state_field, code in (
            (result, "site_state", "site_batch.file_discovery_status_mismatch"),
            (refresh, "current_state", "site_refresh.evidence_mismatch"),
        ):
            forged = batch.to_dict()
            child = forged["site_results"][0]
            child[state_field]["pages"] = [
                page
                for page in child[state_field]["pages"]
                if page["canonical_url"] != file_url
            ]
            context = forged["next_refresh_contexts"][0]
            context["previous_state"]["pages"] = [
                page
                for page in context["previous_state"]["pages"]
                if page["canonical_url"] != file_url
            ]
            with pytest.raises(
                ResultValidationError,
                match=f"^{code}$",
            ):
                site_batch_result_from_mapping(forged)
    finally:
        store.close()


def test_required_file_goal_accepts_partial_candidate_after_tool_switch(
    tmp_path: Path,
) -> None:
    parent = _parent(count=2, limits=Budgets(12, 52_428_800, 60, 4))
    file_url = "https://one.test/report.pdf"
    blocked_url = "https://one.test/z-blocked"
    other_url = "https://two.test/a.html"
    candidates = {
        SEEDS[0]: (blocked_url, file_url),
        SEEDS[1]: (other_url,),
    }
    bodies = {
        SEEDS[0]: b"<main>one seed</main>",
        file_url: b"%PDF-1.7 alternate file evidence",
        blocked_url: b"must not be acquired",
        SEEDS[1]: b"<main>two seed</main>",
        other_url: b"<main>two candidate</main>",
    }
    alternate_manifest = replace(
        WEB_HTTP_MANIFEST,
        tool_id="acquisition.alternate",
    )
    preferred = _Acquisition(
        {
            url: AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "gateway.timeout",
                requests=1,
            )
            for url in bodies
        }
    )
    alternate = _Acquisition(
        bodies,
        mime_types={file_url: "application/pdf"},
        manifest=alternate_manifest,
    )
    first_registry = _registry(
        preferred,
        discovery_manifest=RECOVERY_MANIFEST,
        discovery=_StaticDiscovery(candidates, "complete"),
    )
    first_registry.register(alternate_manifest, alternate)
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
    store = ArtifactStore(tmp_path / "partial-file-switch")
    try:
        first = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            first_registry,
            store,
            run_id="partial-file-switch-first",
            clock=lambda: NOW,
        )

        assert first.status is ResultStatus.COMPLETED
        assert first.file_discovery_statuses == (
            FileDiscoveryStatus.SATISFIED,
            FileDiscoveryStatus.NOT_REQUESTED,
        )
        assert (
            tuple(
                context.site_skill.site_key for context in first.next_refresh_contexts
            )
            == first.site_keys
        )
        assert all(
            context.site_skill.tool.tool_id == alternate_manifest.tool_id
            for context in first.next_refresh_contexts
        )
        assert blocked_url not in preferred.targets
        assert blocked_url not in alternate.targets

        third_manifest = replace(
            WEB_HTTP_MANIFEST,
            tool_id="acquisition.third",
        )
        saved_preferred = _Acquisition(
            {
                url: (
                    AcquisitionFailure(
                        alternate_manifest.tool_id,
                        alternate_manifest.version,
                        "gateway.robots",
                        requests=1,
                    )
                    if url == blocked_url
                    else AcquisitionFailure(
                        alternate_manifest.tool_id,
                        alternate_manifest.version,
                        "gateway.timeout",
                        requests=1,
                    )
                )
                for url in bodies
            },
            manifest=alternate_manifest,
        )
        third = _Acquisition(
            bodies,
            mime_types={file_url: "application/pdf"},
            manifest=third_manifest,
        )
        refresh_registry = Registry()
        refresh_registry.register(
            RECOVERY_MANIFEST,
            _StaticDiscovery(candidates, "complete"),
        )
        refresh_registry.register(alternate_manifest, saved_preferred)
        refresh_registry.register(third_manifest, third)
        refresh = run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                parent,
                first.next_refresh_contexts,
                sites=sites,
            ),
            refresh_registry,
            store,
            run_id="partial-file-switch-refresh",
            clock=lambda: NOW,
        )

        assert refresh.status is ResultStatus.COMPLETED
        assert refresh.file_discovery_statuses == first.file_discovery_statuses
        assert (
            tuple(
                context.site_skill.site_key for context in refresh.next_refresh_contexts
            )
            == refresh.site_keys
        )
        assert all(
            context.site_skill.tool.tool_id == third_manifest.tool_id
            for context in refresh.next_refresh_contexts
        )
        assert blocked_url not in saved_preferred.targets
        assert blocked_url not in third.targets
        assert first.request_sha256 != refresh.request_sha256

        for batch, failed_tool, succeeded_tool in (
            (first, WEB_HTTP_MANIFEST.tool_id, alternate_manifest.tool_id),
            (refresh, alternate_manifest.tool_id, third_manifest.tool_id),
        ):
            child = batch.site_results[0]
            target = next(
                item
                for item in child.target_results
                if item.manifest.requested_url == file_url
            )
            assert target.status is ResultStatus.PARTIAL
            assert [attempt.tool_id for attempt in target.attempts] == [
                failed_tool,
                succeeded_tool,
            ]
            assert [attempt.outcome for attempt in target.attempts] == [
                "failed",
                "succeeded",
            ]
            assert target.attempts[0].error is not None
            assert target.attempts[0].error.code == "gateway.timeout"
            assert target.attempts[1].error is None
            assert [error.code for error in target.errors] == ["gateway.timeout"]
            assert target.usage.requests == sum(
                attempt.requests for attempt in target.attempts
            )
            assert target.usage.tool_attempts == len(target.attempts)
            source = next(
                artifact for artifact in target.artifacts if artifact.role == "source"
            )
            state = (
                child.site_state
                if batch.phase == SiteBatchPhase.FIRST.value
                else child.current_state
            )
            page = next(item for item in state.pages if item.canonical_url == file_url)
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
            context = next(
                item
                for item in batch.next_refresh_contexts
                if item.site_skill.site_key == "one.test"
            )
            assert any(
                item.canonical_url == file_url
                and item.observation_id == source.observation_id
                and item.artifact_id == source.artifact_id
                and item.content_digest == f"sha256:{source.sha256}"
                for item in context.previous_state.pages
            )
            assert "gateway.timeout" in {error.code for error in batch.errors}
            assert batch.usage.requests == sum(
                item.usage.requests for item in batch.site_results
            )
            sibling_target = next(
                item
                for item in batch.site_results[1].target_results
                if item.manifest.requested_url == other_url
            )
            assert sibling_target.status is ResultStatus.PARTIAL
            assert [attempt.tool_id for attempt in sibling_target.attempts] == [
                failed_tool,
                succeeded_tool,
            ]
            assert [attempt.outcome for attempt in sibling_target.attempts] == [
                "failed",
                "succeeded",
            ]
            assert site_batch_result_from_mapping(batch.to_dict()) == batch
    finally:
        store.close()


def test_required_file_goal_reports_not_found_after_candidate_exhaustion(
    tmp_path: Path,
) -> None:
    parent = _parent(count=2, limits=Budgets(6, 52_428_800, 60, 4))
    candidates = {
        SEEDS[0]: (
            "https://one.test/a.html",
            "https://one.test/b.html",
        ),
        SEEDS[1]: ("https://two.test/a.html",),
    }
    acquisition = _Acquisition(
        {
            SEEDS[0]: b"<main>one seed</main>",
            candidates[SEEDS[0]][0]: b"<main>page a</main>",
            candidates[SEEDS[0]][1]: b"<main>page b</main>",
            SEEDS[1]: b"<main>two seed</main>",
            candidates[SEEDS[1]][0]: b"<main>page a</main>",
        }
    )
    sites = (
        SiteBatchSite(
            site_batch_child_scope(parent.scope, SEEDS[0]),
            FileDiscoveryGoal.REQUIRED,
        ),
        SiteBatchSite(
            site_batch_child_scope(parent.scope, SEEDS[1]),
            FileDiscoveryGoal.NOT_REQUIRED,
        ),
    )
    store = ArtifactStore(tmp_path / "required-file-missing")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            _registry(
                acquisition,
                discovery_manifest=RECOVERY_MANIFEST,
                discovery=_StaticDiscovery(candidates, "complete"),
            ),
            store,
            run_id="required-file-missing",
            clock=lambda: NOW,
        )

        assert result.status is ResultStatus.PARTIAL
        assert result.file_discovery_statuses == (
            FileDiscoveryStatus.NOT_FOUND,
            FileDiscoveryStatus.NOT_REQUESTED,
        )
        assert [
            target.manifest.requested_url
            for target in result.site_results[0].target_results
        ] == [SEEDS[0], *candidates[SEEDS[0]]]
        assert [
            context.site_skill.site_key for context in result.next_refresh_contexts
        ] == ["two.test"]
    finally:
        store.close()


def test_required_file_goal_budget_is_independent_for_later_site(
    tmp_path: Path,
) -> None:
    limits = Budgets(3, 52_428_800, 60, 4)
    parent = _parent(count=2, limits=limits)
    file_url = "https://one.test/z-report.pdf"
    candidates = {
        SEEDS[0]: (
            "https://one.test/a.html",
            "https://one.test/b.html",
            file_url,
        ),
        SEEDS[1]: ("https://two.test/a.html",),
    }
    acquisition = _Acquisition(
        {
            SEEDS[0]: b"<main>one seed</main>",
            candidates[SEEDS[0]][0]: b"<main>page a</main>",
            candidates[SEEDS[0]][1]: b"<main>page b</main>",
            file_url: b"%PDF-1.7 unreachable",
            SEEDS[1]: b"<main>two seed</main>",
            candidates[SEEDS[1]][0]: b"<main>page a</main>",
        },
        mime_types={file_url: "application/pdf"},
    )
    sites = (
        SiteBatchSite(
            site_batch_child_scope(parent.scope, SEEDS[0]),
            FileDiscoveryGoal.REQUIRED,
        ),
        SiteBatchSite(
            site_batch_child_scope(parent.scope, SEEDS[1]),
            FileDiscoveryGoal.NOT_REQUIRED,
        ),
    )
    store = ArtifactStore(tmp_path / "required-file-budget")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            _registry(
                acquisition,
                discovery_manifest=RECOVERY_MANIFEST,
                discovery=_StaticDiscovery(candidates, "complete"),
            ),
            store,
            run_id="required-file-budget",
            clock=lambda: NOW,
        )

        assert result.file_discovery_statuses == (
            FileDiscoveryStatus.NOT_FOUND,
            FileDiscoveryStatus.NOT_REQUESTED,
        )
        assert result.site_results[0].stop_reason == "budget_exhausted"
        assert file_url not in acquisition.targets
        second_seed_index = acquisition.targets.index(SEEDS[1])
        assert acquisition.budgets[second_seed_index] == limits
        assert result.site_results[1].status is ResultStatus.COMPLETED
        assert [
            context.site_skill.site_key for context in result.next_refresh_contexts
        ] == ["two.test"]
    finally:
        store.close()


def test_required_file_goal_policy_rejection_is_not_found_without_context(
    tmp_path: Path,
) -> None:
    parent = _parent(count=2, limits=Budgets(8, 52_428_800, 60, 4))
    blocked = "https://one.test/a-blocked"
    file_url = "https://one.test/z-report.pdf"
    candidates = {
        SEEDS[0]: (blocked, file_url),
        SEEDS[1]: ("https://two.test/a.html",),
    }
    rejection = AcquisitionFailure(
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        "gateway.robots",
        requests=1,
    )
    acquisition = _Acquisition(
        {
            SEEDS[0]: b"<main>one seed</main>",
            blocked: rejection,
            file_url: b"%PDF-1.7 unreachable",
            SEEDS[1]: b"<main>two seed</main>",
            candidates[SEEDS[1]][0]: b"<main>page a</main>",
        },
        mime_types={file_url: "application/pdf"},
    )
    sites = (
        SiteBatchSite(
            site_batch_child_scope(parent.scope, SEEDS[0]),
            FileDiscoveryGoal.REQUIRED,
        ),
        SiteBatchSite(
            site_batch_child_scope(parent.scope, SEEDS[1]),
            FileDiscoveryGoal.NOT_REQUIRED,
        ),
    )
    store = ArtifactStore(tmp_path / "required-file-rejected")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            _registry(
                acquisition,
                discovery_manifest=RECOVERY_MANIFEST,
                discovery=_StaticDiscovery(candidates, "complete"),
            ),
            store,
            run_id="required-file-rejected",
            clock=lambda: NOW,
        )

        first = result.site_results[0]
        assert first.status is ResultStatus.REJECTED
        assert first.stop_reason == "rejected"
        assert result.file_discovery_statuses[0] is FileDiscoveryStatus.NOT_FOUND
        assert file_url not in acquisition.targets
        assert first.attempts[-1].error is not None
        assert first.attempts[-1].error.code == "gateway.robots"
        assert "gateway.robots" in {error.code for error in result.errors}
        assert [
            context.site_skill.site_key for context in result.next_refresh_contexts
        ] == ["two.test"]
    finally:
        store.close()


def test_forged_satisfied_status_rejects_earlier_policy_evidence(
    tmp_path: Path,
) -> None:
    parent = _parent(count=2, limits=Budgets(12, 52_428_800, 60, 4))
    blocked = "https://one.test/a-blocked"
    file_url = "https://one.test/z-report.pdf"
    candidates = {
        SEEDS[0]: (blocked, file_url),
        SEEDS[1]: ("https://two.test/a.html",),
    }
    acquisition = _Acquisition(
        {
            SEEDS[0]: b"<main>one seed</main>",
            blocked: AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "gateway.robots",
                requests=1,
            ),
            file_url: b"%PDF-1.7 governed file evidence",
            SEEDS[1]: b"<main>two seed</main>",
            candidates[SEEDS[1]][0]: b"<main>page a</main>",
        },
        mime_types={file_url: "application/pdf"},
    )
    sites = tuple(
        SiteBatchSite(
            site_batch_child_scope(parent.scope, seed),
            FileDiscoveryGoal.NOT_REQUIRED,
        )
        for seed in parent.scope.seeds
    )
    store = ArtifactStore(tmp_path / "forged-policy-satisfied")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            _registry(
                acquisition,
                discovery_manifest=RECOVERY_MANIFEST,
                discovery=_StaticDiscovery(candidates, "complete"),
            ),
            store,
            run_id="forged-policy-satisfied",
            clock=lambda: NOW,
        )

        first = result.site_results[0]
        assert first.status is ResultStatus.COMPLETED
        assert "gateway.robots" in {error.code for error in first.errors}
        blocked_attempt = next(
            attempt for attempt in first.attempts if attempt.requested_url == blocked
        )
        assert blocked_attempt.error is not None
        assert blocked_attempt.error.code == "gateway.robots"
        assert first.target_results[-1].manifest.requested_url == file_url
        assert first.target_results[-1].status is ResultStatus.COMPLETED
        assert any(page.canonical_url == file_url for page in first.site_state.pages)
        assert result.next_refresh_contexts[0].previous_state == first.site_state
        forged = result.to_dict()
        forged["file_discovery_statuses"][0] = "satisfied"

        with pytest.raises(
            ResultValidationError,
            match="^site_batch.file_discovery_status_mismatch$",
        ):
            site_batch_result_from_mapping(forged)
    finally:
        store.close()


def test_all_required_policy_rejections_return_one_strict_audited_result(
    tmp_path: Path,
) -> None:
    parent = _parent(count=2, limits=Budgets(8, 52_428_800, 60, 4))
    candidates = {
        seed: (f"{seed}a-blocked", f"{seed}z-report.pdf") for seed in parent.scope.seeds
    }
    bodies: dict[str, bytes | AcquisitionFailure | type[CancelledError]] = {}
    for seed in parent.scope.seeds:
        bodies[seed] = b"<main>seed</main>"
        bodies[candidates[seed][0]] = AcquisitionFailure(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            "gateway.robots",
            requests=1,
        )
        bodies[candidates[seed][1]] = b"%PDF-1.7 unreachable"
    acquisition = _Acquisition(
        bodies,
        mime_types={
            candidates[seed][1]: "application/pdf" for seed in parent.scope.seeds
        },
    )
    sites = tuple(
        SiteBatchSite(
            site_batch_child_scope(parent.scope, seed),
            FileDiscoveryGoal.REQUIRED,
        )
        for seed in parent.scope.seeds
    )
    store = ArtifactStore(tmp_path / "all-required-rejected")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, (), sites=sites),
            _registry(
                acquisition,
                discovery_manifest=RECOVERY_MANIFEST,
                discovery=_StaticDiscovery(candidates, "complete"),
            ),
            store,
            run_id="all-required-rejected",
            clock=lambda: NOW,
        )

        assert result.status is ResultStatus.REJECTED
        assert result.stop_reason == "rejected"
        assert result.file_discovery_statuses == (
            FileDiscoveryStatus.NOT_FOUND,
            FileDiscoveryStatus.NOT_FOUND,
        )
        assert not result.next_refresh_contexts
        assert [child.status for child in result.site_results] == [
            ResultStatus.REJECTED,
            ResultStatus.REJECTED,
        ]
        assert [
            attempt.error.code
            for child in result.site_results
            for attempt in child.attempts
            if attempt.error is not None
        ] == ["gateway.robots", "gateway.robots"]
        assert [error.code for error in result.errors] == [
            "gateway.robots",
            "gateway.robots",
        ]
        assert result.usage.requests == sum(
            child.usage.requests for child in result.site_results
        )
        assert all(
            candidate[1] not in acquisition.targets for candidate in candidates.values()
        )
        assert site_batch_result_from_mapping(result.to_dict()) == result
    finally:
        store.close()


def test_first_child_scope_excludes_sibling_origins_and_keeps_alias(
    tmp_path: Path,
) -> None:
    alias = "https://cdn.shared.test"
    parent = _parent()
    parent = replace(
        parent,
        scope=replace(
            parent.scope,
            allowed_origins=tuple(sorted((*parent.scope.allowed_origins, alias))),
        ),
    )
    acquisition = _Acquisition(_standard_bodies())
    store = ArtifactStore(tmp_path / "first-isolated")
    try:
        first = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, ()),
            _registry(acquisition),
            store,
            run_id="first-isolated",
            clock=lambda: NOW,
        )

        assert first.usable_site_keys == first.site_keys
        for seed, context in zip(
            parent.scope.seeds,
            first.next_refresh_contexts,
            strict=True,
        ):
            seed_origin = seed.rstrip("/")
            assert context.site_skill.scope == site_batch_child_scope(
                parent.scope,
                seed,
            )
            assert set(context.site_skill.scope.allowed_origins) == {
                seed_origin,
                alias,
            }
        for scope in acquisition.scopes:
            assert len(scope.seeds) == 1
            assert alias in scope.allowed_origins
            seed_origin = scope.seeds[0].rstrip("/")
            assert set(scope.allowed_origins) == {seed_origin, alias}
    finally:
        store.close()


def test_sibling_redirect_is_audited_and_later_sites_remain_deliverable(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(
        _standard_bodies(),
        final_urls={SEEDS[0]: SEEDS[1]},
    )
    store = ArtifactStore(tmp_path / "sibling-redirect")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, _parent(), ()),
            _registry(acquisition),
            store,
            run_id="sibling-redirect",
            clock=lambda: NOW,
        )

        assert len(result.site_results) == 3
        assert result.site_modes[0] is SiteBatchMode.FAILED
        assert result.site_results[0].status in {
            ResultStatus.REJECTED,
            ResultStatus.FAILED,
        }
        assert result.site_results[0].errors
        assert result.usable_site_keys == ("two.test", "three.test")
        assert SEEDS[1] in acquisition.targets
        assert tuple(
            context.site_skill.site_key for context in result.next_refresh_contexts
        ) == ("two.test", "three.test")
    finally:
        store.close()


def test_refresh_child_scope_is_isolated_and_retains_alias(tmp_path: Path) -> None:
    alias = "https://cdn.shared.test"
    parent = _parent()
    parent = replace(
        parent,
        scope=replace(
            parent.scope,
            allowed_origins=tuple(sorted((*parent.scope.allowed_origins, alias))),
        ),
    )
    first_acquisition = _Acquisition(_standard_bodies())
    refresh_acquisition = _Acquisition(_standard_bodies())
    store = ArtifactStore(tmp_path / "refresh-isolated")
    try:
        first = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, parent, ()),
            _registry(first_acquisition),
            store,
            run_id="first-for-refresh-isolated",
            clock=lambda: NOW,
        )
        refresh = run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                parent,
                first.next_refresh_contexts,
            ),
            _registry(refresh_acquisition),
            store,
            run_id="refresh-isolated",
            clock=lambda: NOW,
        )

        assert refresh.usable_site_keys == refresh.site_keys
        assert refresh.site_modes == (SiteBatchMode.REPLAYED,) * 3
        for scope in refresh_acquisition.scopes:
            assert len(scope.seeds) == 1
            assert scope == site_batch_child_scope(parent.scope, scope.seeds[0])
            assert alias in scope.allowed_origins
            seed_origin = scope.seeds[0].rstrip("/")
            assert set(scope.allowed_origins) == {seed_origin, alias}
    finally:
        store.close()


def test_exhausted_site_does_not_remove_later_site_authority(tmp_path: Path) -> None:
    limits = Budgets(1, 52_428_800, 60, 4)
    first, acquisition, store = _first_batch(tmp_path, limits=limits)
    try:
        assert acquisition.targets == list(SEEDS)
        assert [budget.max_requests for budget in acquisition.budgets] == [1, 1, 1]
        assert len(first.site_results) == 3
        assert all(
            child.stop_reason == "budget_exhausted" for child in first.site_results
        )
        assert first.status is ResultStatus.PARTIAL
        assert first.usable_site_keys == first.site_keys
        assert first.usage.requests == 3
    finally:
        store.close()


def test_failed_site_continues_but_explicit_cancellation_stops(tmp_path: Path) -> None:
    failure = AcquisitionFailure(
        "acquisition.web_http",
        "1.0.0",
        "gateway.timeout",
    )
    failed_acquisition = _Acquisition({**_standard_bodies(), SEEDS[0]: failure})
    failed_store = ArtifactStore(tmp_path / "failed")
    try:
        failed = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, _parent(), ()),
            _registry(failed_acquisition),
            failed_store,
            run_id="continue-after-failure",
            clock=lambda: NOW,
        )
        assert len(failed.site_results) == 3
        assert failed_acquisition.targets[0] == SEEDS[0]
        assert SEEDS[1] in failed_acquisition.targets
        assert failed.site_modes[0] is SiteBatchMode.FAILED
        assert failed.usable_site_keys == ("two.test", "three.test")
    finally:
        failed_store.close()

    cancelled_acquisition = _Acquisition(
        {**_standard_bodies(), SEEDS[0]: CancelledError}
    )
    cancelled_store = ArtifactStore(tmp_path / "cancelled")
    try:
        cancelled = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, _parent(), ()),
            _registry(cancelled_acquisition),
            cancelled_store,
            run_id="cancel-batch",
            clock=lambda: NOW,
        )
        assert cancelled.stop_reason == "cancelled"
        assert len(cancelled.site_results) == 1
        assert cancelled_acquisition.targets == [SEEDS[0]]
    finally:
        cancelled_store.close()


def test_boundary_cancel_before_start_is_strict_and_performs_zero_target_io(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(_standard_bodies())
    store = ArtifactStore(tmp_path / "cancel-before-start")
    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, _parent(), ()),
            _registry(acquisition),
            store,
            run_id="cancel-before-start",
            clock=lambda: NOW,
            should_cancel=lambda: True,
        )
        assert not acquisition.targets
        assert result.stop_reason == "cancelled"
        assert len(result.site_results) == 1
        assert result.site_results[0].usage == Usage(0, 0, 0, 0)
        assert site_batch_result_from_mapping(result.to_dict()) == result
    finally:
        store.close()


def test_boundary_cancel_after_first_preserves_checkpoint_and_starts_no_later_io(
    tmp_path: Path,
) -> None:
    acquisition = _Acquisition(_standard_bodies())
    store = ArtifactStore(tmp_path / "cancel-after-first")
    cancelled = False

    def checkpoint(order, _result):
        nonlocal cancelled
        cancelled = order == 1

    try:
        result = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, _parent(), ()),
            _registry(acquisition),
            store,
            run_id="cancel-after-first",
            clock=lambda: NOW,
            checkpoint=checkpoint,
            should_cancel=lambda: cancelled,
        )
        assert len(result.site_results) == 2
        assert result.site_results[0].target_results
        assert result.site_results[1].usage == Usage(0, 0, 0, 0)
        assert result.usage == result.site_results[0].usage
        assert result.next_refresh_contexts[0].site_skill.site_key == "one.test"
        assert all(not target.startswith(SEEDS[1]) for target in acquisition.targets)
        assert all(not target.startswith(SEEDS[2]) for target in acquisition.targets)
        assert site_batch_result_from_mapping(result.to_dict()) == result
    finally:
        store.close()


def test_refresh_replays_persisted_contexts_without_caller_fallback(
    tmp_path: Path,
) -> None:
    first, _first_acquisition, store = _first_batch(tmp_path)
    refresh_acquisition = _Acquisition(_standard_bodies())
    try:
        persisted_first = site_batch_result_from_mapping(first.to_dict())
        refresh_request = site_batch_request_from_mapping(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                _parent(),
                persisted_first.next_refresh_contexts,
            ).to_dict()
        )
        refresh = run_site_batch(
            refresh_request,
            _registry(refresh_acquisition),
            store,
            run_id="refresh-batch",
            clock=lambda: NOW,
        )

        assert refresh.status is ResultStatus.COMPLETED
        assert refresh.site_modes == (SiteBatchMode.REPLAYED,) * 3
        assert refresh.usable_site_keys == refresh.site_keys
        assert len(refresh.next_refresh_contexts) == 3
        assert refresh.request_sha256 != first.request_sha256
        assert [budget.max_requests for budget in refresh_acquisition.budgets] == [
            4,
            3,
            4,
            3,
            4,
            3,
        ]
        for child, previous, current in zip(
            refresh.site_results,
            first.next_refresh_contexts,
            refresh.next_refresh_contexts,
            strict=True,
        ):
            assert child.previous_state == previous.previous_state
            assert current.site_skill == previous.site_skill
            assert child.current_state.pages
            assert {
                page.observation_id for page in child.previous_state.pages
            }.isdisjoint(page.observation_id for page in child.current_state.pages)
    finally:
        store.close()


def test_persisted_first_fixture_directly_executes_refresh(tmp_path: Path) -> None:
    payload = json.loads(
        (FIXTURES / "site-batch-first-usable.v1.json").read_text(encoding="utf-8")
    )
    persisted_first = site_batch_result_from_mapping(payload)
    parent = _parent(count=2)
    refresh_request = site_batch_request_from_mapping(
        SiteBatchRequest(
            SiteBatchPhase.REFRESH,
            parent,
            persisted_first.next_refresh_contexts,
        ).to_dict()
    )
    acquisition = _Acquisition(_standard_bodies(2))
    store = ArtifactStore(tmp_path / "fixture-refresh")
    try:
        refresh = run_site_batch(
            refresh_request,
            _registry(acquisition),
            store,
            run_id="fixture-refresh",
            clock=lambda: NOW,
        )

        assert refresh.site_modes == (SiteBatchMode.REPLAYED,) * 2
        assert refresh.usable_site_keys == refresh.site_keys
        assert len(refresh.next_refresh_contexts) == 2
    finally:
        store.close()


@pytest.mark.parametrize("coverage", ("truncated", "unknown"))
def test_recovery_keeps_partial_coverage_usable_and_emits_next_context(
    tmp_path: Path,
    coverage: str,
) -> None:
    first, _first_acquisition, store = _first_batch(tmp_path)
    input_contexts = tuple(
        replace(
            context,
            previous_state=replace(
                context.previous_state,
                pages=(
                    *context.previous_state.pages,
                    SiteStatePage(
                        f"https://{context.site_skill.site_key}/z-old",
                        f"observation-{marker * 32}",
                        f"artifact-{marker * 64}",
                        f"sha256:{marker * 64}",
                    ),
                ),
            ),
        )
        for context, marker in zip(
            first.next_refresh_contexts,
            "def",
            strict=True,
        )
    )
    recovery_acquisition = _Acquisition(_standard_bodies())
    candidates = {seed: (f"{seed}a",) for seed in SEEDS}
    recovery_registry = _registry(
        recovery_acquisition,
        discovery_manifest=RECOVERY_MANIFEST,
        discovery=_StaticDiscovery(candidates, coverage),
    )
    try:
        refresh = run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                _parent(),
                input_contexts,
            ),
            recovery_registry,
            store,
            run_id="recover-batch",
            clock=lambda: NOW,
        )

        assert refresh.status is ResultStatus.PARTIAL
        assert refresh.site_modes == (SiteBatchMode.RECOVERED,) * 3
        assert refresh.usable_site_keys == refresh.site_keys
        assert len(refresh.next_refresh_contexts) == 3
        assert all(not child.refresh_complete for child in refresh.site_results)
        assert all(not child.missing for child in refresh.site_results)
        assert all(child.unresolved for child in refresh.site_results)
        assert all(
            child.site_skill_update is not None for child in refresh.site_results
        )
        assert all(
            "runtime.discovery_coverage_incomplete"
            in {error.code for error in child.errors}
            for child in refresh.site_results
        )
        for old, child, context in zip(
            first.next_refresh_contexts,
            refresh.site_results,
            refresh.next_refresh_contexts,
            strict=True,
        ):
            update = child.site_skill_update
            assert update is not None
            assert context.site_skill.previous_digest == old.site_skill.digest
            assert context.site_skill.digest == update.candidate.digest
            assert context.previous_state.site_skill_digest == context.site_skill.digest
            assert context.previous_state.pages == child.current_state.pages
            assert context.previous_state.complete is False

        reparsed = site_batch_result_from_mapping(refresh.to_dict())
        direct_request = site_batch_request_from_mapping(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                _parent(),
                reparsed.next_refresh_contexts,
            ).to_dict()
        )
        replay = run_site_batch(
            direct_request,
            recovery_registry,
            store,
            run_id="replay-recovered-batch",
            clock=lambda: NOW,
        )
        assert replay.site_modes == (SiteBatchMode.REPLAYED,) * 3
        assert replay.usable_site_keys == replay.site_keys
        assert len(replay.next_refresh_contexts) == 3
    finally:
        store.close()


def test_batch_refresh_uses_the_same_governed_recovery_as_single_site(
    tmp_path: Path,
) -> None:
    first, _first_acquisition, store = _first_batch(tmp_path, count=2)
    candidates = {seed: (f"{seed}a",) for seed in SEEDS[:2]}
    recovery_registry = _registry(
        _Acquisition(_standard_bodies(2)),
        discovery_manifest=RECOVERY_MANIFEST,
        discovery=_StaticDiscovery(candidates, "complete"),
    )
    try:
        context = first.next_refresh_contexts[0]
        direct = run_site_refresh(
            SiteRefreshRequest(
                _parent(count=2).scope,
                context.site_skill,
                context.previous_state,
                True,
                LIMITS,
            ),
            recovery_registry,
            store,
            run_id="direct-recovery",
            clock=lambda: NOW,
        )
        batch = run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                _parent(count=2),
                first.next_refresh_contexts,
            ),
            recovery_registry,
            store,
            run_id="batch-recovery",
            clock=lambda: NOW,
        )

        assert direct.current_state.pages
        assert direct.site_skill_update is not None
        assert batch.site_modes == (SiteBatchMode.RECOVERED,) * 2
        assert batch.usable_site_keys == batch.site_keys
        assert len(batch.next_refresh_contexts) == 2
    finally:
        store.close()


def test_preferred_tool_switch_is_audited_as_recovered(tmp_path: Path) -> None:
    first, _first_acquisition, store = _first_batch(tmp_path, count=2)
    bodies = _standard_bodies(2)
    alternate_manifest = replace(
        WEB_HTTP_MANIFEST,
        tool_id="acquisition.alternate",
    )
    preferred = _Acquisition(
        {
            url: AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "gateway.timeout",
            )
            for url in bodies
        }
    )
    alternate = _Acquisition(bodies, manifest=alternate_manifest)
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(WEB_HTTP_MANIFEST, preferred)
    registry.register(alternate_manifest, alternate)
    try:
        refresh = run_site_batch(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                _parent(count=2),
                first.next_refresh_contexts,
            ),
            registry,
            store,
            run_id="preferred-switch-batch",
            clock=lambda: NOW,
        )

        assert refresh.site_modes == (SiteBatchMode.RECOVERED,) * 2
        for old_context, child, context in zip(
            first.next_refresh_contexts,
            refresh.site_results,
            refresh.next_refresh_contexts,
            strict=True,
        ):
            update = child.site_skill_update
            assert update is not None
            assert update.reason == "preferred_tool_changed"
            preferred_attempts = tuple(
                attempt
                for attempt in child.attempts
                if attempt.tool_id == WEB_HTTP_MANIFEST.tool_id
            )
            alternate_attempts = tuple(
                attempt
                for attempt in child.attempts
                if attempt.tool_id == alternate_manifest.tool_id
            )
            assert preferred_attempts
            assert {attempt.outcome for attempt in preferred_attempts} == {"failed"}
            assert alternate_attempts
            assert {attempt.outcome for attempt in alternate_attempts} == {"succeeded"}
            previous_digest = old_context.site_skill.digest
            assert f"sha256:{update.previous.sha256}" == previous_digest
            assert update.candidate.digest == context.site_skill.digest
            assert context.site_skill.previous_digest == previous_digest
            assert context.site_skill.tool.tool_id == alternate_manifest.tool_id
            assert context.previous_state.site_skill_digest == update.candidate.digest

        reparsed = site_batch_result_from_mapping(refresh.to_dict())
        assert reparsed.site_modes == (SiteBatchMode.RECOVERED,) * 2
        assert reparsed.next_refresh_contexts == refresh.next_refresh_contexts
    finally:
        store.close()


def test_mixed_html_markdown_and_file_evidence_remains_replayable(
    tmp_path: Path,
) -> None:
    seeds = SEEDS[:2]
    file_url = "https://one.test/report.pdf"
    bodies: dict[str, bytes | AcquisitionFailure | type[CancelledError]] = {
        seeds[0]: (
            b"<main><p>One seed has enough visible words for markdown.</p>"
            b"<a href='/report.pdf'>report</a></main>"
        ),
        file_url: b"%PDF-1.7 governed file evidence",
        seeds[1]: (
            b"<main><p>Two seed has enough visible words for markdown.</p>"
            b"<a href='/a'>a</a></main>"
        ),
        f"{seeds[1]}a": (
            b"<main><p>Two candidate has enough visible words.</p></main>"
        ),
    }
    acquisition = _Acquisition(
        bodies,
        mime_types={file_url: "application/pdf"},
    )
    store = ArtifactStore(tmp_path / "mixed")
    try:
        first = run_site_batch(
            SiteBatchRequest(SiteBatchPhase.FIRST, _parent(count=2), ()),
            _registry(acquisition, transform=True),
            store,
            run_id="mixed-batch",
            clock=lambda: NOW,
        )

        assert first.status is ResultStatus.COMPLETED
        assert first.usable_site_keys == first.site_keys
        assert len(first.next_refresh_contexts) == 2
        sources = [
            artifact
            for child in first.site_results
            for target in child.target_results
            for artifact in target.artifacts
            if artifact.role == "source"
        ]
        markdown = [
            artifact
            for child in first.site_results
            for target in child.target_results
            for artifact in target.artifacts
            if artifact.role == "derived" and artifact.mime_type == "text/markdown"
        ]
        file_source = next(
            item for item in sources if item.mime_type == "application/pdf"
        )
        assert markdown
        assert all(item.lineage for item in markdown)
        assert store.read_artifact(file_source.artifact_id).content.startswith(b"%PDF")
        skill = site_skill_from_mapping(
            first.site_results[0].site_skill_candidate.to_dict()
        )
        assert skill.success_checks.allowed_mime_types == (
            "application/pdf",
            "text/html",
        )
    finally:
        store.close()
