"""Smart URL Fetch runtime tests."""

# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=too-few-public-methods,duplicate-code

import hashlib

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets
from web_listening.request.url_fetch import UrlFetchRequest
from web_listening.runtime.jobs import JobRepository
from web_listening.runtime.url_fetch import run_url_fetch
from web_listening.tool_registry.acquisition.builtins.web_http import WEB_HTTP_MANIFEST
from web_listening.tool_registry.discovery.builtins.html_navigation import (
    HTML_NAVIGATION_MANIFEST,
    HtmlNavigationDiscoveryTool,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.protocols.transform import TransformFailure
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)


class Acquisition:
    manifest = WEB_HTTP_MANIFEST

    def __init__(self, outcomes):
        self.outcomes, self.targets, self.budgets = outcomes, [], []

    def acquire(self, tool_input):
        self.targets.append(tool_input.target_url)
        self.budgets.append(tool_input.request.budgets)
        outcome = self.outcomes[tool_input.target_url]
        mime, body = outcome[:2]
        final_url = outcome[2] if len(outcome) == 3 else tool_input.target_url
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
            mime,
            body,
            hashlib.sha256(body).hexdigest(),
            redirects,
            1,
            len(redirects) + 1,
            len(body),
        )


def test_html_navigation_to_file_shares_remaining_budget(tmp_path) -> None:
    acquisition = Acquisition(
        {
            "https://example.test/": (
                "text/html",
                b"<html><body><p>hello governed web listening world</p>"
                b'<a download href="/file">file</a></body></html>',
            ),
            "https://example.test/file": ("application/pdf", b"PDF"),
        }
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(HTML_NAVIGATION_MANIFEST, HtmlNavigationDiscoveryTool())
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, SimpleHtmlMarkdownTransform())
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        result = run_url_fetch(
            UrlFetchRequest(
                "https://example.test/", False, True, 3, Budgets(3, 1000, 30, 3)
            ),
            registry,
            store,
            run_id="fetch",
            clock=lambda: "2026-09-05T00:00:00Z",
        )
        assert result.stop_reason == "terminal_file"
        assert result.resolution_kind.value == "html_navigation_file"
        assert acquisition.targets == [
            "https://example.test/",
            "https://example.test/file",
        ]
        assert acquisition.budgets[1].max_requests == 2
        assert result.usage.requests == 2
        assert result.usage.tool_attempts == 4
        assert result.discovery[0].usage.tool_attempts == 1
        assert len(result.intermediate_results) == 1
        assert any(
            item.role == "derived" for item in result.intermediate_results[0].artifacts
        )
    finally:
        store.close()


def test_redirect_final_url_is_in_loop_guard(tmp_path) -> None:
    acquisition = Acquisition(
        {
            "https://example.test/a": (
                "text/html",
                b'<a download href="/a">again</a>',
                "https://example.test/b",
            )
        }
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(HTML_NAVIGATION_MANIFEST, HtmlNavigationDiscoveryTool())
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        result = run_url_fetch(
            UrlFetchRequest(
                "https://example.test/a", False, True, 3, Budgets(3, 1000, 30, 3)
            ),
            registry,
            store,
            run_id="loop",
            clock=lambda: "2026-09-05T00:00:00Z",
        )
        assert result.stop_reason == "navigation_loop", result.errors
        assert acquisition.targets == ["https://example.test/a"]
    finally:
        store.close()


class FailingTransform:
    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    def transform(self, _tool_input):
        return TransformFailure(
            self.manifest.tool_id, self.manifest.version, "transform.output_invalid"
        )


class CountingNavigation:
    manifest = HTML_NAVIGATION_MANIFEST

    def __init__(self):
        self.delegate = HtmlNavigationDiscoveryTool()
        self.calls = 0

    def discover(self, tool_input):
        self.calls += 1
        return self.delegate.discover(tool_input)


def test_transform_failure_continues_to_file_and_aggregate_is_partial(tmp_path) -> None:
    acquisition = Acquisition(
        {
            "https://example.test/": (
                "text/html",
                b'<a download href="/file">file</a>',
            ),
            "https://example.test/file": ("application/pdf", b"PDF"),
        }
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(HTML_NAVIGATION_MANIFEST, HtmlNavigationDiscoveryTool())
    registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, FailingTransform())
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        result = run_url_fetch(
            UrlFetchRequest(
                "https://example.test/", False, True, 3, Budgets(3, 1000, 30, 3)
            ),
            registry,
            store,
            run_id="partial",
            clock=lambda: "2026-09-05T00:00:00Z",
        )
        assert acquisition.targets == [
            "https://example.test/",
            "https://example.test/file",
        ]
        assert result.status.value == "partial"
        assert result.terminal_artifact.mime_type == "application/pdf"
        assert result.errors
    finally:
        store.close()


def test_cancel_before_first_hop_has_safe_error_and_zero_io(tmp_path) -> None:
    acquisition = Acquisition({})
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        result = run_url_fetch(
            UrlFetchRequest(
                "https://example.test/", False, True, 3, Budgets(3, 1000, 30, 2)
            ),
            registry,
            store,
            run_id="cancel",
            clock=lambda: "2026-09-05T00:00:00Z",
            should_cancel=lambda: True,
        )
        assert not acquisition.targets
        assert [error.code for error in result.errors] == ["runtime.cancelled"]
    finally:
        store.close()


def test_cancel_after_checkpoint_preserves_result_and_starts_no_io(tmp_path) -> None:
    acquisition = Acquisition(
        {"https://example.test/": ("text/html", b"<p>terminal html</p>")}
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "artifacts")
    request = UrlFetchRequest(
        "https://example.test/", False, False, 3, Budgets(3, 1000, 30, 2)
    )
    try:
        first = run_url_fetch(
            request,
            registry,
            store,
            run_id="first",
            clock=lambda: "2026-09-05T00:00:00Z",
        )
        acquisition.targets.clear()
        result = run_url_fetch(
            request,
            registry,
            store,
            run_id="resume",
            clock=lambda: "2026-09-05T00:00:00Z",
            completed_results=(first.terminal_result,),
            should_cancel=lambda: True,
        )
        assert not acquisition.targets
        assert result.terminal_result == first.terminal_result
        assert result.status.value == "partial"
        assert [error.code for error in result.errors] == ["runtime.cancelled"]
    finally:
        store.close()


def test_resume_uses_checkpointed_unique_discovery_once(tmp_path) -> None:
    acquisition = Acquisition(
        {
            "https://example.test/": (
                "text/html",
                b'<a download href="/file">file</a>',
            ),
            "https://example.test/file": ("application/pdf", b"PDF"),
        }
    )
    navigation = CountingNavigation()
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(HTML_NAVIGATION_MANIFEST, navigation)
    store = ArtifactStore(tmp_path / "artifacts")
    request = UrlFetchRequest(
        "https://example.test/", False, True, 3, Budgets(3, 1000, 30, 2)
    )
    jobs_path = tmp_path / "jobs.sqlite3"
    jobs = JobRepository(jobs_path)
    jobs.submit_url_fetch(
        "restart-job",
        request,
        caller_id="caller",
        idempotency_key="restart-key",
        at="2026-09-05T00:00:00Z",
    )
    assert jobs.claim_next_url_fetch(at="2026-09-05T00:00:01Z") is not None

    def crash_after_discovery(order, evidence):
        jobs.checkpoint_url_fetch_discovery("restart-job", order, evidence)
        raise RuntimeError("simulated crash")

    try:
        with pytest.raises(RuntimeError, match="simulated crash"):
            run_url_fetch(
                request,
                registry,
                store,
                run_id="before-crash",
                clock=lambda: "2026-09-05T00:00:00Z",
                checkpoint=lambda order, result: jobs.checkpoint_url_fetch(
                    "restart-job", order, result
                ),
                checkpoint_discovery=crash_after_discovery,
            )
        jobs.close()
        jobs = JobRepository(jobs_path)
        jobs.reconcile_url_fetches()
        assert jobs.claim_next_url_fetch(at="2026-09-05T00:00:02Z") is not None
        completed = jobs.url_fetch_checkpoints("restart-job")
        discoveries = jobs.url_fetch_discovery_checkpoints("restart-job")
        result = run_url_fetch(
            request,
            registry,
            store,
            run_id="after-restart",
            clock=lambda: "2026-09-05T00:00:00Z",
            completed_results=completed,
            completed_discovery=discoveries,
        )
        assert acquisition.targets == [
            "https://example.test/",
            "https://example.test/file",
        ]
        assert navigation.calls == 1
        assert result.stop_reason == "terminal_file"
        assert result.usage.requests == 2
        assert result.usage.tool_attempts == 3
        assert result.discovery == discoveries
    finally:
        jobs.close()
        store.close()
