"""Minimal service boundary for one governed Runtime execution."""

# pylint: disable=too-few-public-methods

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from web_listening.artifact.model import StoredArtifact
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Request, RequestValidationError
from web_listening.result.site_explore import SiteExploreResult
from web_listening.runtime.jobs import Job, JobRepository, JobStatus
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.workflow import run_single_target
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_LINKS_MANIFEST,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import PinnedHttpTransport
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

_OwnedResource = WebHttpAcquisitionTool | ArtifactStore | JobRepository


class RuntimeService:
    """Run one target and make the Job repository the sole state owner."""

    def __init__(
        self,
        registry: Registry,
        artifact_store: ArtifactStore,
        jobs: JobRepository,
        *,
        clock: Callable[[], str] | None = None,
        job_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._registry = registry
        self._artifact_store = artifact_store
        self._jobs = jobs
        self._clock = clock or _utc_now
        self._job_id_factory = job_id_factory or _job_id
        self._closed = False
        self._owned_resources: tuple[_OwnedResource, ...] = ()

    @classmethod
    def open(cls, data_dir: str | Path) -> RuntimeService:
        """Open the one current built-in Runtime composition in a data directory."""
        root = Path(data_dir)
        root.mkdir(parents=True, exist_ok=True)
        resources: list[_OwnedResource] = []
        try:
            tool = WebHttpAcquisitionTool(PinnedHttpTransport)
            resources.append(tool)
            registry = Registry()
            registry.register(WEB_HTTP_MANIFEST, tool)
            discovery = HtmlLinksDiscoveryTool()
            registry.register(HTML_LINKS_MANIFEST, discovery)
            transform = SimpleHtmlMarkdownTransform()
            registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)
            artifact_store = ArtifactStore(root / "artifacts")
            resources.append(artifact_store)
            jobs = JobRepository(root / "jobs.sqlite3")
            resources.append(jobs)
            service = cls(registry, artifact_store, jobs)
            service._owned_resources = tuple(resources)
            return service
        except BaseException:
            _close_resources(resources)
            raise

    def run(self, request: Request) -> Job:
        """Record submitted/running/terminal around the one-target workflow."""
        self._ensure_open()
        job_id = self._job_id_factory()
        self._jobs.submit(job_id, at=self._clock())
        self._jobs.transition(job_id, JobStatus.RUNNING, at=self._clock())
        try:
            result = run_single_target(
                request,
                self._registry,
                self._artifact_store,
                run_id=job_id,
                clock=self._clock,
            )
        except RequestValidationError as exc:
            return self._jobs.transition(
                job_id,
                JobStatus.REJECTED,
                at=self._clock(),
                failure_code=exc.code,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            try:
                self._jobs.transition(
                    job_id,
                    JobStatus.FAILED,
                    at=self._clock(),
                    failure_code="runtime.workflow_failed",
                )
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            raise
        status = JobStatus(result.status.value)
        failure_code = (
            result.errors[0].code
            if result.errors
            else next(
                (
                    attempt.error.code
                    for attempt in result.attempts
                    if attempt.error is not None
                ),
                None,
            )
        )
        return self._jobs.transition(
            job_id,
            status,
            at=self._clock(),
            result=result,
            failure_code=failure_code,
        )

    def get_job(self, job_id: str) -> Job:
        """Return one Job without adding Runtime-owned interpretation."""
        self._ensure_open()
        return self._jobs.get(job_id)

    def explore_site(self, request: Request) -> SiteExploreResult:
        """Run deterministic exploration through the shared Runtime workflow."""
        self._ensure_open()
        return run_site_explore(
            request,
            self._registry,
            self._artifact_store,
            run_id=self._job_id_factory(),
            clock=self._clock,
        )

    def read_artifact(self, artifact_id: str) -> StoredArtifact:
        """Return one verified Artifact through the Store's public boundary."""
        self._ensure_open()
        return self._artifact_store.read_artifact(artifact_id)

    def close(self) -> None:
        """Close only resources created by open; repeated closes are harmless."""
        if self._closed:
            return
        self._closed = True
        resources = self._owned_resources
        self._owned_resources = ()
        _close_resources(list(resources))

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("runtime.closed")


def _close_resources(resources: list[_OwnedResource]) -> None:
    for resource in reversed(resources):
        try:
            resource.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job_id() -> str:
    return f"job-{uuid.uuid4().hex}"


__all__ = ["RuntimeService"]
