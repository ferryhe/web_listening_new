"""Minimal service boundary for one governed Runtime execution."""

# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
# pylint: disable=too-many-public-methods

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from web_listening.artifact.model import (
    ArtifactStoreError,
    StoredArtifact,
    VerifiedArtifactStream,
)
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, Request, RequestValidationError
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.request.validate import compile_access_policy
from web_listening.result.errors import SafeError
from web_listening.result.handoff import AcquisitionHandoff
from web_listening.result.model import Result, ResultStatus
from web_listening.result.site_explore import SiteExploreResult
from web_listening.result.site_refresh import SiteRefreshResult
from web_listening.runtime.handoff import project_handoff
from web_listening.runtime.jobs import (
    Job,
    JobRepository,
    JobStateError,
    JobStatus,
    canonical_request_facts,
)
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.site_refresh import run_site_refresh
from web_listening.runtime.workflow import (
    cancellation_check,
    cancelled_result,
    run_single_target,
    terminal_failure_result,
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
from web_listening.tool_registry.discovery.builtins.rss import (
    RSS_MANIFEST,
    RssDiscoveryTool,
)
from web_listening.tool_registry.discovery.builtins.sitemap import (
    SITEMAP_MANIFEST,
    SitemapDiscoveryTool,
)
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import PinnedHttpTransport
from web_listening.tool_registry.runners.subprocess import SubprocessTransformTool
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

_OwnedResource = WebHttpAcquisitionTool | ArtifactStore | JobRepository
_ADMISSION_MAXIMA = Budgets(100, 100 * 1024 * 1024, 600, 4)


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
        admission_maxima: Budgets = _ADMISSION_MAXIMA,
    ) -> None:
        self._registry = registry
        self._artifact_store = artifact_store
        self._jobs = jobs
        self._clock = clock or _utc_now
        self._job_id_factory = job_id_factory or _job_id
        self._closed = False
        self._admission_maxima = admission_maxima
        self._owned_resources: tuple[_OwnedResource, ...] = ()

    @classmethod
    def open(
        cls, data_dir: str | Path, *, admission_maxima: Budgets = _ADMISSION_MAXIMA
    ) -> RuntimeService:
        """Open the one current built-in Runtime composition in a data directory."""
        root = Path(data_dir)
        root.mkdir(parents=True, exist_ok=True)
        resources: list[_OwnedResource] = []
        try:
            tool = WebHttpAcquisitionTool(PinnedHttpTransport)
            resources.append(tool)
            registry = Registry()
            registry.register(WEB_HTTP_MANIFEST, tool)
            file_discovery = HtmlFileLinksDiscoveryTool()
            registry.register(HTML_FILE_LINKS_MANIFEST, file_discovery)
            discovery = HtmlLinksDiscoveryTool()
            registry.register(HTML_LINKS_MANIFEST, discovery)
            registry.register(RSS_MANIFEST, RssDiscoveryTool())
            registry.register(SITEMAP_MANIFEST, SitemapDiscoveryTool())
            lifecycle = ToolLifecycle(root)
            for external in lifecycle.active_versions(ToolCategory.TRANSFORM):
                registry.register(
                    external.manifest,
                    SubprocessTransformTool(external.manifest, external.command),
                )
            transform = SimpleHtmlMarkdownTransform()
            registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)
            artifact_store = ArtifactStore(root / "artifacts")
            resources.append(artifact_store)
            jobs = JobRepository(root / "jobs.sqlite3")
            resources.append(jobs)
            service = cls(
                registry, artifact_store, jobs, admission_maxima=admission_maxima
            )
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
            terminal_at = self._clock()
            result = terminal_failure_result(
                None,
                status=ResultStatus.REJECTED,
                run_id=job_id,
                generated_at=terminal_at,
                code=exc.code,
                message="Runtime request was rejected.",
            )
            return self._jobs.transition(
                job_id,
                JobStatus.REJECTED,
                at=terminal_at,
                result=result,
                failure_code=exc.code,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            try:
                terminal_at = self._clock()
                result = terminal_failure_result(
                    request,
                    status=ResultStatus.FAILED,
                    run_id=job_id,
                    generated_at=terminal_at,
                    code="runtime.workflow_failed",
                    message="Runtime execution did not complete.",
                )
                self._jobs.transition(
                    job_id,
                    JobStatus.FAILED,
                    at=terminal_at,
                    result=result,
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

    def submit(self, request: Request, *, caller_id: str, idempotency_key: str) -> Job:
        """Validate and durably submit one idempotent asynchronous acquisition."""
        self._ensure_open()
        canonical, _, _ = canonical_request_facts(request)
        admitted = _admit(canonical, self._admission_maxima)
        return self._jobs.submit_request(
            self._job_id_factory(),
            canonical,
            caller_id=caller_id,
            idempotency_key=idempotency_key,
            at=self._clock(),
            execution_request=admitted,
        )

    def cancel(self, job_id: str) -> Job:
        """Request cooperative cancellation without inventing a Job status."""
        self._ensure_open()
        return self._jobs.cancel(job_id, at=self._clock())

    def execute_submitted(
        self,
        job_id: str,
        request: Request,
        should_cancel: Callable[[], bool],
    ) -> Job:
        """Execute one already-claimed persisted Request under its fencing token."""
        self._ensure_open()
        job = self._jobs.get(job_id)
        if job.status is not JobStatus.RUNNING or job.claim_token is None:
            raise JobStateError("job.not_claimed")
        canonical, _, fingerprint = canonical_request_facts(request)
        if fingerprint != job.execution_request_fingerprint:
            raise JobStateError("job.request_mismatch")

        callback_error: Exception | None = None

        def cancellation() -> bool:
            nonlocal callback_error
            if callback_error is not None:
                return True
            try:
                requested = should_cancel()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                callback_error = exc
                return True
            return requested or self._jobs.get(job_id).cancel_requested_at is not None

        result: Result | None = None
        try:
            with cancellation_check(cancellation):
                result = run_single_target(
                    canonical,
                    self._registry,
                    self._artifact_store,
                    run_id=job_id,
                    clock=self._clock,
                )
            if cancellation():
                result = cancelled_result(result, generated_at=self._clock())
            if callback_error is not None:
                raise callback_error
        except Exception:  # pylint: disable=broad-exception-caught
            try:
                self._terminalize_execution_exception(job, canonical, result)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            raise
        try:
            terminal = self._jobs.transition(
                job_id,
                JobStatus(result.status.value),
                at=self._clock(),
                result=result,
                failure_code=_failure_code(result),
                claim_token=job.claim_token,
            )
            return terminal
        except JobStateError as exc:
            if exc.code != "job.cancel_requested":
                raise
            result = cancelled_result(result, generated_at=self._clock())
            terminal = self._jobs.transition(
                job_id,
                JobStatus(result.status.value),
                at=self._clock(),
                result=result,
                failure_code=_failure_code(result),
                claim_token=job.claim_token,
            )
            return terminal

    def _terminalize_execution_exception(
        self, job: Job, request: Request, execution_result: Result | None
    ) -> None:
        """Persist strict failure without re-entering a failed cancellation callback."""
        cancelled = self._jobs.get(job.job_id).cancel_requested_at is not None
        terminal_at = self._clock()
        result = _execution_exception_result(
            request,
            job_id=job.job_id,
            generated_at=terminal_at,
            execution_result=execution_result,
            cancelled=cancelled,
        )
        try:
            self._jobs.transition(
                job.job_id,
                JobStatus(result.status.value),
                at=terminal_at,
                result=result,
                failure_code=_failure_code(result),
                claim_token=job.claim_token,
            )
        except JobStateError as exc:
            if exc.code != "job.cancel_requested":
                raise
            terminal_at = self._clock()
            result = _execution_exception_result(
                request,
                job_id=job.job_id,
                generated_at=terminal_at,
                execution_result=execution_result,
                cancelled=True,
            )
            self._jobs.transition(
                job.job_id,
                JobStatus(result.status.value),
                at=terminal_at,
                result=result,
                failure_code=_failure_code(result),
                claim_token=job.claim_token,
            )

    def get_job(self, job_id: str) -> Job:
        """Return one Job without adding Runtime-owned interpretation."""
        self._ensure_open()
        return self._jobs.get(job_id)

    def get_owned_job(self, job_id: str, caller_id: str) -> Job:
        """Return a Job only when its persisted caller exactly matches."""
        job = self.get_job(job_id)
        if job.caller_id != caller_id:
            raise JobStateError("job.not_found")
        return job

    def cancel_owned(self, job_id: str, caller_id: str) -> Job:
        """Cancel only a caller-owned Job without revealing other identities."""
        self.get_owned_job(job_id, caller_id)
        return self.cancel(job_id)

    def get_handoff(self, job_id: str) -> AcquisitionHandoff:
        """Return a read-only deterministic projection of one terminal Job."""
        self._ensure_open()
        return project_handoff(self._jobs.get(job_id), self._artifact_store)

    def get_owned_handoff(self, job_id: str, caller_id: str) -> AcquisitionHandoff:
        """Project a handoff only from one caller-owned terminal Job."""
        self.get_owned_job(job_id, caller_id)
        return self.get_handoff(job_id)

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

    def explore_site_owned(self, request: Request, caller_id: str) -> SiteExploreResult:
        """Explore through the shared workflow and grant its explicit Artifacts."""
        result = self.explore_site(request)
        self._grant_target_results(caller_id, result.target_results)
        return result

    def refresh_site(self, request: SiteRefreshRequest) -> SiteRefreshResult:
        """Replay one validated Site Skill through the shared Runtime workflow."""
        self._ensure_open()
        return run_site_refresh(
            request,
            self._registry,
            self._artifact_store,
            run_id=self._job_id_factory(),
            clock=self._clock,
        )

    def refresh_site_owned(
        self, request: SiteRefreshRequest, caller_id: str
    ) -> SiteRefreshResult:
        """Refresh through the shared workflow and grant its explicit Artifacts."""
        result = self.refresh_site(request)
        self._grant_target_results(caller_id, result.target_results)
        return result

    def read_artifact(self, artifact_id: str) -> StoredArtifact:
        """Return one verified Artifact through the Store's public boundary."""
        self._ensure_open()
        return self._artifact_store.read_artifact(artifact_id)

    def read_owned_artifact(self, artifact_id: str, caller_id: str) -> StoredArtifact:
        """Read content only through a durable caller grant."""
        if not self._caller_has_artifact(caller_id, artifact_id):
            raise ArtifactStoreError("artifact.not_found")
        return self.read_artifact(artifact_id)

    @contextmanager
    def open_owned_artifact(
        self, artifact_id: str, caller_id: str
    ) -> Iterator[VerifiedArtifactStream]:
        """Open a verified stream only through a durable caller grant."""
        self._ensure_open()
        if not self._caller_has_artifact(caller_id, artifact_id):
            raise ArtifactStoreError("artifact.not_found")
        with self._artifact_store.open_verified_artifact(artifact_id) as opened:
            yield opened

    def repository_check(self) -> None:
        """Perform local repository reads used by readiness."""
        self._ensure_open()
        self._jobs.check()
        self._artifact_store.check()

    @property
    def job_repository(self) -> JobRepository:
        """Expose the repository solely for the existing worker composition."""
        self._ensure_open()
        return self._jobs

    @property
    def clock(self) -> Callable[[], str]:
        """Expose the Runtime clock solely for the existing worker composition."""
        self._ensure_open()
        return self._clock

    def _grant_target_results(
        self, caller_id: str, results: tuple[Result, ...]
    ) -> None:
        self._artifact_store.grant_artifacts(
            caller_id,
            tuple(
                artifact.artifact_id
                for result in results
                for artifact in result.artifacts
            ),
        )

    def _caller_has_artifact(self, caller_id: str, artifact_id: str) -> bool:
        return self._jobs.caller_has_artifact(
            caller_id, artifact_id
        ) or self._artifact_store.caller_has_artifact(caller_id, artifact_id)

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


def _admit(request: Request, maxima: Budgets = _ADMISSION_MAXIMA) -> Request:
    limits = Budgets(
        min(request.budgets.max_requests, maxima.max_requests),
        min(request.budgets.max_bytes, maxima.max_bytes),
        min(
            request.budgets.max_runtime_seconds,
            maxima.max_runtime_seconds,
        ),
        min(
            request.budgets.max_tool_attempts_per_target,
            maxima.max_tool_attempts_per_target,
        ),
    )
    policy = compile_access_policy(request, budgets=limits)
    return Request(
        request.scope, request.site_skill, request.explore_all_tools, policy.budgets
    )


def _execution_exception_result(
    request: Request,
    *,
    job_id: str,
    generated_at: str,
    execution_result: Result | None,
    cancelled: bool,
) -> Result:
    if cancelled and execution_result is not None:
        return cancelled_result(execution_result, generated_at=generated_at)
    if execution_result is not None:
        error = SafeError(
            "runtime.workflow_failed",
            "Runtime execution did not complete.",
        )
        attempts = tuple(
            (
                replace(attempt, error=error)
                if attempt.error is not None
                and attempt.error.code == "runtime.cancelled"
                else attempt
            )
            for attempt in execution_result.attempts
        )
        return Result(
            status=(
                ResultStatus.PARTIAL
                if execution_result.artifacts
                else ResultStatus.FAILED
            ),
            manifest=replace(
                execution_result.manifest,
                generated_at=generated_at,
                attempts=attempts,
            ),
            site_skill_used=execution_result.site_skill_used,
            site_skill_update=execution_result.site_skill_update,
            attempts=attempts,
            errors=(error,),
            usage=execution_result.usage,
        )
    code = "runtime.cancelled" if cancelled else "runtime.workflow_failed"
    return terminal_failure_result(
        request,
        status=ResultStatus.FAILED,
        run_id=job_id,
        generated_at=generated_at,
        code=code,
        message=(
            "Runtime execution was cancelled."
            if cancelled
            else "Runtime execution did not complete."
        ),
    )


def _failure_code(result: Result) -> str | None:
    errors = result.errors
    if errors:
        return errors[0].code
    return next(
        (
            attempt.error.code
            for attempt in result.attempts
            if attempt.error is not None
        ),
        None,
    )


__all__ = ["RuntimeService"]
