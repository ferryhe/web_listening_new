"""Minimal service boundary for one governed Runtime execution."""

# pylint: disable=too-few-public-methods

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Request, RequestValidationError
from web_listening.runtime.jobs import Job, JobRepository, JobStatus
from web_listening.runtime.workflow import run_single_target
from web_listening.tool_registry.registry import Registry


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

    def run(self, request: Request) -> Job:
        """Record submitted/running/terminal around the one-target workflow."""
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
        failure_code = result.errors[0].code if result.errors else None
        return self._jobs.transition(
            job_id,
            status,
            at=self._clock(),
            result=result,
            failure_code=failure_code,
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job_id() -> str:
    return f"job-{uuid.uuid4().hex}"


__all__ = ["RuntimeService"]
