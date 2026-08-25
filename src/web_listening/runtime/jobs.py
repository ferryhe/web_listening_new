"""Explicit in-memory state for minimal Runtime Jobs."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    parse_utc_time,
    validate_text,
    validate_utc_time,
)
from web_listening.result.model import Result


class JobStateError(ValueError):
    """Reject an invalid Job operation with a stable safe code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class JobStatus(str, Enum):
    """The necessary lifecycle states for one minimal Runtime execution."""

    SUBMITTED = "submitted"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    REJECTED = "rejected"
    FAILED = "failed"


_TERMINAL = frozenset(
    {
        JobStatus.COMPLETED,
        JobStatus.PARTIAL,
        JobStatus.REJECTED,
        JobStatus.FAILED,
    }
)
_TRANSITIONS = {
    JobStatus.SUBMITTED: frozenset({JobStatus.RUNNING}),
    JobStatus.RUNNING: _TERMINAL,
}


@dataclass(frozen=True, slots=True)
class Job:
    """One immutable Job snapshot returned by the repository."""

    job_id: str
    status: JobStatus
    submitted_at: str
    started_at: str | None = None
    finished_at: str | None = None
    result: Result | None = None
    failure_code: str | None = None


@dataclass(frozen=True, slots=True)
class JobEvent:
    """One ordered Job state transition for replay and audit."""

    sequence: int
    job_id: str
    previous_status: JobStatus | None
    status: JobStatus
    at: str


class JobRepository:
    """Own legal Job state transitions and immutable readback only."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._events: dict[str, list[JobEvent]] = {}

    def submit(self, job_id: str, *, at: str) -> Job:
        """Create one submitted Job with a caller-owned identity."""
        identifier = _validate_job_id(job_id)
        timestamp = _validate_time(at)
        if identifier in self._jobs:
            raise JobStateError("job.duplicate")
        job = Job(identifier, JobStatus.SUBMITTED, timestamp)
        self._jobs[identifier] = job
        self._events[identifier] = [
            JobEvent(1, identifier, None, JobStatus.SUBMITTED, timestamp)
        ]
        return job

    def transition(  # pylint: disable=too-many-branches
        self,
        job_id: str,
        status: JobStatus,
        *,
        at: str,
        result: Result | None = None,
        failure_code: str | None = None,
    ) -> Job:
        """Apply one legal transition; no other component may change state."""
        identifier = _validate_job_id(job_id)
        timestamp = _validate_time(at)
        if type(status) is not JobStatus:
            raise JobStateError("job.status_invalid")
        if result is not None and not isinstance(result, Result):
            raise JobStateError("job.result_invalid")
        current = self._require(identifier)
        if status not in _TRANSITIONS.get(current.status, frozenset()):
            raise JobStateError("job.transition_invalid")
        if result is not None and (
            result.status.value != status.value or result.manifest.run_id != identifier
        ):
            raise JobStateError("job.result_mismatch")
        if status is JobStatus.RUNNING and (
            result is not None or failure_code is not None
        ):
            raise JobStateError("job.transition_invalid")
        if status is JobStatus.RUNNING:
            if parse_utc_time(timestamp) < parse_utc_time(current.submitted_at):
                raise JobStateError("job.time_invalid")
        else:
            assert current.started_at is not None
            window_start = parse_utc_time(current.started_at)
            window_end = parse_utc_time(timestamp)
            if window_end < window_start:
                raise JobStateError("job.time_invalid")
            if result is not None:
                result_times = (
                    result.manifest.generated_at,
                    *(
                        value
                        for attempt in result.attempts
                        for value in (attempt.started_at, attempt.finished_at)
                    ),
                    *(artifact.observed_at for artifact in result.artifacts),
                )
                if any(
                    not window_start <= parse_utc_time(value) <= window_end
                    for value in result_times
                ):
                    raise JobStateError("job.time_invalid")
            if status in {JobStatus.COMPLETED, JobStatus.PARTIAL} and result is None:
                raise JobStateError("job.result_required")
            if result is None:
                if failure_code is None:
                    raise JobStateError("job.failure_code_required")
                _validate_failure_code(failure_code)
            elif failure_code != _result_failure_code(result):
                raise JobStateError("job.failure_code_mismatch")
        updated = replace(
            current,
            status=status,
            started_at=(
                timestamp if status is JobStatus.RUNNING else current.started_at
            ),
            finished_at=(timestamp if status in _TERMINAL else None),
            result=result,
            failure_code=failure_code,
        )
        self._jobs[identifier] = updated
        history = self._events[identifier]
        history.append(
            JobEvent(
                len(history) + 1,
                identifier,
                current.status,
                status,
                timestamp,
            )
        )
        return updated

    def get(self, job_id: str) -> Job:
        """Return the current immutable snapshot for one Job."""
        identifier = _validate_job_id(job_id)
        return self._require(identifier)

    def events(self, job_id: str) -> tuple[JobEvent, ...]:
        """Return ordered immutable transition evidence for one Job."""
        identifier = _validate_job_id(job_id)
        self._require(identifier)
        return tuple(self._events[identifier])

    def _require(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise JobStateError("job.not_found")
        return job


def _validate_job_id(value: object) -> str:
    try:
        return validate_text(value, code="job.id_invalid", maximum=128)
    except ResultValidationError as exc:
        raise JobStateError(exc.code) from exc


def _validate_time(value: object) -> str:
    try:
        return validate_utc_time(value)
    except ResultValidationError as exc:
        raise JobStateError("job.time_invalid") from exc


def _validate_failure_code(value: object) -> str:
    try:
        return SafeError(value, "Job did not complete.").code  # type: ignore[arg-type]
    except ResultValidationError as exc:
        raise JobStateError("job.failure_code_invalid") from exc


def _result_failure_code(result: Result) -> str | None:
    if result.errors:
        return result.errors[0].code
    return next(
        (
            attempt.error.code
            for attempt in result.attempts
            if attempt.error is not None
        ),
        None,
    )


__all__ = ["Job", "JobEvent", "JobRepository", "JobStateError", "JobStatus"]
