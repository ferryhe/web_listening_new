"""Explicit in-memory or SQLite state for minimal Runtime Jobs."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

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

    def __init__(self, database_path: str | os.PathLike[str] | None = None) -> None:
        self._jobs: dict[str, Job] = {}
        self._events: dict[str, list[JobEvent]] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._connection: sqlite3.Connection | None = None
        if database_path is None:
            return
        path = Path(os.path.abspath(os.fspath(database_path)))
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            path, isolation_level=None, check_same_thread=False
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            _create_schema(connection)
        except BaseException:
            connection.close()
            raise
        self._connection = connection

    def close(self) -> None:
        """Close a persistent handle; repeated closes are harmless."""
        with self._lock:
            if self._closed:
                return
            if self._connection is not None:
                self._connection.close()
            self._closed = True

    def submit(self, job_id: str, *, at: str) -> Job:
        """Create one submitted Job with a caller-owned identity."""
        identifier = _validate_job_id(job_id)
        timestamp = _validate_time(at)
        job = Job(identifier, JobStatus.SUBMITTED, timestamp)
        event = JobEvent(1, identifier, None, JobStatus.SUBMITTED, timestamp)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                if identifier in self._jobs:
                    raise JobStateError("job.duplicate")
                self._jobs[identifier] = job
                self._events[identifier] = [event]
                return job
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                if self._job_row(identifier) is not None:
                    raise JobStateError("job.duplicate")
                self._connection.execute(
                    "INSERT INTO jobs"
                    " (job_id, status, submitted_at, started_at, finished_at,"
                    " result_json, failure_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (identifier, job.status.value, timestamp, None, None, None, None),
                )
                self._insert_event(event)
                self._connection.execute("COMMIT")
                return job
            except BaseException:
                self._rollback()
                raise

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
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                current = self._require(identifier)
                updated = _transition_snapshot(
                    current, status, timestamp, result, failure_code
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
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._require(identifier)
                updated = _transition_snapshot(
                    current, status, timestamp, result, failure_code
                )
                event = JobEvent(
                    len(_expected_events(current)) + 1,
                    identifier,
                    current.status,
                    status,
                    timestamp,
                )
                self._connection.execute(
                    "UPDATE jobs SET status = ?, started_at = ?, finished_at = ?,"
                    " result_json = ?, failure_code = ? WHERE job_id = ?",
                    (
                        updated.status.value,
                        updated.started_at,
                        updated.finished_at,
                        _result_json(updated.result),
                        updated.failure_code,
                        identifier,
                    ),
                )
                self._insert_event(event)
                self._connection.execute("COMMIT")
                return updated
            except BaseException:
                self._rollback()
                raise

    def get(self, job_id: str) -> Job:
        """Return the current immutable snapshot for one Job."""
        identifier = _validate_job_id(job_id)
        with self._lock:
            self._ensure_open()
            if self._connection is not None:
                return self._read_snapshot(identifier)[0]
            return self._require(identifier)

    def events(self, job_id: str) -> tuple[JobEvent, ...]:
        """Return ordered immutable transition evidence for one Job."""
        identifier = _validate_job_id(job_id)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                self._require(identifier)
                return tuple(self._events[identifier])
            return self._read_snapshot(identifier)[1]

    def _require(self, job_id: str) -> Job:
        if self._connection is None:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobStateError("job.not_found")
            return job
        job = self._load_job(job_id)
        self._load_events(job)
        return job

    def _read_snapshot(self, job_id: str) -> tuple[Job, tuple[JobEvent, ...]]:
        assert self._connection is not None
        try:
            self._connection.execute("BEGIN")
            job = self._load_job(job_id)
            events = self._load_events(job)
            self._connection.execute("COMMIT")
            return job, events
        except BaseException:
            self._rollback()
            raise

    def _load_job(self, job_id: str) -> Job:
        row = self._job_row(job_id)
        if row is None:
            raise JobStateError("job.not_found")
        return _job_from_row(row)

    def _job_row(self, job_id: str) -> sqlite3.Row | None:
        assert self._connection is not None
        return self._connection.execute(
            "SELECT job_id, status, submitted_at, started_at, finished_at,"
            " result_json, failure_code FROM jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()

    def _insert_event(self, event: JobEvent) -> None:
        assert self._connection is not None
        self._connection.execute(
            "INSERT INTO job_events"
            " (job_id, sequence, previous_status, status, at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                event.job_id,
                event.sequence,
                (
                    None
                    if event.previous_status is None
                    else event.previous_status.value
                ),
                event.status.value,
                event.at,
            ),
        )

    def _load_events(self, job: Job) -> tuple[JobEvent, ...]:
        assert self._connection is not None
        rows = self._connection.execute(
            "SELECT sequence, job_id, previous_status, status, at"
            " FROM job_events WHERE job_id = ? ORDER BY sequence",
            (job.job_id,),
        ).fetchall()
        try:
            events = tuple(_event_from_row(row) for row in rows)
        except (JobStateError, TypeError, ValueError) as exc:
            raise JobStateError("job.persisted_invalid") from exc
        if events != _expected_events(job):
            raise JobStateError("job.persisted_invalid")
        return events

    def _rollback(self) -> None:
        assert self._connection is not None
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")

    def _ensure_open(self) -> None:
        if self._closed:
            raise JobStateError("repository.closed")


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            result_json TEXT,
            failure_code TEXT
        );
        CREATE TABLE IF NOT EXISTS job_events (
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            sequence INTEGER NOT NULL,
            previous_status TEXT,
            status TEXT NOT NULL,
            at TEXT NOT NULL,
            PRIMARY KEY (job_id, sequence)
        );
        """)


def _transition_snapshot(  # pylint: disable=too-many-branches
    current: Job,
    status: JobStatus,
    timestamp: str,
    result: Result | None,
    failure_code: str | None,
) -> Job:
    if status not in _TRANSITIONS.get(current.status, frozenset()):
        raise JobStateError("job.transition_invalid")
    if result is not None and (
        result.status.value != status.value or result.manifest.run_id != current.job_id
    ):
        raise JobStateError("job.result_mismatch")
    if status is JobStatus.RUNNING and (result is not None or failure_code is not None):
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
    return replace(
        current,
        status=status,
        started_at=(timestamp if status is JobStatus.RUNNING else current.started_at),
        finished_at=(timestamp if status in _TERMINAL else None),
        result=result,
        failure_code=failure_code,
    )


def _job_from_row(row: sqlite3.Row) -> Job:
    try:
        identifier = _validate_job_id(row["job_id"])
        status = JobStatus(row["status"])
        submitted_at = _validate_time(row["submitted_at"])
        started_at = _optional_time(row["started_at"])
        finished_at = _optional_time(row["finished_at"])
        result = _result_from_json(row["result_json"])
        failure_code = row["failure_code"]
        if failure_code is not None and type(failure_code) is not str:
            raise JobStateError("job.failure_code_invalid")
        candidate = Job(
            identifier,
            status,
            submitted_at,
            started_at,
            finished_at,
            result,
            failure_code,
        )
        rebuilt = Job(identifier, JobStatus.SUBMITTED, submitted_at)
        if status is not JobStatus.SUBMITTED:
            if started_at is None:
                raise JobStateError("job.persisted_invalid")
            rebuilt = _transition_snapshot(
                rebuilt, JobStatus.RUNNING, started_at, None, None
            )
        if status in _TERMINAL:
            if finished_at is None:
                raise JobStateError("job.persisted_invalid")
            rebuilt = _transition_snapshot(
                rebuilt, status, finished_at, result, failure_code
            )
        if rebuilt != candidate:
            raise JobStateError("job.persisted_invalid")
        return rebuilt
    except (JobStateError, ResultValidationError, TypeError, ValueError) as exc:
        raise JobStateError("job.persisted_invalid") from exc


def _event_from_row(row: sqlite3.Row) -> JobEvent:
    sequence = row["sequence"]
    if type(sequence) is not int or sequence <= 0:
        raise JobStateError("job.persisted_invalid")
    identifier = _validate_job_id(row["job_id"])
    previous_raw = row["previous_status"]
    if previous_raw is not None and type(previous_raw) is not str:
        raise JobStateError("job.persisted_invalid")
    previous = None if previous_raw is None else JobStatus(previous_raw)
    status_raw = row["status"]
    if type(status_raw) is not str:
        raise JobStateError("job.persisted_invalid")
    return JobEvent(
        sequence,
        identifier,
        previous,
        JobStatus(status_raw),
        _validate_time(row["at"]),
    )


def _expected_events(job: Job) -> tuple[JobEvent, ...]:
    events = [JobEvent(1, job.job_id, None, JobStatus.SUBMITTED, job.submitted_at)]
    if job.started_at is not None:
        events.append(
            JobEvent(
                2,
                job.job_id,
                JobStatus.SUBMITTED,
                JobStatus.RUNNING,
                job.started_at,
            )
        )
    if job.finished_at is not None:
        events.append(
            JobEvent(
                3,
                job.job_id,
                JobStatus.RUNNING,
                job.status,
                job.finished_at,
            )
        )
    return tuple(events)


def _optional_time(value: object) -> str | None:
    return None if value is None else _validate_time(value)


def _result_json(result: Result | None) -> str | None:
    if result is None:
        return None
    return json.dumps(
        result.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _result_from_json(value: object) -> Result | None:
    if value is None:
        return None
    if type(value) is not str:
        raise JobStateError("job.persisted_invalid")
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise JobStateError("job.persisted_invalid") from exc
    return Result.from_dict(payload)


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
