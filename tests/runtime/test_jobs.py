"""Minimal Runtime Job lifecycle tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from web_listening.result.errors import parse_utc_time
from web_listening.result.model import Result
from web_listening.runtime.jobs import (
    JobRepository,
    JobStateError,
    JobStatus,
)

NOW = "2026-08-25T20:00:00Z"
LATER = "2026-08-25T20:00:01Z"
RESULT_WINDOW_START = "2026-08-25T00:00:00Z"
RESULT_WINDOW_END = "2026-08-25T23:59:59Z"

_RESULT_FIXTURES = {
    JobStatus.COMPLETED: "completed.v1.json",
    JobStatus.PARTIAL: "partial.v1.json",
    JobStatus.REJECTED: "rejected-boundary.v1.json",
    JobStatus.FAILED: "failed.v1.json",
}


def _result(status: JobStatus) -> Result:
    fixture = (
        Path(__file__).parents[1] / "result" / "fixtures" / _RESULT_FIXTURES[status]
    )
    return Result.from_dict(json.loads(fixture.read_text(encoding="utf-8")))


def _terminal_facts(status: JobStatus) -> tuple[Result, str | None]:
    result = _result(status)
    failure_code = result.errors[0].code if result.errors else None
    return result, failure_code


@pytest.mark.parametrize(
    "terminal",
    [
        JobStatus.COMPLETED,
        JobStatus.PARTIAL,
        JobStatus.REJECTED,
        JobStatus.FAILED,
    ],
)
def test_submitted_running_terminal_transitions_are_explicit(
    terminal: JobStatus,
) -> None:
    repository = JobRepository()
    result, failure_code = _terminal_facts(terminal)
    job_id = result.manifest.run_id

    submitted = repository.submit(job_id, at=RESULT_WINDOW_START)
    running = repository.transition(job_id, JobStatus.RUNNING, at=RESULT_WINDOW_START)
    finished = repository.transition(
        job_id,
        terminal,
        at=RESULT_WINDOW_END,
        result=result,
        failure_code=failure_code,
    )

    assert submitted.status is JobStatus.SUBMITTED
    assert submitted.submitted_at == RESULT_WINDOW_START
    assert submitted.started_at is None
    assert running.status is JobStatus.RUNNING
    assert running.started_at == RESULT_WINDOW_START
    assert finished.status is terminal
    assert finished.finished_at == RESULT_WINDOW_END
    assert repository.get(job_id) == finished
    assert [event.status for event in repository.events(job_id)] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        terminal,
    ]
    assert [event.sequence for event in repository.events(job_id)] == [1, 2, 3]


_TERMINALS = (
    JobStatus.COMPLETED,
    JobStatus.PARTIAL,
    JobStatus.REJECTED,
    JobStatus.FAILED,
)
_LEGAL = {
    (JobStatus.SUBMITTED, JobStatus.RUNNING),
    *((JobStatus.RUNNING, terminal) for terminal in _TERMINALS),
}
_ILLEGAL = tuple(
    (current, target)
    for current in JobStatus
    for target in JobStatus
    if (current, target) not in _LEGAL
)


@pytest.mark.parametrize(("current", "illegal"), _ILLEGAL)
def test_every_other_job_transition_is_rejected(
    current: JobStatus, illegal: JobStatus
) -> None:
    repository = JobRepository()
    result_facts = _terminal_facts(current) if current in _TERMINALS else None
    job_id = result_facts[0].manifest.run_id if result_facts else "job-one"
    started_at = RESULT_WINDOW_START if result_facts else NOW
    terminal_at = RESULT_WINDOW_END if result_facts else LATER
    repository.submit(job_id, at=started_at)
    if current is not JobStatus.SUBMITTED:
        repository.transition(job_id, JobStatus.RUNNING, at=started_at)
        if current is not JobStatus.RUNNING:
            assert result_facts is not None
            result, failure_code = result_facts
            repository.transition(
                job_id,
                current,
                at=terminal_at,
                result=result,
                failure_code=failure_code,
            )

    with pytest.raises(JobStateError) as error:
        repository.transition(job_id, illegal, at=terminal_at)

    assert error.value.code == "job.transition_invalid"


def test_job_repository_rejects_duplicate_and_missing_identities() -> None:
    repository = JobRepository()
    repository.submit("job-one", at=NOW)

    with pytest.raises(JobStateError) as duplicate:
        repository.submit("job-one", at=NOW)
    with pytest.raises(JobStateError) as missing:
        repository.get("job-missing")

    assert duplicate.value.code == "job.duplicate"
    assert missing.value.code == "job.not_found"


def test_job_timestamps_cannot_move_backwards() -> None:
    repository = JobRepository()
    repository.submit("job-one", at=LATER)

    with pytest.raises(JobStateError) as before_submit:
        repository.transition("job-one", JobStatus.RUNNING, at=NOW)

    assert before_submit.value.code == "job.time_invalid"
    assert repository.get("job-one").status is JobStatus.SUBMITTED

    repository = JobRepository()
    result, failure_code = _terminal_facts(JobStatus.FAILED)
    job_id = result.manifest.run_id
    repository.submit(job_id, at=NOW)
    repository.transition(job_id, JobStatus.RUNNING, at=LATER)

    with pytest.raises(JobStateError) as before_start:
        repository.transition(
            job_id,
            JobStatus.FAILED,
            at=NOW,
            result=result,
            failure_code=failure_code,
        )

    assert before_start.value.code == "job.time_invalid"
    assert repository.get(job_id).status is JobStatus.RUNNING


@pytest.mark.parametrize("terminal", [JobStatus.COMPLETED, JobStatus.PARTIAL])
def test_success_bearing_terminal_requires_result(terminal: JobStatus) -> None:
    repository = JobRepository()
    repository.submit("job-one", at=NOW)
    repository.transition("job-one", JobStatus.RUNNING, at=NOW)

    with pytest.raises(JobStateError) as error:
        repository.transition("job-one", terminal, at=LATER)

    assert error.value.code == "job.result_required"


@pytest.mark.parametrize("terminal", [JobStatus.REJECTED, JobStatus.FAILED])
def test_pre_result_failure_requires_a_safe_stable_code(
    terminal: JobStatus,
) -> None:
    repository = JobRepository()
    repository.submit("job-one", at=NOW)
    repository.transition("job-one", JobStatus.RUNNING, at=NOW)

    with pytest.raises(JobStateError) as missing:
        repository.transition("job-one", terminal, at=LATER)
    with pytest.raises(JobStateError) as unsafe:
        repository.transition(
            "job-one", terminal, at=LATER, failure_code="PRIVATE ERROR"
        )

    assert missing.value.code == "job.failure_code_required"
    assert unsafe.value.code == "job.failure_code_invalid"
    finished = repository.transition(
        "job-one", terminal, at=LATER, failure_code="runtime.pre_result_failure"
    )
    assert finished.failure_code == "runtime.pre_result_failure"


@pytest.mark.parametrize("terminal", _TERMINALS)
def test_result_failure_code_must_match_first_error_fact(
    terminal: JobStatus,
) -> None:
    repository = JobRepository()
    result = _result(terminal)
    job_id = result.manifest.run_id
    repository.submit(job_id, at=RESULT_WINDOW_START)
    repository.transition(job_id, JobStatus.RUNNING, at=RESULT_WINDOW_START)

    with pytest.raises(JobStateError) as error:
        repository.transition(
            job_id,
            terminal,
            at=RESULT_WINDOW_END,
            result=result,
            failure_code="runtime.wrong_code",
        )

    assert error.value.code == "job.failure_code_mismatch"


def test_terminal_result_cannot_predate_job_start() -> None:
    repository = JobRepository()
    result = _result(JobStatus.COMPLETED)
    job_id = result.manifest.run_id
    started_at = "2026-08-25T23:59:58Z"
    result_times = (
        result.manifest.generated_at,
        result.attempts[0].started_at,
        result.attempts[0].finished_at,
        result.artifacts[0].observed_at,
    )
    assert all(
        parse_utc_time(value) < parse_utc_time(started_at) for value in result_times
    )
    repository.submit(job_id, at=started_at)
    repository.transition(job_id, JobStatus.RUNNING, at=started_at)

    with pytest.raises(JobStateError) as error:
        repository.transition(
            job_id,
            JobStatus.COMPLETED,
            at=RESULT_WINDOW_END,
            result=result,
        )

    assert error.value.code == "job.time_invalid"
    assert repository.get(job_id).status is JobStatus.RUNNING


def test_terminal_result_facts_cannot_postdate_terminal_event() -> None:
    repository = JobRepository()
    result = _result(JobStatus.COMPLETED)
    job_id = result.manifest.run_id
    terminal_at = "2026-08-25T00:00:01Z"
    result_times = (
        result.manifest.generated_at,
        result.attempts[0].started_at,
        result.attempts[0].finished_at,
        result.artifacts[0].observed_at,
    )
    assert all(
        parse_utc_time(value) > parse_utc_time(terminal_at) for value in result_times
    )
    repository.submit(job_id, at=RESULT_WINDOW_START)
    repository.transition(job_id, JobStatus.RUNNING, at=RESULT_WINDOW_START)

    with pytest.raises(JobStateError) as error:
        repository.transition(
            job_id,
            JobStatus.COMPLETED,
            at=terminal_at,
            result=result,
        )

    assert error.value.code == "job.time_invalid"
    assert repository.get(job_id).status is JobStatus.RUNNING


def test_terminal_result_must_belong_to_the_same_job() -> None:
    repository = JobRepository()
    result = _result(JobStatus.COMPLETED)
    assert result.manifest.run_id == "run-completed-001"
    repository.submit("job-one", at=NOW)
    repository.transition("job-one", JobStatus.RUNNING, at=NOW)

    with pytest.raises(JobStateError) as error:
        repository.transition("job-one", JobStatus.COMPLETED, at=LATER, result=result)

    assert error.value.code == "job.result_mismatch"
    assert repository.get("job-one").status is JobStatus.RUNNING


def test_job_and_event_reads_are_immutable_snapshots() -> None:
    repository = JobRepository()
    job = repository.submit("job-one", at=NOW)
    event = repository.events("job-one")[0]

    with pytest.raises(FrozenInstanceError):
        job.status = JobStatus.FAILED  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        event.status = JobStatus.FAILED  # type: ignore[misc]

    assert repository.get("job-one").status is JobStatus.SUBMITTED
