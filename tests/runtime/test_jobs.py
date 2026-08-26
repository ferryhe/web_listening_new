"""Minimal Runtime Job lifecycle tests."""

# pylint: disable=missing-function-docstring,mixed-line-endings

from __future__ import annotations

import json
import sqlite3
import threading
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


def _make_symlink(link: Path, target: Path, *, directory: bool) -> None:
    """Create a test symlink or skip where the host denies that capability."""
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


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


@pytest.mark.parametrize("terminal", _TERMINALS)
def test_sqlite_repository_reopens_exact_job_result_and_event_history(
    tmp_path: Path, terminal: JobStatus
) -> None:
    database = tmp_path / "jobs.sqlite3"
    result, failure_code = _terminal_facts(terminal)
    job_id = result.manifest.run_id
    first = JobRepository(database)
    first.submit(job_id, at=RESULT_WINDOW_START)
    first.transition(job_id, JobStatus.RUNNING, at=RESULT_WINDOW_START)
    expected = first.transition(
        job_id,
        terminal,
        at=RESULT_WINDOW_END,
        result=result,
        failure_code=failure_code,
    )
    expected_events = first.events(job_id)
    first.close()

    reopened = JobRepository(database)

    assert reopened.get(job_id) == expected
    assert reopened.get(job_id).result == result
    assert reopened.events(job_id) == expected_events
    assert [event.sequence for event in reopened.events(job_id)] == [1, 2, 3]
    reopened.close()


def test_sqlite_repository_preserves_duplicate_not_found_and_transition_rules(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    first = JobRepository(database)
    first.submit("job-one", at=NOW)
    first.close()
    reopened = JobRepository(database)

    with pytest.raises(JobStateError) as duplicate:
        reopened.submit("job-one", at=NOW)
    with pytest.raises(JobStateError) as missing:
        reopened.get("job-missing")
    with pytest.raises(JobStateError) as invalid_transition:
        reopened.transition("job-one", JobStatus.COMPLETED, at=LATER)

    assert duplicate.value.code == "job.duplicate"
    assert missing.value.code == "job.not_found"
    assert invalid_transition.value.code == "job.transition_invalid"
    assert reopened.get("job-one").status is JobStatus.SUBMITTED
    reopened.close()


def test_sqlite_repository_reopens_terminal_failure_without_result(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    first = JobRepository(database)
    first.submit("job-one", at=NOW)
    first.transition("job-one", JobStatus.RUNNING, at=NOW)
    expected = first.transition(
        "job-one",
        JobStatus.FAILED,
        at=LATER,
        failure_code="runtime.pre_result_failure",
    )
    first.close()

    reopened = JobRepository(database)

    assert reopened.get("job-one") == expected
    assert reopened.get("job-one").result is None
    assert [event.status for event in reopened.events("job-one")] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        JobStatus.FAILED,
    ]
    reopened.close()


@pytest.mark.parametrize("operation", ["get", "events"])
# pylint: disable-next=too-many-locals,too-many-statements
def test_sqlite_reader_uses_one_snapshot_while_writer_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    database = tmp_path / "jobs.sqlite3"
    seed = JobRepository(database)
    seed.submit("job-one", at=NOW)
    seed.close()
    reader = JobRepository(database)
    writer = JobRepository(database)
    row_read = threading.Event()
    event_inserted = threading.Event()
    commit_started = threading.Event()
    writer_errors: list[BaseException] = []
    history_reads = 0
    read_row = reader._job_row  # pylint: disable=protected-access
    read_events = reader._load_events  # pylint: disable=protected-access
    insert_event = writer._insert_event  # pylint: disable=protected-access

    def pause_after_row(job_id: str):
        row = read_row(job_id)
        row_read.set()
        assert event_inserted.wait(5)
        assert commit_started.wait(5)
        return row

    def count_history(job):
        nonlocal history_reads
        history_reads += 1
        return read_events(job)

    def signal_inserted(event) -> None:
        insert_event(event)
        event_inserted.set()

    def trace(statement: str) -> None:
        if statement == "COMMIT":
            commit_started.set()

    monkeypatch.setattr(reader, "_job_row", pause_after_row)
    monkeypatch.setattr(reader, "_load_events", count_history)
    monkeypatch.setattr(writer, "_insert_event", signal_inserted)
    assert writer._connection is not None  # pylint: disable=protected-access
    writer._connection.set_trace_callback(trace)  # pylint: disable=protected-access

    def transition() -> None:
        assert row_read.wait(5)
        try:
            writer.transition("job-one", JobStatus.RUNNING, at=LATER)
        except BaseException as exc:  # pylint: disable=broad-exception-caught
            writer_errors.append(exc)

    thread = threading.Thread(target=transition)
    thread.start()
    observed = reader.get("job-one") if operation == "get" else reader.events("job-one")
    thread.join(5)
    monkeypatch.setattr(reader, "_job_row", read_row)
    monkeypatch.setattr(reader, "_load_events", read_events)

    assert not thread.is_alive()
    assert not writer_errors
    assert history_reads == 1
    if operation == "get":
        assert observed.status is JobStatus.SUBMITTED
    else:
        assert [event.status for event in observed] == [JobStatus.SUBMITTED]
    assert reader.get("job-one").status is JobStatus.RUNNING
    reader.close()
    writer.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("status", "unknown"),
        ("started_at", "2026-08-25T19:59:59Z"),
        ("result_json", "{not-json"),
        ("result_json", "{}"),
    ],
)
def test_sqlite_repository_rejects_corrupt_or_schema_invalid_job_records(
    tmp_path: Path, column: str, value: str
) -> None:
    database = tmp_path / "jobs.sqlite3"
    result, failure_code = _terminal_facts(JobStatus.COMPLETED)
    job_id = result.manifest.run_id
    repository = JobRepository(database)
    repository.submit(job_id, at=RESULT_WINDOW_START)
    repository.transition(job_id, JobStatus.RUNNING, at=RESULT_WINDOW_START)
    repository.transition(
        job_id,
        JobStatus.COMPLETED,
        at=RESULT_WINDOW_END,
        result=result,
        failure_code=failure_code,
    )
    repository.close()
    connection = sqlite3.connect(database)
    connection.execute(
        f"UPDATE jobs SET {column} = ? WHERE job_id = ?", (value, job_id)
    )
    connection.commit()
    connection.close()

    reopened = JobRepository(database)
    with pytest.raises(JobStateError) as error:
        reopened.get(job_id)

    assert error.value.code == "job.persisted_invalid"
    reopened.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [("sequence", 7), ("status", "unknown"), ("at", "not-a-time")],
)
def test_sqlite_repository_rejects_corrupt_event_records(
    tmp_path: Path, column: str, value: object
) -> None:
    database = tmp_path / "jobs.sqlite3"
    repository = JobRepository(database)
    repository.submit("job-one", at=NOW)
    repository.transition("job-one", JobStatus.RUNNING, at=LATER)
    repository.close()
    connection = sqlite3.connect(database)
    connection.execute(
        f"UPDATE job_events SET {column} = ?" " WHERE job_id = ? AND sequence = 2",
        (value, "job-one"),
    )
    connection.commit()
    connection.close()

    reopened = JobRepository(database)
    with pytest.raises(JobStateError) as get_error:
        reopened.get("job-one")
    with pytest.raises(JobStateError) as events_error:
        reopened.events("job-one")

    assert get_error.value.code == "job.persisted_invalid"
    assert events_error.value.code == "job.persisted_invalid"
    reopened.close()


def test_sqlite_repository_close_is_idempotent_and_rejects_future_operations(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3")
    repository.close()
    repository.close()

    with pytest.raises(JobStateError) as error:
        repository.get("job-one")

    assert error.value.code == "repository.closed"


def test_sqlite_database_symlink_is_rejected_without_mutating_target(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "runtime-data"
    data_dir.mkdir()
    victim = tmp_path / "outside.sqlite3"
    original = b"outside content must remain unchanged"
    victim.write_bytes(original)
    _make_symlink(data_dir / "jobs.sqlite3", victim, directory=False)

    with pytest.raises(JobStateError) as error:
        JobRepository(data_dir / "jobs.sqlite3")

    assert error.value.code == "path.symlink"
    assert victim.read_bytes() == original


def test_sqlite_parent_symlink_is_rejected_without_outside_mutation(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "runtime-data"
    _make_symlink(link, outside, directory=True)

    with pytest.raises(JobStateError) as error:
        JobRepository(link / "jobs.sqlite3")

    assert error.value.code == "path.symlink"
    assert not list(outside.iterdir())


def test_sqlite_parent_junction_is_rejected_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "runtime-data"
    data_dir.mkdir()
    sentinel = data_dir / "sentinel"
    sentinel.write_bytes(b"preserve")
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda candidate: candidate == data_dir,
        raising=False,
    )

    with pytest.raises(JobStateError) as error:
        JobRepository(data_dir / "jobs.sqlite3")

    assert error.value.code == "path.symlink"
    assert list(data_dir.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"preserve"


def test_sqlite_database_must_be_a_regular_file(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    database.mkdir()

    with pytest.raises(JobStateError) as error:
        JobRepository(database)

    assert error.value.code == "path.not_file"
    assert not list(database.iterdir())


def test_sqlite_existing_regular_file_is_opened(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    database.touch()

    repository = JobRepository(database)
    submitted = repository.submit("job-one", at=NOW)

    assert submitted.status is JobStatus.SUBMITTED
    assert database.is_file()
    repository.close()


def test_sqlite_open_failure_does_not_mutate_outside_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "runtime-data"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"preserve")
    attempted: list[Path] = []

    def fail_open(path: Path, **_kwargs: object) -> sqlite3.Connection:
        attempted.append(path)
        raise OSError("injected SQLite open failure")

    monkeypatch.setattr(sqlite3, "connect", fail_open)

    with pytest.raises(OSError, match="injected SQLite open failure"):
        JobRepository(data_dir / "jobs.sqlite3")

    assert attempted == [data_dir / "jobs.sqlite3"]
    assert list(outside.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"preserve"
    assert not (data_dir / "jobs.sqlite3").exists()
