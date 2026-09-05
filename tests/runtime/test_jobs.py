"""Minimal Runtime Job lifecycle tests."""

# pylint: disable=missing-function-docstring,mixed-line-endings,too-many-lines

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.request.site_batch import SiteBatchPhase, SiteBatchRequest
from web_listening.result.errors import parse_utc_time
from web_listening.result.model import Result
from web_listening.runtime.jobs import (
    JobRepository,
    JobStateError,
    JobStatus,
    canonical_request_facts,
)
from web_listening.runtime.site_batch import site_batch_result_from_mapping
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.manifest import ToolCategory

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


def _request() -> Request:
    return Request(
        Scope(
            ("https://example.test/report",),
            ("https://example.test",),
            ("/report",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(2, 1000, 10, 1),
    )


def _batch_request(max_requests: int = 2) -> SiteBatchRequest:
    return SiteBatchRequest(
        SiteBatchPhase.FIRST,
        Request(
            Scope(
                ("https://one.test/report", "https://two.test/report"),
                ("https://one.test", "https://two.test"),
                ("/report",),
                (ContentType.HTML,),
            ),
            None,
            False,
            Budgets(max_requests, 1000, 10, 1),
        ),
        (),
    )


def _batch_children():
    fixture = (
        Path(__file__).parents[1] / "result/fixtures/site-batch-first-usable.v1.json"
    )
    return site_batch_result_from_mapping(
        json.loads(fixture.read_text(encoding="utf-8"))
    ).site_results


def test_site_batch_submission_is_ordered_idempotent_and_persistent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    repository = JobRepository(database)
    first = repository.submit_batch(
        "batch-one", _batch_request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    replay = repository.submit_batch(
        "batch-two",
        _batch_request(),
        caller_id="caller",
        idempotency_key="key",
        at=LATER,
    )
    assert replay.batch_id == first.batch_id
    assert [(item.order, item.site_key, item.status) for item in first.children] == [
        (1, "one.test", "submitted"),
        (2, "two.test", "submitted"),
    ]
    with pytest.raises(JobStateError, match="^idempotency.conflict$"):
        repository.submit_batch(
            "batch-three",
            _batch_request(3),
            caller_id="caller",
            idempotency_key="key",
            at=LATER,
        )
    repository.close()
    reopened = JobRepository(database)
    assert (
        reopened.get_batch("batch-one").request_fingerprint == first.request_fingerprint
    )
    reopened.close()


def test_site_batch_cancel_preserves_first_timestamp_and_restarts_running(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    repository = JobRepository(database)
    repository.submit_batch(
        "batch-one", _batch_request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    claimed = repository.claim_next_batch(at=LATER)
    assert claimed is not None and claimed.batch.status is JobStatus.RUNNING
    first = repository.cancel_batch("batch-one", at="2026-08-25T20:00:02Z")
    second = repository.cancel_batch("batch-one", at="2026-08-25T20:00:03Z")
    assert second.cancel_requested_at == first.cancel_requested_at
    repository.close()
    reopened = JobRepository(database)
    reopened.reconcile_batches()
    assert reopened.get_batch("batch-one").status is JobStatus.SUBMITTED
    reopened.close()


def test_two_sqlite_handles_never_both_claim_the_same_batch(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    first = JobRepository(database)
    second = JobRepository(database)
    first.submit_batch(
        "batch-one", _batch_request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    barrier = threading.Barrier(3)
    claims = []

    def claim(repository: JobRepository) -> None:
        barrier.wait()
        claims.append(repository.claim_next_batch(at=LATER))

    threads = [
        threading.Thread(target=claim, args=(repository,))
        for repository in (first, second)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    obtained = [item for item in claims if item is not None]
    assert len(obtained) == 1
    assert obtained[0].batch.batch_id == "batch-one"
    first.close()
    second.close()


def test_sqlite_checkpoint_rejects_skipped_repeated_and_out_of_order(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3")
    repository.submit_batch(
        "batch-one", _batch_request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    assert repository.claim_next_batch(at=LATER) is not None
    children = _batch_children()
    with pytest.raises(JobStateError, match="^batch.checkpoint_order_invalid$"):
        repository.checkpoint_batch("batch-one", 2, children[1])
    repository.checkpoint_batch("batch-one", 1, children[0])
    with pytest.raises(JobStateError, match="^batch.checkpoint_order_invalid$"):
        repository.checkpoint_batch("batch-one", 1, children[0])
    with pytest.raises(JobStateError, match="^batch.checkpoint_order_invalid$"):
        repository.checkpoint_batch("batch-one", 3, children[1])
    assert len(repository.batch_checkpoint_results("batch-one")) == 1
    repository.close()


def _site_skill():
    request = _request()
    return create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=request.scope,
        budgets=request.budgets,
        tool=ToolReference(
            tool_id="acquisition.web_http",
            version="1.0.0",
            category=ToolCategory.ACQUISITION,
            capabilities=frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
    ).skill


# pylint: disable-next=too-many-return-statements
def _invalid_execution_request(request: Request, difference: str) -> Request:
    if difference in {
        "max_requests",
        "max_bytes",
        "max_runtime_seconds",
        "max_tool_attempts_per_target",
    }:
        return replace(
            request,
            budgets=replace(
                request.budgets,
                **{difference: getattr(request.budgets, difference) + 1},
            ),
        )
    if difference == "seeds":
        return replace(
            request,
            scope=replace(
                request.scope,
                seeds=(*request.scope.seeds, "https://example.test/report?part=2"),
            ),
        )
    if difference == "allowed_origins":
        return replace(
            request,
            scope=replace(
                request.scope,
                allowed_origins=(*request.scope.allowed_origins, "https://other.test"),
            ),
        )
    if difference == "include_paths":
        return replace(
            request,
            scope=replace(
                request.scope, include_paths=(*request.scope.include_paths, "/other")
            ),
        )
    if difference == "content_types":
        return replace(
            request,
            scope=replace(
                request.scope,
                content_types=(*request.scope.content_types, ContentType.FILE),
            ),
        )
    if difference == "site_skill":
        return replace(request, site_skill=_site_skill())
    if difference == "explore_all_tools":
        return replace(request, explore_all_tools=True)
    raise AssertionError(difference)


def test_in_memory_persisted_request_must_be_claimed_to_enter_running() -> None:
    repository = JobRepository()
    submitted = repository.submit_request(
        "job-one",
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=NOW,
    )
    events = repository.events(submitted.job_id)

    for token in (None, "forged-token"):
        with pytest.raises(JobStateError, match="^job.claim_required$"):
            repository.transition(
                submitted.job_id, JobStatus.RUNNING, at=LATER, claim_token=token
            )

    assert repository.get(submitted.job_id) == submitted
    assert repository.events(submitted.job_id) == events


def test_sqlite_persisted_request_must_be_claimed_to_enter_running(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3")
    submitted = repository.submit_request(
        "job-one",
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=NOW,
    )
    events = repository.events(submitted.job_id)

    for token in (None, "forged-token"):
        with pytest.raises(JobStateError, match="^job.claim_required$"):
            repository.transition(
                submitted.job_id, JobStatus.RUNNING, at=LATER, claim_token=token
            )

    assert repository.get(submitted.job_id) == submitted
    assert repository.events(submitted.job_id) == events


@pytest.mark.parametrize("persistent", [False, True])
def test_claim_installs_facts_and_only_matching_token_terminalizes(
    tmp_path: Path, persistent: bool
) -> None:
    result, failure_code = _terminal_facts(JobStatus.FAILED)
    repository = JobRepository(tmp_path / "jobs.sqlite3" if persistent else None)
    repository.submit_request(
        result.manifest.run_id,
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=RESULT_WINDOW_START,
    )

    claim = repository.claim_next(
        "worker-one",
        at=RESULT_WINDOW_START,
        lease_deadline="2026-08-25T00:10:00Z",
    )

    assert claim is not None
    assert claim.job.status is JobStatus.RUNNING
    assert claim.job.worker_id == "worker-one"
    assert claim.job.started_at == RESULT_WINDOW_START
    assert claim.job.claimed_at == RESULT_WINDOW_START
    assert claim.job.lease_deadline == "2026-08-25T00:10:00Z"
    assert claim.job.claim_token == claim.token
    assert len(claim.token) == 64
    assert claim.request == _request()
    running_events = repository.events(claim.job.job_id)

    for token in (None, "stale-token"):
        with pytest.raises(JobStateError, match="^job.claim_stale$"):
            repository.transition(
                claim.job.job_id,
                JobStatus.FAILED,
                at=RESULT_WINDOW_END,
                result=result,
                failure_code=failure_code,
                claim_token=token,
            )
        assert repository.get(claim.job.job_id) == claim.job
        assert repository.events(claim.job.job_id) == running_events

    finished = repository.transition(
        claim.job.job_id,
        JobStatus.FAILED,
        at=RESULT_WINDOW_END,
        result=result,
        failure_code=failure_code,
        claim_token=claim.token,
    )

    assert finished.status is JobStatus.FAILED
    assert repository.events(claim.job.job_id)[-1].status is JobStatus.FAILED


def test_legacy_submit_remains_tokenless_transition_compatible() -> None:
    result, failure_code = _terminal_facts(JobStatus.FAILED)
    repository = JobRepository()
    submitted = repository.submit(result.manifest.run_id, at=RESULT_WINDOW_START)

    running = repository.transition(
        submitted.job_id, JobStatus.RUNNING, at=RESULT_WINDOW_START
    )
    finished = repository.transition(
        submitted.job_id,
        JobStatus.FAILED,
        at=RESULT_WINDOW_END,
        result=result,
        failure_code=failure_code,
    )

    assert running.claim_token is None
    assert finished.status is JobStatus.FAILED


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


@pytest.mark.parametrize(
    ("terminal", "failure_code"),
    [
        (JobStatus.REJECTED, "runtime.pre_result_failure"),
        (JobStatus.FAILED, "runtime.pre_result_failure"),
        (JobStatus.REJECTED, "service.restart_interrupted"),
        (JobStatus.FAILED, "runtime.workflow_failed"),
    ],
)
@pytest.mark.parametrize("persistent", [False, True])
def test_only_restart_interruption_may_terminalize_without_result(
    tmp_path: Path, terminal: JobStatus, failure_code: str, persistent: bool
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3" if persistent else None)
    repository.submit("job-one", at=NOW)
    repository.transition("job-one", JobStatus.RUNNING, at=NOW)

    with pytest.raises(JobStateError) as error:
        repository.transition("job-one", terminal, at=LATER, failure_code=failure_code)

    assert error.value.code == "job.result_required"


@pytest.mark.parametrize("persistent", [False, True])
def test_restart_interruption_is_the_only_resultless_terminal_state(
    tmp_path: Path, persistent: bool
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3" if persistent else None)
    repository.submit("job-one", at=NOW)
    repository.transition("job-one", JobStatus.RUNNING, at=NOW)

    finished = repository.transition(
        "job-one",
        JobStatus.FAILED,
        at=LATER,
        failure_code="service.restart_interrupted",
    )

    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "service.restart_interrupted"
    assert finished.result is None


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


def test_sqlite_repository_reopens_restart_interruption_without_result(
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
        failure_code="service.restart_interrupted",
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


def test_request_submission_is_atomic_idempotent_and_caller_scoped(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3")
    first = repository.submit_request(
        "job-one", _request(), caller_id="caller-a", idempotency_key="same-key", at=NOW
    )
    replay = repository.submit_request(
        "job-other",
        _request(),
        caller_id="caller-a",
        idempotency_key="same-key",
        at=LATER,
    )
    isolated = repository.submit_request(
        "job-two",
        _request(),
        caller_id="caller-b",
        idempotency_key="same-key",
        at=LATER,
    )

    assert replay == first
    assert isolated.job_id == "job-two"
    assert repository.request(first.job_id) == _request()
    assert len(first.request_fingerprint or "") == 64

    conflicting = replace(_request(), explore_all_tools=True)
    with pytest.raises(JobStateError, match="idempotency.conflict"):
        repository.submit_request(
            "job-three",
            conflicting,
            caller_id="caller-a",
            idempotency_key="same-key",
            at=LATER,
        )
    assert repository.get("job-one") == first


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
@pytest.mark.parametrize(
    "difference",
    [
        "max_requests",
        "max_bytes",
        "max_runtime_seconds",
        "max_tool_attempts_per_target",
        "seeds",
        "allowed_origins",
        "include_paths",
        "content_types",
        "site_skill",
        "explore_all_tools",
    ],
)
def test_submit_rejects_execution_request_outside_original_authority_without_write(
    tmp_path: Path, persistent: bool, difference: str
) -> None:
    database = tmp_path / f"invalid-{difference}.sqlite3"
    repository = JobRepository(database if persistent else None)
    original = _request()
    execution = _invalid_execution_request(original, difference)

    with pytest.raises(JobStateError, match="^request.execution_authority_invalid$"):
        repository.submit_request(
            "job-invalid",
            original,
            execution_request=execution,
            caller_id="caller",
            idempotency_key="key",
            at=NOW,
        )

    with pytest.raises(JobStateError, match="^job.not_found$"):
        repository.get("job-invalid")
    with pytest.raises(JobStateError, match="^job.not_found$"):
        repository.events("job-invalid")
    assert (
        repository.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
        is None
    )
    if persistent:
        connection = sqlite3.connect(database)
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM job_events").fetchone()[0] == 0
        connection.close()
    repository.close()


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
@pytest.mark.parametrize(
    "difference",
    [
        "exact",
        "canonical-ordering",
        "max_requests",
        "max_bytes",
        "max_runtime_seconds",
        "max_tool_attempts_per_target",
    ],
)
def test_submit_accepts_equal_or_narrowed_execution_authority_and_claims_it(
    tmp_path: Path, persistent: bool, difference: str
) -> None:
    database = tmp_path / f"accepted-{difference}.sqlite3"
    original = Request(
        Scope(
            ("https://example.test/report",),
            ("https://other.test", "https://example.test"),
            ("/z/**", "/report"),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        Budgets(3, 2000, 20, 2),
    )
    execution = original
    if difference == "canonical-ordering":
        execution = replace(
            original,
            scope=replace(
                original.scope,
                allowed_origins=tuple(reversed(original.scope.allowed_origins)),
                include_paths=tuple(reversed(original.scope.include_paths)),
                content_types=tuple(reversed(original.scope.content_types)),
            ),
        )
    elif difference != "exact":
        execution = replace(
            original,
            budgets=replace(
                original.budgets,
                **{difference: getattr(original.budgets, difference) - 1},
            ),
        )
    expected_original = canonical_request_facts(original)[0]
    expected_execution = canonical_request_facts(execution)[0]
    repository = JobRepository(database if persistent else None)
    submitted = repository.submit_request(
        "job-accepted",
        original,
        execution_request=execution,
        caller_id="caller",
        idempotency_key="key",
        at=NOW,
    )
    if persistent:
        repository.close()
        repository = JobRepository(database)

    assert repository.request(submitted.job_id) == expected_original
    assert repository.execution_request(submitted.job_id) == expected_execution
    claim = repository.claim_next(
        "worker", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None
    assert claim.request == expected_execution
    assert claim.job.request_json == submitted.request_json
    assert claim.job.execution_request_json == submitted.execution_request_json
    repository.close()


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
def test_invalid_execution_authority_cannot_replay_an_existing_idempotent_job(
    tmp_path: Path, persistent: bool
) -> None:
    database = tmp_path / "duplicate-boundary.sqlite3"
    repository = JobRepository(database if persistent else None)
    original = _request()
    first = repository.submit_request(
        "job-one",
        original,
        caller_id="caller",
        idempotency_key="key",
        at=NOW,
    )
    first_events = repository.events(first.job_id)

    with pytest.raises(JobStateError, match="^request.execution_authority_invalid$"):
        repository.submit_request(
            "job-two",
            original,
            execution_request=_invalid_execution_request(original, "max_requests"),
            caller_id="caller",
            idempotency_key="key",
            at=LATER,
        )

    assert repository.get(first.job_id) == first
    assert repository.events(first.job_id) == first_events
    with pytest.raises(JobStateError, match="^job.not_found$"):
        repository.get("job-two")
    if persistent:
        connection = sqlite3.connect(database)
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM job_events").fetchone()[0] == 1
        connection.close()
    repository.close()


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
def test_concurrent_valid_and_invalid_duplicate_submission_persists_only_valid_job(
    tmp_path: Path, persistent: bool
) -> None:
    database = tmp_path / "concurrent-boundary.sqlite3"
    repository = JobRepository(database if persistent else None)
    original = _request()
    barrier = threading.Barrier(3)
    outcomes: list[str] = []

    def submit(job_id: str, execution: Request) -> None:
        barrier.wait()
        try:
            repository.submit_request(
                job_id,
                original,
                execution_request=execution,
                caller_id="caller",
                idempotency_key="key",
                at=NOW,
            )
            outcomes.append("accepted")
        except JobStateError as exc:
            outcomes.append(exc.code)

    threads = (
        threading.Thread(target=submit, args=("job-valid", original)),
        threading.Thread(
            target=submit,
            args=(
                "job-invalid",
                _invalid_execution_request(original, "max_requests"),
            ),
        ),
    )
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["accepted", "request.execution_authority_invalid"]
    assert repository.get("job-valid").status is JobStatus.SUBMITTED
    with pytest.raises(JobStateError, match="^job.not_found$"):
        repository.get("job-invalid")
    assert len(repository.events("job-valid")) == 1
    if persistent:
        connection = sqlite3.connect(database)
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM job_events").fetchone()[0] == 1
        connection.close()
    claim = repository.claim_next(
        "worker", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None and claim.request == original
    repository.close()


def test_reordered_set_like_scope_fields_replay_and_round_trip_canonically(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    request = replace(
        _request(),
        scope=Scope(
            ("https://example.test/report",),
            ("https://other.test", "https://example.test"),
            ("/z/**", "/report"),
            (ContentType.HTML, ContentType.FILE),
        ),
    )
    reordered = replace(
        request,
        scope=replace(
            request.scope,
            allowed_origins=tuple(reversed(request.scope.allowed_origins)),
            include_paths=tuple(reversed(request.scope.include_paths)),
            content_types=tuple(reversed(request.scope.content_types)),
        ),
    )
    repository = JobRepository(database)
    first = repository.submit_request(
        "job-one", request, caller_id="caller", idempotency_key="scope", at=NOW
    )
    replay = repository.submit_request(
        "job-two", reordered, caller_id="caller", idempotency_key="scope", at=LATER
    )

    assert replay == first
    assert repository.request(first.job_id).scope == Scope(
        request.scope.seeds,
        tuple(sorted(request.scope.allowed_origins)),
        tuple(sorted(request.scope.include_paths)),
        tuple(sorted(request.scope.content_types, key=lambda item: item.value)),
    )
    assert json.loads(first.request_json or "")["scope"] == {
        "seeds": list(request.scope.seeds),
        "allowed_origins": sorted(request.scope.allowed_origins),
        "include_paths": sorted(request.scope.include_paths),
        "content_types": sorted(item.value for item in request.scope.content_types),
    }
    repository.close()

    reopened = JobRepository(database)
    assert reopened.get(first.job_id).request_fingerprint == first.request_fingerprint
    assert reopened.request(first.job_id).scope.seeds == request.scope.seeds


@pytest.mark.parametrize("key", [" ", " key ", " " * 128, "!", "~"])
def test_printable_ascii_idempotency_key_preserves_exact_identity(
    tmp_path: Path, key: str
) -> None:
    repository = JobRepository(tmp_path / f"key-{len(key)}-{ord(key[0])}.sqlite3")
    first = repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key=key, at=NOW
    )
    replay = repository.submit_request(
        "job-two", _request(), caller_id="caller", idempotency_key=key, at=LATER
    )

    assert replay == first
    assert first.idempotency_key == key
    assert repository.get(first.job_id).idempotency_key == key


@pytest.mark.parametrize("key", ["", " " * 129, "\x1f", "\x7f", "é"])
def test_idempotency_key_rejects_values_outside_exact_printable_ascii_domain(
    tmp_path: Path, key: str
) -> None:
    database = tmp_path / f"invalid-{len(key)}-{ord(key[0]) if key else 0}.sqlite3"
    repository = JobRepository(database)

    with pytest.raises(JobStateError, match="^idempotency.key_invalid$"):
        repository.submit_request(
            "job-one", _request(), caller_id="caller", idempotency_key=key, at=NOW
        )

    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    connection.close()


@pytest.mark.parametrize(
    "query",
    [
        "access_token=private-value",
        "api_key=private-value",
        "credential=private-value",
        "password=private-value",
        "refresh%5Ftoken=private-value",
        "authorization=Bearer%20private-value",
    ],
)
def test_sensitive_request_payload_is_rejected_before_any_sqlite_write(
    tmp_path: Path, query: str
) -> None:
    database = tmp_path / "jobs.sqlite3"
    repository = JobRepository(database)
    request = _request()
    request = replace(
        request,
        scope=replace(
            request.scope,
            seeds=(f"https://example.test/report?{query}",),
        ),
    )

    with pytest.raises(JobStateError, match="^request.sensitive_data$"):
        repository.submit_request(
            "job-secret",
            request,
            caller_id="caller-a",
            idempotency_key="key-a",
            at=NOW,
        )

    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM job_events").fetchone()[0] == 0
    connection.close()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("tokenizer", "wordpiece"),
        ("authorization_date", "2026-09-05"),
        ("sessionidentifier", "public-record"),
    ],
)
def test_safe_nearby_query_keys_persist_and_restart(
    tmp_path: Path, key: str, value: str
) -> None:
    database = tmp_path / "jobs.sqlite3"
    request = _request()
    request = replace(
        request,
        scope=replace(
            request.scope,
            seeds=(f"https://example.test/report?{key}={value}",),
        ),
    )
    repository = JobRepository(database)
    submitted = repository.submit_request(
        "job-safe",
        request,
        caller_id="caller-a",
        idempotency_key="key-a",
        at=NOW,
    )
    repository.close()

    reopened = JobRepository(database)
    assert reopened.request(submitted.job_id) == request
    claim = reopened.claim_next(
        "worker-one", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None and claim.request == request


def test_original_identity_and_narrowed_execution_are_distinct_durable_facts(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    original = replace(_request(), budgets=Budgets(101, 1000, 10, 1))
    admitted = replace(original, budgets=Budgets(100, 1000, 10, 1))
    repository = JobRepository(database)
    submitted = repository.submit_request(
        "job-one",
        original,
        execution_request=admitted,
        caller_id="caller-a",
        idempotency_key="key-a",
        at=NOW,
    )
    repository.close()

    reopened = JobRepository(database)
    assert reopened.request(submitted.job_id) == original
    claim = reopened.claim_next(
        "worker-one", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None and claim.request == admitted
    assert claim.job.request_fingerprint != claim.job.execution_request_fingerprint

    with pytest.raises(JobStateError, match="^idempotency.conflict$"):
        reopened.submit_request(
            "job-two",
            admitted,
            execution_request=admitted,
            caller_id="caller-a",
            idempotency_key="key-a",
            at=LATER,
        )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("request_fingerprint", "0" * 64),
        ("execution_request_fingerprint", "0" * 64),
        ("execution_request_json", "{}"),
    ],
)
def test_persisted_request_json_and_fingerprints_cannot_diverge(
    tmp_path: Path, column: str, value: str
) -> None:
    database = tmp_path / "jobs.sqlite3"
    repository = JobRepository(database)
    repository.submit_request(
        "job-one",
        _request(),
        caller_id="caller-a",
        idempotency_key="key-a",
        at=NOW,
    )
    repository.close()
    connection = sqlite3.connect(database)
    connection.execute(f"UPDATE jobs SET {column}=?", (value,))
    connection.commit()
    connection.close()

    reopened = JobRepository(database)
    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        reopened.get("job-one")


def test_cancel_and_completed_terminalization_are_atomically_ordered(
    tmp_path: Path,
) -> None:
    result = _result(JobStatus.COMPLETED)
    job_id = result.manifest.run_id
    first = JobRepository(tmp_path / "cancel-first.sqlite3")
    first.submit_request(
        job_id,
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=RESULT_WINDOW_START,
    )
    claim = first.claim_next(
        "worker", at=RESULT_WINDOW_START, lease_deadline="2026-08-25T00:10:00Z"
    )
    assert claim is not None
    second = JobRepository(tmp_path / "cancel-first.sqlite3")
    second.cancel(job_id, at=RESULT_WINDOW_END)

    with pytest.raises(JobStateError, match="^job.cancel_requested$"):
        first.transition(
            job_id,
            JobStatus.COMPLETED,
            at=RESULT_WINDOW_END,
            result=result,
            claim_token=claim.token,
        )

    first = JobRepository(tmp_path / "complete-first.sqlite3")
    first.submit_request(
        job_id,
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=RESULT_WINDOW_START,
    )
    claim = first.claim_next(
        "worker", at=RESULT_WINDOW_START, lease_deadline="2026-08-25T00:10:00Z"
    )
    assert claim is not None
    second = JobRepository(tmp_path / "complete-first.sqlite3")
    completed = first.transition(
        job_id,
        JobStatus.COMPLETED,
        at=RESULT_WINDOW_END,
        result=result,
        claim_token=claim.token,
    )
    cancelled = second.cancel(job_id, at=RESULT_WINDOW_END)

    assert cancelled == completed
    assert cancelled.cancel_requested_at is None


@pytest.mark.parametrize(
    "status",
    [JobStatus.FAILED, JobStatus.PARTIAL, JobStatus.REJECTED],
)
def test_cancel_first_rejects_every_uncancelled_terminal_result(
    tmp_path: Path, status: JobStatus
) -> None:
    result = _result(status)
    job_id = result.manifest.run_id
    database = tmp_path / f"cancel-first-{status.value}.sqlite3"
    worker_repository = JobRepository(database)
    worker_repository.submit_request(
        job_id,
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=RESULT_WINDOW_START,
    )
    claim = worker_repository.claim_next(
        "worker", at=RESULT_WINDOW_START, lease_deadline="2026-08-25T00:10:00Z"
    )
    assert claim is not None
    cancellation_repository = JobRepository(database)
    cancellation_repository.cancel(job_id, at=RESULT_WINDOW_END)
    cancellation_repository.close()

    with pytest.raises(JobStateError, match="^job.cancel_requested$"):
        worker_repository.transition(
            job_id,
            status,
            at=RESULT_WINDOW_END,
            result=result,
            failure_code=_terminal_facts(status)[1],
            claim_token=claim.token,
        )

    assert worker_repository.get(job_id).status is JobStatus.RUNNING


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
def test_claim_before_submission_is_rejected_without_mutation(
    tmp_path: Path, persistent: bool
) -> None:
    database = tmp_path / "claim-before-submission.sqlite3"
    repository = JobRepository(database if persistent else None)
    submitted = repository.submit_request(
        "job-one",
        _request(),
        caller_id="caller",
        idempotency_key="key",
        at=NOW,
    )

    with pytest.raises(JobStateError) as error:
        repository.claim_next(
            "worker",
            at="2026-08-25T19:00:00Z",
            lease_deadline="2026-08-25T19:01:00Z",
        )

    assert error.value.code == "job.time_invalid"
    assert repository.get(submitted.job_id) == submitted
    events = repository.events(submitted.job_id)
    assert len(events) == 1
    assert events[0].status is JobStatus.SUBMITTED
    unclaimed = repository.get(submitted.job_id)
    assert (
        unclaimed.started_at,
        unclaimed.worker_id,
        unclaimed.claim_token,
        unclaimed.claimed_at,
        unclaimed.lease_deadline,
    ) == (None, None, None, None, None)
    if persistent:
        connection = sqlite3.connect(database)
        row = connection.execute(
            "SELECT status,started_at,worker_id,claim_token,claimed_at,lease_deadline "
            "FROM jobs WHERE job_id='job-one'"
        ).fetchone()
        event_count = connection.execute(
            "SELECT COUNT(*) FROM job_events WHERE job_id='job-one'"
        ).fetchone()[0]
        connection.close()
        assert row == ("submitted", None, None, None, None, None)
        assert event_count == 1
    repository.close()


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
@pytest.mark.parametrize(
    ("claimed_at", "lease_deadline", "code"),
    [
        ("not-a-time", "2026-08-25T20:00:02Z", "job.time_invalid"),
        (LATER, "not-a-time", "job.time_invalid"),
        (LATER, LATER, "job.lease_invalid"),
        (LATER, NOW, "job.lease_invalid"),
    ],
    ids=("malformed-claim", "malformed-deadline", "equal-deadline", "past-deadline"),
)
def test_invalid_claim_time_boundaries_leave_submitted_job_unchanged(
    tmp_path: Path,
    persistent: bool,
    claimed_at: str,
    lease_deadline: str,
    code: str,
) -> None:
    database = tmp_path / "invalid-claim-boundary.sqlite3"
    repository = JobRepository(database if persistent else None)
    submitted = repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )

    with pytest.raises(JobStateError, match=f"^{code}$"):
        repository.claim_next("worker", at=claimed_at, lease_deadline=lease_deadline)

    assert repository.get(submitted.job_id) == submitted
    assert len(repository.events(submitted.job_id)) == 1
    repository.close()


@pytest.mark.parametrize("persistent", [False, True], ids=("memory", "sqlite"))
@pytest.mark.parametrize(
    ("claimed_at", "lease_deadline"),
    [
        (NOW, LATER),
        (LATER, "2026-08-25T20:00:02Z"),
    ],
    ids=("at-submission", "after-submission"),
)
def test_valid_claim_time_boundaries_match_between_memory_and_sqlite(
    tmp_path: Path, persistent: bool, claimed_at: str, lease_deadline: str
) -> None:
    database = tmp_path / "valid-claim-boundary.sqlite3"
    repository = JobRepository(database if persistent else None)
    repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )

    claim = repository.claim_next(
        "worker", at=claimed_at, lease_deadline=lease_deadline
    )

    assert claim is not None
    assert claim.job.status is JobStatus.RUNNING
    assert claim.job.started_at == claimed_at
    assert claim.job.claimed_at == claimed_at
    assert claim.job.lease_deadline == lease_deadline
    assert claim.job.worker_id == "worker"
    assert claim.job.claim_token == claim.token
    assert len(repository.events(claim.job.job_id)) == 2
    repository.close()


def test_invalid_sqlite_claim_releases_transaction_for_another_connection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "multiple-connections.sqlite3"
    first = JobRepository(database)
    submitted = first.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    second = JobRepository(database)

    with pytest.raises(JobStateError, match="^job.time_invalid$"):
        first.claim_next(
            "worker-invalid",
            at="2026-08-25T19:00:00Z",
            lease_deadline="2026-08-25T19:01:00Z",
        )

    assert second.get(submitted.job_id) == submitted
    claim = second.claim_next("worker-valid", at=NOW, lease_deadline=LATER)
    assert claim is not None
    assert claim.job.status is JobStatus.RUNNING
    assert claim.job.worker_id == "worker-valid"
    assert len(second.events(submitted.job_id)) == 2
    first.close()
    second.close()


def test_sqlite_claim_readback_error_rolls_back_update_and_event(
    tmp_path: Path,
) -> None:
    database = tmp_path / "claim-readback.sqlite3"
    repository = JobRepository(database)
    submitted = repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TRIGGER corrupt_claim AFTER UPDATE OF status ON jobs "
        "WHEN NEW.status='running' BEGIN "
        "UPDATE jobs SET started_at='not-a-time' WHERE job_id=NEW.job_id; END"
    )
    connection.commit()
    connection.close()

    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        repository.claim_next("worker", at=NOW, lease_deadline=LATER)

    assert repository.get(submitted.job_id) == submitted
    assert len(repository.events(submitted.job_id)) == 1
    connection = sqlite3.connect(database)
    row = connection.execute(
        "SELECT status,started_at,worker_id,claim_token,claimed_at,lease_deadline "
        "FROM jobs WHERE job_id='job-one'"
    ).fetchone()
    event_count = connection.execute(
        "SELECT COUNT(*) FROM job_events WHERE job_id='job-one'"
    ).fetchone()[0]
    connection.close()
    assert row == ("submitted", None, None, None, None, None)
    assert event_count == 1
    repository.close()


@pytest.mark.parametrize(
    "trigger",
    [
        (
            "CREATE TRIGGER replace_claim_token AFTER UPDATE OF status ON jobs "
            "WHEN NEW.status='running' BEGIN UPDATE jobs SET "
            "claim_token='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "
            "WHERE job_id=NEW.job_id; END"
        ),
        (
            "CREATE TRIGGER replace_worker AFTER UPDATE OF status ON jobs "
            "WHEN NEW.status='running' BEGIN UPDATE jobs SET worker_id='other-worker' "
            "WHERE job_id=NEW.job_id; END"
        ),
        (
            "CREATE TRIGGER replace_claimed_at AFTER UPDATE OF status ON jobs "
            "WHEN NEW.status='running' BEGIN UPDATE jobs SET "
            "claimed_at='2026-08-25T20:00:01Z' WHERE job_id=NEW.job_id; END"
        ),
        (
            "CREATE TRIGGER replace_lease AFTER UPDATE OF status ON jobs "
            "WHEN NEW.status='running' BEGIN UPDATE jobs SET "
            "lease_deadline='2026-08-25T20:02:00Z' WHERE job_id=NEW.job_id; END"
        ),
        (
            "CREATE TRIGGER replace_running_event AFTER INSERT ON job_events "
            "WHEN NEW.sequence=2 BEGIN UPDATE jobs SET "
            "started_at='2026-08-25T20:00:01Z' WHERE job_id=NEW.job_id; "
            "UPDATE job_events SET at='2026-08-25T20:00:01Z' "
            "WHERE job_id=NEW.job_id AND sequence=NEW.sequence; END"
        ),
    ],
    ids=("claim-token", "worker", "claimed-at", "lease-deadline", "event"),
)
def test_sqlite_claim_valid_but_different_readback_rolls_back_and_releases_lock(
    tmp_path: Path, trigger: str
) -> None:
    database = tmp_path / "claim-equality.sqlite3"
    repository = JobRepository(database)
    submitted = repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    second = JobRepository(database)
    connection = sqlite3.connect(database)
    connection.execute(trigger)
    connection.commit()
    connection.close()

    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        repository.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")

    assert repository.get(submitted.job_id) == submitted
    assert second.get(submitted.job_id) == submitted
    assert second.events(submitted.job_id) == repository.events(submitted.job_id)
    connection = sqlite3.connect(database, timeout=0)
    connection.execute("BEGIN IMMEDIATE")
    row = connection.execute(
        "SELECT status,started_at,worker_id,claim_token,claimed_at,lease_deadline "
        "FROM jobs WHERE job_id='job-one'"
    ).fetchone()
    events = connection.execute(
        "SELECT sequence,previous_status,status,at FROM job_events "
        "WHERE job_id='job-one' ORDER BY sequence"
    ).fetchall()
    connection.execute(
        "DROP TRIGGER "
        + connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchone()[0]
    )
    connection.commit()
    connection.close()
    assert row == ("submitted", None, None, None, None, None)
    assert events == [(1, None, "submitted", NOW)]

    claim = second.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    assert claim is not None
    durable = repository.get(submitted.job_id)
    assert claim.token == claim.job.claim_token == durable.claim_token
    repository.close()
    second.close()


def test_sqlite_submit_request_readback_error_rolls_back_job_and_event(
    tmp_path: Path,
) -> None:
    database = tmp_path / "submit-request-readback.sqlite3"
    repository = JobRepository(database)
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TRIGGER corrupt_submission AFTER INSERT ON jobs BEGIN "
        "UPDATE jobs SET request_fingerprint='invalid' WHERE job_id=NEW.job_id; END"
    )
    connection.commit()
    connection.close()

    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        repository.submit_request(
            "job-one",
            _request(),
            caller_id="caller",
            idempotency_key="key",
            at=NOW,
        )

    connection = sqlite3.connect(database, timeout=0)
    connection.execute("BEGIN IMMEDIATE")
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM job_events").fetchone()[0] == 0
    connection.rollback()
    connection.close()
    repository.close()


def test_sqlite_legacy_submit_readback_error_rolls_back_job_and_event(
    tmp_path: Path,
) -> None:
    database = tmp_path / "submit-readback.sqlite3"
    repository = JobRepository(database)
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TRIGGER corrupt_submission AFTER INSERT ON jobs BEGIN "
        "UPDATE jobs SET submitted_at='not-a-time' WHERE job_id=NEW.job_id; END"
    )
    connection.commit()
    connection.close()

    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        repository.submit("job-one", at=NOW)

    connection = sqlite3.connect(database, timeout=0)
    connection.execute("BEGIN IMMEDIATE")
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM job_events").fetchone()[0] == 0
    connection.rollback()
    connection.close()
    repository.close()


@pytest.mark.parametrize(
    "trigger",
    [
        (
            "CREATE TRIGGER corrupt_terminal_job AFTER UPDATE OF status ON jobs "
            "WHEN NEW.status='failed' BEGIN "
            "UPDATE jobs SET finished_at='not-a-time' WHERE job_id=NEW.job_id; END"
        ),
        (
            "CREATE TRIGGER corrupt_terminal_event AFTER INSERT ON job_events "
            "WHEN NEW.sequence=3 BEGIN "
            "UPDATE job_events SET at='not-a-time' "
            "WHERE job_id=NEW.job_id AND sequence=NEW.sequence; END"
        ),
    ],
    ids=("job", "event"),
)
def test_sqlite_terminal_readback_error_restores_running_claim_and_events(
    tmp_path: Path, trigger: str
) -> None:
    database = tmp_path / "terminal-readback.sqlite3"
    repository = JobRepository(database)
    repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    claim = repository.claim_next(
        "worker", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None
    running_events = repository.events(claim.job.job_id)
    connection = sqlite3.connect(database)
    connection.execute(trigger)
    connection.commit()
    connection.close()

    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        repository.transition(
            claim.job.job_id,
            JobStatus.FAILED,
            at="2026-08-25T20:00:02Z",
            failure_code="service.restart_interrupted",
            claim_token=claim.token,
        )

    assert repository.get(claim.job.job_id) == claim.job
    assert repository.events(claim.job.job_id) == running_events
    connection = sqlite3.connect(database, timeout=0)
    connection.execute("BEGIN IMMEDIATE")
    row = connection.execute(
        "SELECT status,finished_at,worker_id,claim_token,claimed_at,lease_deadline "
        "FROM jobs WHERE job_id='job-one'"
    ).fetchone()
    event_count = connection.execute(
        "SELECT COUNT(*) FROM job_events WHERE job_id='job-one'"
    ).fetchone()[0]
    connection.rollback()
    connection.close()
    assert row == (
        "running",
        None,
        claim.job.worker_id,
        claim.token,
        claim.job.claimed_at,
        claim.job.lease_deadline,
    )
    assert event_count == 2
    repository.close()


def test_sqlite_cancel_readback_error_restores_timestamp_and_releases_lock(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cancel-readback.sqlite3"
    repository = JobRepository(database)
    repository.submit_request(
        "job-one", _request(), caller_id="caller", idempotency_key="key", at=NOW
    )
    claim = repository.claim_next(
        "worker", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TRIGGER corrupt_cancellation AFTER UPDATE OF cancel_requested_at ON jobs "
        "BEGIN UPDATE jobs SET cancel_requested_at='2026-08-25T20:00:09Z' "
        "WHERE job_id=NEW.job_id; END"
    )
    connection.commit()
    connection.close()

    with pytest.raises(JobStateError, match="^job.persisted_invalid$"):
        repository.cancel(claim.job.job_id, at="2026-08-25T20:00:02Z")

    assert repository.get(claim.job.job_id) == claim.job
    connection = sqlite3.connect(database, timeout=0)
    connection.execute("BEGIN IMMEDIATE")
    assert connection.execute(
        "SELECT cancel_requested_at FROM jobs WHERE job_id='job-one'"
    ).fetchone() == (None,)
    connection.execute("DROP TRIGGER corrupt_cancellation")
    connection.commit()
    connection.close()

    cancelled = repository.cancel(claim.job.job_id, at="2026-08-25T20:00:02Z")
    repeated = repository.cancel(claim.job.job_id, at="2026-08-25T20:00:03Z")
    terminal = repository.reconcile(at="2026-08-25T20:00:04Z")[0]

    assert cancelled.cancel_requested_at == "2026-08-25T20:00:02Z"
    assert repeated == cancelled
    assert terminal.status is JobStatus.FAILED
    assert repository.cancel(claim.job.job_id, at="2026-08-25T20:00:05Z") == terminal
    repository.close()


def test_claim_order_fencing_cancellation_and_restart_are_fail_closed(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3")
    repository.submit_request(
        "job-b", _request(), caller_id="b", idempotency_key="b", at=NOW
    )
    repository.submit_request(
        "job-a", _request(), caller_id="a", idempotency_key="a", at=NOW
    )
    claim = repository.claim_next(
        "worker-one", at=LATER, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert claim is not None and claim.job.job_id == "job-a"
    with pytest.raises(JobStateError, match="job.claim_stale"):
        repository.transition(
            "job-a",
            JobStatus.FAILED,
            at=LATER,
            failure_code="runtime.workflow_failed",
            claim_token="stale",
        )
    cancelled = repository.cancel("job-a", at=LATER)
    assert repository.cancel("job-a", at="2026-08-25T20:00:02Z") == cancelled
    interrupted = repository.reconcile(at="2026-08-25T20:00:03Z")
    assert interrupted[0].failure_code == "service.restart_interrupted"
    assert repository.get("job-b").status is JobStatus.SUBMITTED


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


def test_terminal_artifact_grants_are_atomic_caller_scoped_and_backfilled(
    tmp_path: Path,
) -> None:
    path = tmp_path / "jobs.sqlite3"
    repository = JobRepository(path)
    repository.submit_request(
        "job-grant",
        _request(),
        caller_id="caller-one",
        idempotency_key="grant",
        at=RESULT_WINDOW_START,
    )
    claim = repository.claim_next(
        "worker", at=RESULT_WINDOW_START, lease_deadline=RESULT_WINDOW_END
    )
    assert claim is not None
    result, failure = _terminal_facts(JobStatus.COMPLETED)
    result = replace(result, manifest=replace(result.manifest, run_id="job-grant"))
    repository.transition(
        "job-grant",
        JobStatus.COMPLETED,
        at=RESULT_WINDOW_END,
        result=result,
        failure_code=failure,
        claim_token=claim.token,
    )
    artifact_id = result.artifacts[0].artifact_id
    assert repository.caller_has_artifact("caller-one", artifact_id)
    assert not repository.caller_has_artifact("caller-two", artifact_id)
    repository.close()

    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM job_artifact_grants")
    reopened = JobRepository(path)
    try:
        assert reopened.caller_has_artifact("caller-one", artifact_id)
        assert not reopened.caller_has_artifact("caller-two", artifact_id)
    finally:
        reopened.close()
