"""Persistent bounded acquisition worker tests."""

# pylint: disable=missing-function-docstring,too-few-public-methods

from __future__ import annotations

from threading import Event, Thread

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.model import ResultStatus
from web_listening.runtime.acquisition_service import AcquisitionService
from web_listening.runtime.jobs import JobRepository, JobStatus
from web_listening.runtime.workflow import terminal_failure_result

NOW = "2026-08-25T20:00:00Z"


def _request() -> Request:
    return Request(
        Scope(
            ("https://example.test/report",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(1, 1000, 10, 1),
    )


class _Runtime:
    def __init__(self, jobs: JobRepository, *, fail_first: bool = False) -> None:
        self.jobs = jobs
        self.fail_first = fail_first
        self.calls: list[str] = []

    def execute_submitted(self, job_id: str, _request: Request, _cancel) -> object:
        self.calls.append(job_id)
        job = self.jobs.get(job_id)
        if self.fail_first and len(self.calls) == 1:
            result = terminal_failure_result(
                _request,
                status=ResultStatus.FAILED,
                run_id=job_id,
                generated_at=NOW,
                code="runtime.workflow_failed",
                message="Runtime execution did not complete.",
            )
            self.jobs.transition(
                job_id,
                JobStatus.FAILED,
                at=NOW,
                result=result,
                failure_code="runtime.workflow_failed",
                claim_token=job.claim_token,
            )
            raise RuntimeError("isolated")
        result = terminal_failure_result(
            _request,
            status=ResultStatus.FAILED,
            run_id=job_id,
            generated_at=NOW,
            code="test.finished",
            message="Test execution finished.",
        )
        return self.jobs.transition(
            job_id,
            JobStatus.FAILED,
            at=NOW,
            result=result,
            failure_code="test.finished",
            claim_token=job.claim_token,
        )

    def cancel(self, job_id: str) -> object:
        return self.jobs.cancel(job_id, at=NOW)


class _ClaimGate:
    def __init__(self, jobs: JobRepository, *, fail: bool = False) -> None:
        self.jobs = jobs
        self.claimed = Event()
        self.release = Event()
        self.fail = fail

    def reconcile(self, *, at: str) -> object:
        return self.jobs.reconcile(at=at)

    def claim_next(self, *args, **kwargs):
        if self.fail:
            raise RuntimeError("repository failed")
        claim = self.jobs.claim_next(*args, **kwargs)
        self.claimed.set()
        self.release.wait(5)
        return claim


def test_workers_reconcile_running_and_execute_submitted_in_stable_order() -> None:
    jobs = JobRepository()
    jobs.submit_request("job-b", _request(), caller_id="b", idempotency_key="b", at=NOW)
    jobs.submit_request("job-a", _request(), caller_id="a", idempotency_key="a", at=NOW)
    running = jobs.claim_next(
        "dead-worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z"
    )
    assert running is not None and running.job.job_id == "job-a"
    runtime = _Runtime(jobs)

    workers = AcquisitionService(  # type: ignore[arg-type]
        runtime, jobs, concurrency=1, clock=lambda: NOW
    )
    workers.run_available()
    workers.close()

    assert jobs.get("job-a").failure_code == "service.restart_interrupted"
    assert runtime.calls == ["job-b"]


def test_one_worker_exception_does_not_stop_later_jobs() -> None:
    jobs = JobRepository()
    for index in range(3):
        jobs.submit_request(
            f"job-{index}",
            _request(),
            caller_id=f"caller-{index}",
            idempotency_key=f"key-{index}",
            at=NOW,
        )
    runtime = _Runtime(jobs, fail_first=True)
    workers = AcquisitionService(  # type: ignore[arg-type]
        runtime, jobs, concurrency=1, clock=lambda: NOW
    )

    workers.run_available()
    workers.close()

    assert runtime.calls == ["job-0", "job-1", "job-2"]
    assert all(
        jobs.get(f"job-{index}").status is JobStatus.FAILED for index in range(3)
    )


@pytest.mark.parametrize("invalid", [0, 33, True, False, 1.0, 1.5, "2", None])
def test_worker_concurrency_requires_builtin_int_in_range(invalid: object) -> None:
    jobs = JobRepository()
    runtime = _Runtime(jobs)

    with pytest.raises(ValueError, match="^worker.concurrency_invalid$"):
        AcquisitionService(  # type: ignore[arg-type]
            runtime, jobs, concurrency=invalid, clock=lambda: NOW
        )


def test_wake_during_final_empty_claim_is_not_lost() -> None:
    jobs = JobRepository()
    gate = _ClaimGate(jobs)
    runtime = _Runtime(jobs)
    workers = AcquisitionService(  # type: ignore[arg-type]
        runtime, gate, concurrency=1, clock=lambda: NOW
    )
    workers.wake()
    assert gate.claimed.wait(5)
    jobs.submit_request(
        "job-late", _request(), caller_id="caller", idempotency_key="late", at=NOW
    )
    workers.wake()
    gate.release.set()
    workers.run_available()
    workers.close()
    assert runtime.calls == ["job-late"]


def test_close_cancels_claim_between_repository_claim_and_registration() -> None:
    jobs = JobRepository()
    jobs.submit_request(
        "job-race", _request(), caller_id="caller", idempotency_key="race", at=NOW
    )
    gate = _ClaimGate(jobs)
    runtime = _Runtime(jobs)
    workers = AcquisitionService(  # type: ignore[arg-type]
        runtime, gate, concurrency=1, clock=lambda: NOW
    )
    workers.wake()
    assert gate.claimed.wait(5)
    closer = Thread(target=workers.close)
    closer.start()
    gate.release.set()
    closer.join(5)
    assert not closer.is_alive()
    assert not runtime.calls
    assert jobs.get("job-race").cancel_requested_at == NOW


def test_claim_failure_marks_worker_unhealthy() -> None:
    jobs = JobRepository()
    gate = _ClaimGate(jobs, fail=True)
    workers = AcquisitionService(  # type: ignore[arg-type]
        _Runtime(jobs), gate, concurrency=1, clock=lambda: NOW
    )
    workers.run_available()
    assert not workers.healthy
    workers.close()
