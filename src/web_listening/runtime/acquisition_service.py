"""Bounded single-host workers for persisted asynchronous acquisitions."""

# pylint: disable=too-many-arguments,too-many-instance-attributes
# pylint: disable=unidiomatic-typecheck,too-many-branches,too-many-statements

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta

from web_listening.result.errors import parse_utc_time
from web_listening.runtime.jobs import JobRepository
from web_listening.runtime.service import RuntimeService


class AcquisitionService:
    """Claim persisted Jobs with a bounded, failure-isolated in-process pool."""

    def __init__(
        self,
        runtime: RuntimeService,
        jobs: JobRepository,
        *,
        concurrency: int = 2,
        clock: Callable[[], str],
        worker_id: str | None = None,
        lease_seconds: int = 900,
        poll_interval_seconds: float | None = None,
    ) -> None:
        if type(concurrency) is not int or not 1 <= concurrency <= 32:
            raise ValueError("worker.concurrency_invalid")
        if isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValueError("worker.lease_invalid")
        if poll_interval_seconds is not None and (
            isinstance(poll_interval_seconds, bool) or poll_interval_seconds <= 0
        ):
            raise ValueError("worker.poll_interval_invalid")
        self._runtime = runtime
        self._jobs = jobs
        self._concurrency = concurrency
        self._clock = clock
        self._worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
        self._lease_seconds = lease_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._poll_event = threading.Event()
        self._executor = ThreadPoolExecutor(
            max_workers=concurrency, thread_name_prefix="web-listening-acquisition"
        )
        self._lock = threading.Lock()
        self._futures: set[Future[None]] = set()
        self._active_job_ids: set[str] = set()
        self._active_batch_ids: set[str] = set()
        self._worker_count = 0
        self._wake_generation = 0
        self._claim_failed = False
        self._closed = False
        self._jobs.reconcile(at=self._clock())
        if hasattr(self._jobs, "reconcile_batches"):
            self._jobs.reconcile_batches()

    def wake(self) -> None:
        """Use available capacity to process durable submitted work."""
        with self._lock:
            if self._closed:
                raise RuntimeError("worker.closed")
            self._wake_generation += 1
            self._poll_event.set()
            self._futures = {future for future in self._futures if not future.done()}
            for _unused in range(self._concurrency - self._worker_count):
                self._worker_count += 1
                future = self._executor.submit(self._worker)
                self._futures.add(future)

    def run_available(self) -> None:
        """Process all currently submitted work and wait for worker quiescence."""
        self.wake()
        while True:
            with self._lock:
                futures = tuple(self._futures)
            if not futures:
                return
            for future in futures:
                future.result()
            with self._lock:
                self._futures.difference_update(futures)
                if not self._futures:
                    return

    def close(self) -> None:
        """Stop accepting wakeups and wait for active invocations to finish."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._poll_event.set()
            active = tuple(self._active_job_ids)
            active_batches = tuple(self._active_batch_ids)
        for job_id in active:
            try:
                self._runtime.cancel(job_id)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        for batch_id in active_batches:
            try:
                self._runtime.cancel_batch(batch_id)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        self._executor.shutdown(wait=True)

    @property
    def healthy(self) -> bool:
        """Report whether the worker still accepts durable work."""
        with self._lock:
            return (
                not self._closed
                and not self._claim_failed
                and not any(
                    future.done() and future.exception() is not None
                    for future in self._futures
                )
            )

    def _worker(self) -> None:
        while True:
            with self._lock:
                if self._closed:
                    self._worker_count -= 1
                    return
                observed_generation = self._wake_generation
            now = self._clock()
            deadline = (
                parse_utc_time(now) + timedelta(seconds=self._lease_seconds)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                claim = self._jobs.claim_next(
                    self._worker_id, at=now, lease_deadline=deadline
                )
            except Exception:  # pylint: disable=broad-exception-caught
                with self._lock:
                    self._claim_failed = True
                    self._worker_count -= 1
                return
            if claim is None:
                batch_claim = (
                    self._jobs.claim_next_batch(at=now)
                    if hasattr(self._jobs, "claim_next_batch")
                    else None
                )
                if batch_claim is not None:
                    with self._lock:
                        self._active_batch_ids.add(batch_claim.batch.batch_id)
                    try:
                        self._runtime.execute_submitted_batch(
                            batch_claim.batch.batch_id
                        )
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass
                    finally:
                        with self._lock:
                            self._active_batch_ids.discard(batch_claim.batch.batch_id)
                    continue
                with self._lock:
                    if self._wake_generation != observed_generation:
                        continue
                    poll_interval = self._poll_interval_seconds
                    if poll_interval is not None:
                        self._poll_event.clear()
                if poll_interval is not None:
                    self._poll_event.wait(poll_interval)
                    continue
                with self._lock:
                    self._worker_count -= 1
                    return
            with self._lock:
                if self._closed:
                    cancel_claim = True
                    self._worker_count -= 1
                else:
                    cancel_claim = False
                    self._active_job_ids.add(claim.job.job_id)
            if cancel_claim:
                try:
                    self._runtime.cancel(claim.job.job_id)
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
                return
            try:
                self._runtime.execute_submitted(
                    claim.job.job_id, claim.request, lambda: False
                )
            except Exception:  # pylint: disable=broad-exception-caught
                continue
            finally:
                with self._lock:
                    self._active_job_ids.discard(claim.job.job_id)


__all__ = ["AcquisitionService"]
