"""Bounded single-host workers for persisted asynchronous acquisitions."""

# pylint: disable=too-many-arguments,too-many-instance-attributes
# pylint: disable=unidiomatic-typecheck

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
    ) -> None:
        if type(concurrency) is not int or not 1 <= concurrency <= 32:
            raise ValueError("worker.concurrency_invalid")
        if isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValueError("worker.lease_invalid")
        self._runtime = runtime
        self._jobs = jobs
        self._concurrency = concurrency
        self._clock = clock
        self._worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
        self._lease_seconds = lease_seconds
        self._executor = ThreadPoolExecutor(
            max_workers=concurrency, thread_name_prefix="web-listening-acquisition"
        )
        self._lock = threading.Lock()
        self._futures: set[Future[None]] = set()
        self._closed = False
        self._jobs.reconcile(at=self._clock())

    def wake(self) -> None:
        """Use available capacity to process durable submitted work."""
        with self._lock:
            if self._closed:
                raise RuntimeError("worker.closed")
            self._futures = {future for future in self._futures if not future.done()}
            for _unused in range(self._concurrency - len(self._futures)):
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
        self._executor.shutdown(wait=True)

    def _worker(self) -> None:
        while True:
            now = self._clock()
            deadline = (
                parse_utc_time(now) + timedelta(seconds=self._lease_seconds)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                claim = self._jobs.claim_next(
                    self._worker_id, at=now, lease_deadline=deadline
                )
            except Exception:  # pylint: disable=broad-exception-caught
                return
            if claim is None:
                return
            try:
                self._runtime.execute_submitted(
                    claim.job.job_id, claim.request, lambda: False
                )
            except Exception:  # pylint: disable=broad-exception-caught
                continue


__all__ = ["AcquisitionService"]
