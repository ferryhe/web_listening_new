"""Explicit in-memory or SQLite state for minimal Runtime Jobs."""

# pylint: disable=duplicate-code,too-many-arguments,too-many-boolean-expressions
# pylint: disable=too-many-lines
# pylint: disable=too-many-instance-attributes,too-many-locals
# pylint: disable=unidiomatic-typecheck,too-many-public-methods

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from web_listening.artifact.lineage import validate_artifact_id
from web_listening.request.model import Request
from web_listening.request.site_batch import (
    SiteBatchRequest,
    site_batch_request_from_json,
    validate_site_batch_request,
)
from web_listening.request.url_fetch import UrlFetchRequest, url_fetch_request_from_json
from web_listening.request.validate import request_from_mapping, validate_request
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    ensure_safe_text,
    parse_utc_time,
    validate_text,
    validate_utc_time,
)
from web_listening.result.model import Result
from web_listening.result.site_batch import SiteBatchResult
from web_listening.result.url_fetch import NavigationDiscovery, UrlFetchResult
from web_listening.runtime.site_batch import (
    site_batch_child_result_from_mapping,
    site_batch_result_from_mapping,
)
from web_listening.site_skill.model import SiteSkill, SiteSkillError
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
)


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
_SECRET_QUERY_KEYS = frozenset(
    {
        "auth",
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "token",
        "accesstoken",
        "refreshtoken",
        "apikey",
        "password",
        "passwd",
        "secret",
        "clientsecret",
        "privatekey",
        "credential",
        "sessionid",
    }
)


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
    request_json: str | None = None
    request_fingerprint: str | None = None
    caller_id: str | None = None
    idempotency_key: str | None = None
    cancel_requested_at: str | None = None
    worker_id: str | None = None
    claim_token: str | None = None
    claimed_at: str | None = None
    lease_deadline: str | None = None
    execution_request_json: str | None = None
    execution_request_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class JobClaim:
    """Opaque authority to execute and update one claimed Job."""

    job: Job
    request: Request
    token: str


@dataclass(frozen=True, slots=True)
class JobEvent:
    """One ordered Job state transition for replay and audit."""

    sequence: int
    job_id: str
    previous_status: JobStatus | None
    status: JobStatus
    at: str


@dataclass(frozen=True, slots=True)
class BatchChild:
    """One stable ordered child checkpoint exposed with its parent."""

    site_key: str
    order: int
    status: str


@dataclass(frozen=True, slots=True)
class SiteBatch:
    """One caller-owned durable multi-site execution snapshot."""

    batch_id: str
    status: JobStatus
    submitted_at: str
    children: tuple[BatchChild, ...]
    started_at: str | None = None
    finished_at: str | None = None
    cancel_requested_at: str | None = None
    result: SiteBatchResult | None = None
    failure_code: str | None = None
    caller_id: str | None = None
    idempotency_key: str | None = None
    request_json: str | None = None
    request_fingerprint: str | None = None
    execution_request_json: str | None = None


@dataclass(frozen=True, slots=True)
class SiteBatchClaim:
    """Claimed batch and its revalidated persisted request."""

    batch: SiteBatch
    request: SiteBatchRequest


@dataclass(frozen=True, slots=True)
class UrlFetchJob:
    """One caller-owned durable Smart URL Fetch execution."""

    job_id: str
    status: JobStatus
    submitted_at: str
    started_at: str | None = None
    finished_at: str | None = None
    cancel_requested_at: str | None = None
    result: UrlFetchResult | None = None
    failure_code: str | None = None
    caller_id: str | None = None
    idempotency_key: str | None = None
    request_json: str | None = None
    request_fingerprint: str | None = None
    execution_request_json: str | None = None


@dataclass(frozen=True, slots=True)
class UrlFetchClaim:
    """Claimed URL fetch and its revalidated persisted request."""

    job: UrlFetchJob
    request: UrlFetchRequest


class JobRepository:
    """Own legal Job state transitions and immutable readback only."""

    def __init__(self, database_path: str | os.PathLike[str] | None = None) -> None:
        self._jobs: dict[str, Job] = {}
        self._events: dict[str, list[JobEvent]] = {}
        self._artifact_grants: set[tuple[str, str]] = set()
        self._batches: dict[str, SiteBatch] = {}
        self._batch_results: dict[str, tuple[object, ...]] = {}
        self._url_fetches: dict[str, UrlFetchJob] = {}
        self._url_fetch_results: dict[str, tuple[Result, ...]] = {}
        self._url_fetch_discovery: dict[str, tuple[NavigationDiscovery, ...]] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._connection: sqlite3.Connection | None = None
        if database_path is None:
            return
        path = Path(os.path.abspath(os.fspath(database_path)))
        _reject_symlink_chain(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_chain(path)
        _require_directory(path.parent)
        _require_regular_file(path, missing_ok=True)
        connection = sqlite3.connect(
            path, isolation_level=None, check_same_thread=False
        )
        connection.row_factory = sqlite3.Row
        try:
            _reject_symlink_chain(path)
            _require_regular_file(path, missing_ok=False)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            _create_schema(connection)
            _backfill_artifact_grants(connection)
        except BaseException:
            connection.close()
            raise
        self._connection = connection

    def submit_batch(
        self,
        batch_id: str,
        request: SiteBatchRequest,
        *,
        caller_id: str,
        idempotency_key: str,
        at: str,
        execution_request: SiteBatchRequest | None = None,
    ) -> SiteBatch:
        """Atomically persist a strict batch parent and ordered children."""
        identifier = _validate_job_id(batch_id)
        timestamp = _validate_time(at)
        caller = _validate_boundary_text(caller_id, "caller.invalid", 256)
        key = _validate_idempotency_key(idempotency_key)
        canonical = validate_site_batch_request(request)
        request_json = canonical.canonical_json_bytes().decode("utf-8")
        fingerprint = canonical.request_sha256
        execution = validate_site_batch_request(execution_request or canonical)
        execution_json = execution.canonical_json_bytes().decode("utf-8")
        children = tuple(
            BatchChild(site_key, order, "submitted")
            for order, site_key in enumerate(canonical.site_keys, start=1)
        )
        batch = SiteBatch(
            identifier,
            JobStatus.SUBMITTED,
            timestamp,
            children,
            caller_id=caller,
            idempotency_key=key,
            request_json=request_json,
            request_fingerprint=fingerprint,
            execution_request_json=execution_json,
        )
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                existing = next(
                    (
                        item
                        for item in self._batches.values()
                        if item.caller_id == caller and item.idempotency_key == key
                    ),
                    None,
                )
                if existing is not None:
                    if existing.request_fingerprint != fingerprint:
                        raise JobStateError("idempotency.conflict")
                    return existing
                self._batches[identifier] = batch
                return batch
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT batch_id,request_fingerprint FROM site_batches "
                    "WHERE caller_id=? AND idempotency_key=?",
                    (caller, key),
                ).fetchone()
                if row is not None:
                    if row["request_fingerprint"] != fingerprint:
                        raise JobStateError("idempotency.conflict")
                    result = self._batch_from_database(row["batch_id"])
                    self._connection.execute("COMMIT")
                    return result
                self._connection.execute(
                    "INSERT INTO site_batches "
                    "(batch_id,status,submitted_at,caller_id,idempotency_key,"
                    "request_json,request_fingerprint,execution_request_json) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        "submitted",
                        timestamp,
                        caller,
                        key,
                        request_json,
                        fingerprint,
                        execution_json,
                    ),
                )
                self._connection.executemany(
                    "INSERT INTO site_batch_children "
                    "(batch_id,child_order,site_key,status) VALUES (?,?,?,?)",
                    (
                        (identifier, item.order, item.site_key, item.status)
                        for item in children
                    ),
                )
                result = self._batch_from_database(identifier)
                self._connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback()
                raise

    def get_batch(self, batch_id: str) -> SiteBatch:
        """Read one batch snapshot and its ordered children."""
        identifier = _validate_job_id(batch_id)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                try:
                    return self._batches[identifier]
                except KeyError as exc:
                    raise JobStateError("batch.not_found") from exc
            return self._batch_from_database(identifier)

    def claim_next_batch(self, *, at: str) -> SiteBatchClaim | None:
        """Claim the oldest queued batch; checkpoints make claims resumable."""
        timestamp = _validate_time(at)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                queued = sorted(
                    (
                        item
                        for item in self._batches.values()
                        if item.status is JobStatus.SUBMITTED
                    ),
                    key=lambda item: (item.submitted_at, item.batch_id),
                )
                if not queued:
                    return None
                batch = replace(
                    queued[0],
                    status=JobStatus.RUNNING,
                    started_at=queued[0].started_at or timestamp,
                )
                self._batches[batch.batch_id] = batch
            else:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    row = self._connection.execute(
                        "SELECT batch_id FROM site_batches WHERE status='submitted' "
                        "ORDER BY submitted_at,batch_id LIMIT 1"
                    ).fetchone()
                    if row is None:
                        self._connection.execute("COMMIT")
                        return None
                    updated = self._connection.execute(
                        "UPDATE site_batches SET status='running',"
                        "started_at=COALESCE(started_at,?) "
                        "WHERE batch_id=? AND status='submitted'",
                        (timestamp, row["batch_id"]),
                    )
                    if updated.rowcount != 1:
                        raise JobStateError("batch.claim_failed")
                    batch = self._batch_from_database(row["batch_id"])
                    if batch.status is not JobStatus.RUNNING:
                        raise JobStateError("batch.claim_failed")
                    assert batch.execution_request_json is not None
                    try:
                        request = site_batch_request_from_json(
                            batch.execution_request_json
                        )
                    except (TypeError, ValueError) as exc:
                        raise JobStateError("batch.persisted_invalid") from exc
                    self._connection.execute("COMMIT")
                    return SiteBatchClaim(batch, request)
                except BaseException:
                    self._rollback()
                    raise
            assert batch.execution_request_json is not None
            try:
                request = site_batch_request_from_json(batch.execution_request_json)
            except (TypeError, ValueError) as exc:
                raise JobStateError("batch.persisted_invalid") from exc
            return SiteBatchClaim(batch, request)

    def claimed_batch_request(self, batch_id: str) -> SiteBatchRequest:
        """Revalidate the request of one already claimed batch."""
        batch = self.get_batch(batch_id)
        if batch.execution_request_json is None:
            raise JobStateError("batch.persisted_invalid")
        try:
            return site_batch_request_from_json(batch.execution_request_json)
        except (TypeError, ValueError) as exc:
            raise JobStateError("batch.persisted_invalid") from exc

    def checkpoint_batch(self, batch_id: str, order: int, result: object) -> SiteBatch:
        """Durably commit all completed child evidence before later I/O."""
        identifier = _validate_job_id(batch_id)
        payload = json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            if self._connection is None:
                current = self.get_batch(identifier)
                existing = self._batch_results.get(identifier, ())
                if (
                    current.status is not JobStatus.RUNNING
                    or order != len(existing) + 1
                    or order > len(current.children)
                ):
                    raise JobStateError("batch.checkpoint_order_invalid")
                children = tuple(
                    replace(
                        item,
                        status=(
                            result.status.value if item.order == order else item.status
                        ),
                    )
                    for item in current.children
                )
                updated = replace(current, children=children)
                self._batches[identifier] = updated
                self._batch_results[identifier] = (*existing, result)
                return updated
            try:
                assert self._connection is not None
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._batch_from_database(identifier)
                if current.status is not JobStatus.RUNNING:
                    raise JobStateError("batch.checkpoint_order_invalid")
                request = self.claimed_batch_request(identifier)
                rows = self._connection.execute(
                    "SELECT child_order,result_json FROM site_batch_children "
                    "WHERE batch_id=? ORDER BY child_order",
                    (identifier,),
                ).fetchall()
                prefix = 0
                empty_seen = False
                for row in rows:
                    if row["result_json"] is None:
                        empty_seen = True
                    elif empty_seen:
                        raise JobStateError("batch.checkpoint_order_invalid")
                    else:
                        try:
                            site_batch_child_result_from_mapping(
                                request.phase, json.loads(row["result_json"])
                            )
                        except (TypeError, ValueError) as exc:
                            raise JobStateError(
                                "batch.checkpoint_order_invalid"
                            ) from exc
                        prefix += 1
                if order != prefix + 1 or order > len(rows):
                    raise JobStateError("batch.checkpoint_order_invalid")
                updated = self._connection.execute(
                    "UPDATE site_batch_children SET status=?,result_json=? "
                    "WHERE batch_id=? AND child_order=? AND result_json IS NULL",
                    (result.status.value, payload, identifier, order),
                )
                if updated.rowcount != 1:
                    raise JobStateError("batch.checkpoint_order_invalid")
                persisted = self._batch_from_database(identifier)
                row = self._connection.execute(
                    "SELECT status,result_json FROM site_batch_children "
                    "WHERE batch_id=? AND child_order=?",
                    (identifier, order),
                ).fetchone()
                if (
                    row is None
                    or row["status"] != result.status.value
                    or row["result_json"] != payload
                ):
                    raise JobStateError("batch.checkpoint_order_invalid")
                self._connection.execute("COMMIT")
                return persisted
            except BaseException:
                self._rollback()
                raise

    def batch_checkpoint_results(self, batch_id: str) -> tuple[object, ...]:
        """Return the valid contiguous completed child prefix."""
        batch = self.get_batch(batch_id)
        if self._connection is None:
            return self._batch_results.get(batch.batch_id, ())
        assert self._connection is not None
        rows = self._connection.execute(
            "SELECT result_json FROM site_batch_children WHERE batch_id=? "
            "ORDER BY child_order",
            (batch.batch_id,),
        ).fetchall()
        request = self.claimed_batch_request(batch_id)
        results = []
        for row in rows:
            if row["result_json"] is None:
                break
            results.append(
                site_batch_child_result_from_mapping(
                    request.phase, json.loads(row["result_json"])
                )
            )
        return tuple(results)

    def finish_batch(
        self,
        batch_id: str,
        *,
        at: str,
        failure_code: str | None = None,
        result: SiteBatchResult | None = None,
    ) -> SiteBatch:
        """Terminalize a batch, preserving its latest durable checkpoint."""
        identifier = _validate_job_id(batch_id)
        timestamp = _validate_time(at)
        with self._lock:
            current = self.get_batch(identifier)
            if current.status in _TERMINAL:
                return current
            terminal_result = result or current.result
            status = (
                JobStatus(terminal_result.status.value)
                if terminal_result is not None
                else JobStatus.FAILED
            )
            if self._connection is None:
                updated = replace(
                    current,
                    status=status,
                    finished_at=timestamp,
                    failure_code=failure_code,
                    result=terminal_result,
                )
                self._batches[identifier] = updated
                return updated
            self._connection.execute(
                "UPDATE site_batches SET status=?,finished_at=?,failure_code=?,"
                "result_json=? WHERE batch_id=?",
                (
                    status.value,
                    timestamp,
                    failure_code,
                    (
                        None
                        if terminal_result is None
                        else json.dumps(
                            terminal_result.to_dict(),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    ),
                    identifier,
                ),
            )
            return self._batch_from_database(identifier)

    def cancel_batch(self, batch_id: str, *, at: str) -> SiteBatch:
        """Persist only the first batch cancellation timestamp."""
        timestamp = _validate_time(at)
        with self._lock:
            current = self.get_batch(batch_id)
            if current.status in _TERMINAL or current.cancel_requested_at is not None:
                return current
            if self._connection is None:
                updated = replace(current, cancel_requested_at=timestamp)
                self._batches[current.batch_id] = updated
                return updated
            self._connection.execute(
                "UPDATE site_batches SET cancel_requested_at=? WHERE batch_id=? "
                "AND cancel_requested_at IS NULL AND finished_at IS NULL",
                (timestamp, current.batch_id),
            )
            return self._batch_from_database(current.batch_id)

    def reconcile_batches(self) -> None:
        """Return interrupted batches to the one queue at a safe child boundary."""
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                self._batches = {
                    key: (
                        replace(value, status=JobStatus.SUBMITTED)
                        if value.status is JobStatus.RUNNING
                        else value
                    )
                    for key, value in self._batches.items()
                }
                return
            self._connection.execute(
                "UPDATE site_batches SET status='submitted' WHERE status='running'"
            )

    def _batch_from_database(self, batch_id: str) -> SiteBatch:
        assert self._connection is not None
        row = self._connection.execute(
            "SELECT * FROM site_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        if row is None:
            raise JobStateError("batch.not_found")
        child_rows = self._connection.execute(
            "SELECT site_key,child_order,status FROM site_batch_children "
            "WHERE batch_id=? ORDER BY child_order",
            (batch_id,),
        ).fetchall()
        result = None
        if row["result_json"] is not None:
            try:
                result = site_batch_result_from_mapping(json.loads(row["result_json"]))
            except (TypeError, ValueError) as exc:
                raise JobStateError("batch.persisted_invalid") from exc
        return SiteBatch(
            row["batch_id"],
            JobStatus(row["status"]),
            row["submitted_at"],
            tuple(
                BatchChild(item["site_key"], item["child_order"], item["status"])
                for item in child_rows
            ),
            row["started_at"],
            row["finished_at"],
            row["cancel_requested_at"],
            result,
            row["failure_code"],
            row["caller_id"],
            row["idempotency_key"],
            row["request_json"],
            row["request_fingerprint"],
            row["execution_request_json"],
        )

    def submit_url_fetch(
        self,
        job_id: str,
        request: UrlFetchRequest,
        *,
        caller_id: str,
        idempotency_key: str,
        at: str,
        execution_request: UrlFetchRequest | None = None,
    ) -> UrlFetchJob:
        """Persist canonical URL-fetch intent before any I/O."""
        identifier = _validate_job_id(job_id)
        timestamp = _validate_time(at)
        caller = _validate_boundary_text(caller_id, "caller.invalid", 256)
        key = _validate_idempotency_key(idempotency_key)
        canonical = UrlFetchRequest.from_dict(request.to_dict())
        request_json = canonical.canonical_json_bytes().decode()
        execution_json = (
            (execution_request or canonical).canonical_json_bytes().decode()
        )
        item = UrlFetchJob(
            identifier,
            JobStatus.SUBMITTED,
            timestamp,
            caller_id=caller,
            idempotency_key=key,
            request_json=request_json,
            request_fingerprint=canonical.request_sha256,
            execution_request_json=execution_json,
        )
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                existing = next(
                    (
                        value
                        for value in self._url_fetches.values()
                        if value.caller_id == caller and value.idempotency_key == key
                    ),
                    None,
                )
                if existing:
                    if existing.request_fingerprint != canonical.request_sha256:
                        raise JobStateError("idempotency.conflict")
                    return existing
                self._url_fetches[identifier] = item
                return item
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT job_id,request_fingerprint FROM url_fetches "
                    "WHERE caller_id=? AND idempotency_key=?",
                    (caller, key),
                ).fetchone()
                if row:
                    if row["request_fingerprint"] != canonical.request_sha256:
                        raise JobStateError("idempotency.conflict")
                    result = self._url_fetch_from_database(row["job_id"])
                    self._connection.execute("COMMIT")
                    return result
                self._connection.execute(
                    "INSERT INTO url_fetches "
                    "(job_id,status,submitted_at,caller_id,idempotency_key,"
                    "request_json,request_fingerprint,execution_request_json) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        "submitted",
                        timestamp,
                        caller,
                        key,
                        request_json,
                        canonical.request_sha256,
                        execution_json,
                    ),
                )
                self._connection.execute("COMMIT")
                return self._url_fetch_from_database(identifier)
            except BaseException:
                self._rollback()
                raise

    def get_url_fetch(self, job_id: str) -> UrlFetchJob:
        """Read one URL-fetch snapshot."""
        identifier = _validate_job_id(job_id)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                try:
                    return self._url_fetches[identifier]
                except KeyError as exc:
                    raise JobStateError("url_fetch.not_found") from exc
            return self._url_fetch_from_database(identifier)

    def claim_next_url_fetch(self, *, at: str) -> UrlFetchClaim | None:
        """Atomically claim the oldest submitted URL fetch."""
        timestamp = _validate_time(at)
        with self._lock:
            if self._connection is None:
                queued = sorted(
                    (
                        item
                        for item in self._url_fetches.values()
                        if item.status is JobStatus.SUBMITTED
                    ),
                    key=lambda item: (item.submitted_at, item.job_id),
                )
                if not queued:
                    return None
                job = replace(
                    queued[0],
                    status=JobStatus.RUNNING,
                    started_at=queued[0].started_at or timestamp,
                )
                self._url_fetches[job.job_id] = job
            else:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    row = self._connection.execute(
                        "SELECT job_id FROM url_fetches WHERE status='submitted' "
                        "ORDER BY submitted_at,job_id LIMIT 1"
                    ).fetchone()
                    if row is None:
                        self._connection.execute("COMMIT")
                        return None
                    self._connection.execute(
                        "UPDATE url_fetches SET status='running',"
                        "started_at=COALESCE(started_at,?) "
                        "WHERE job_id=? AND status='submitted'",
                        (timestamp, row["job_id"]),
                    )
                    job = self._url_fetch_from_database(row["job_id"])
                    self._connection.execute("COMMIT")
                except BaseException:
                    self._rollback()
                    raise
            assert job.execution_request_json
            return UrlFetchClaim(
                job, url_fetch_request_from_json(job.execution_request_json)
            )

    def checkpoint_url_fetch(self, job_id: str, order: int, result: Result) -> None:
        """Durably commit one completed hop before later I/O."""
        payload = json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            current = self.get_url_fetch(job_id)
            if current.status is not JobStatus.RUNNING:
                raise JobStateError("url_fetch.checkpoint_order_invalid")
            if self._connection is None:
                prior = self._url_fetch_results.get(job_id, ())
                if order != len(prior) + 1:
                    raise JobStateError("url_fetch.checkpoint_order_invalid")
                self._url_fetch_results[job_id] = (*prior, result)
                if current.caller_id:
                    self._artifact_grants.update(
                        (current.caller_id, artifact.artifact_id)
                        for artifact in result.artifacts
                    )
                return
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                count = self._connection.execute(
                    "SELECT COUNT(*) FROM url_fetch_hops WHERE job_id=?", (job_id,)
                ).fetchone()[0]
                if order != count + 1:
                    raise JobStateError("url_fetch.checkpoint_order_invalid")
                self._connection.execute(
                    "INSERT INTO url_fetch_hops (job_id,hop_order,result_json) VALUES (?,?,?)",
                    (job_id, order, payload),
                )
                self._connection.executemany(
                    "INSERT OR IGNORE INTO url_fetch_artifact_grants "
                    "(job_id,caller_id,artifact_id) VALUES (?,?,?)",
                    (
                        (job_id, current.caller_id, artifact.artifact_id)
                        for artifact in result.artifacts
                    ),
                )
                self._connection.execute("COMMIT")
            except BaseException:
                self._rollback()
                raise

    def url_fetch_checkpoints(self, job_id: str) -> tuple[Result, ...]:
        """Return the ordered completed-hop prefix."""
        self.get_url_fetch(job_id)
        if self._connection is None:
            return self._url_fetch_results.get(job_id, ())
        rows = self._connection.execute(
            "SELECT result_json FROM url_fetch_hops WHERE job_id=? ORDER BY hop_order",
            (job_id,),
        ).fetchall()
        try:
            return tuple(Result.from_dict(json.loads(row[0])) for row in rows)
        except (TypeError, ValueError) as exc:
            raise JobStateError("url_fetch.persisted_invalid") from exc

    def checkpoint_url_fetch_discovery(
        self, job_id: str, order: int, discovery: NavigationDiscovery
    ) -> None:
        """Durably commit navigation evidence before later I/O."""
        payload = json.dumps(discovery.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            current = self.get_url_fetch(job_id)
            if current.status is not JobStatus.RUNNING:
                raise JobStateError("url_fetch.checkpoint_order_invalid")
            if self._connection is None:
                prior = self._url_fetch_discovery.get(job_id, ())
                if order != len(prior) + 1:
                    raise JobStateError("url_fetch.checkpoint_order_invalid")
                self._url_fetch_discovery[job_id] = (*prior, discovery)
                return
            count = self._connection.execute(
                "SELECT COUNT(*) FROM url_fetch_discovery WHERE job_id=?", (job_id,)
            ).fetchone()[0]
            if order != count + 1:
                raise JobStateError("url_fetch.checkpoint_order_invalid")
            self._connection.execute(
                "INSERT INTO url_fetch_discovery "
                "(job_id,discovery_order,evidence_json) VALUES (?,?,?)",
                (job_id, order, payload),
            )

    def url_fetch_discovery_checkpoints(
        self, job_id: str
    ) -> tuple[NavigationDiscovery, ...]:
        """Return ordered persisted navigation evidence."""
        self.get_url_fetch(job_id)
        if self._connection is None:
            return self._url_fetch_discovery.get(job_id, ())
        rows = self._connection.execute(
            "SELECT evidence_json FROM url_fetch_discovery WHERE job_id=? "
            "ORDER BY discovery_order",
            (job_id,),
        ).fetchall()
        try:
            return tuple(
                NavigationDiscovery.from_dict(json.loads(row[0])) for row in rows
            )
        except (TypeError, ValueError) as exc:
            raise JobStateError("url_fetch.persisted_invalid") from exc

    def finish_url_fetch(
        self,
        job_id: str,
        *,
        at: str,
        result: UrlFetchResult | None = None,
        failure_code: str | None = None,
    ) -> UrlFetchJob:
        """Atomically terminalize one claimed URL fetch."""
        current = self.get_url_fetch(job_id)
        if current.status is not JobStatus.RUNNING:
            raise JobStateError("url_fetch.not_claimed")
        status = JobStatus.FAILED if result is None else JobStatus(result.status.value)
        updated = replace(
            current,
            status=status,
            finished_at=_validate_time(at),
            result=result,
            failure_code=failure_code,
        )
        with self._lock:
            if self._connection is None:
                self._url_fetches[job_id] = updated
                return updated
            self._connection.execute(
                "UPDATE url_fetches SET status=?,finished_at=?,"
                "result_json=?,failure_code=? "
                "WHERE job_id=? AND status='running'",
                (
                    status.value,
                    updated.finished_at,
                    (
                        None
                        if result is None
                        else json.dumps(
                            result.to_dict(), sort_keys=True, separators=(",", ":")
                        )
                    ),
                    failure_code,
                    job_id,
                ),
            )
            return self._url_fetch_from_database(job_id)

    def cancel_url_fetch(self, job_id: str, *, at: str) -> UrlFetchJob:
        """Persist a cooperative URL-fetch cancellation request."""
        current = self.get_url_fetch(job_id)
        if current.status in _TERMINAL or current.cancel_requested_at:
            return current
        timestamp = _validate_time(at)
        with self._lock:
            if self._connection is None:
                updated = replace(current, cancel_requested_at=timestamp)
                self._url_fetches[job_id] = updated
                return updated
            self._connection.execute(
                "UPDATE url_fetches SET cancel_requested_at=? "
                "WHERE job_id=? AND finished_at IS NULL",
                (timestamp, job_id),
            )
            return self._url_fetch_from_database(job_id)

    def reconcile_url_fetches(self) -> None:
        """Return interrupted URL fetches to the resumable queue."""
        with self._lock:
            if self._connection is None:
                for key, item in tuple(self._url_fetches.items()):
                    if item.status is JobStatus.RUNNING:
                        self._url_fetches[key] = replace(
                            item, status=JobStatus.SUBMITTED
                        )
            else:
                self._connection.execute(
                    "UPDATE url_fetches SET status='submitted' WHERE status='running'"
                )

    def _url_fetch_from_database(self, job_id: str) -> UrlFetchJob:
        """Revalidate one persisted URL-fetch snapshot."""
        assert self._connection is not None
        row = self._connection.execute(
            "SELECT * FROM url_fetches WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None:
            raise JobStateError("url_fetch.not_found")
        try:
            return UrlFetchJob(
                row["job_id"],
                JobStatus(row["status"]),
                row["submitted_at"],
                row["started_at"],
                row["finished_at"],
                row["cancel_requested_at"],
                (
                    None
                    if row["result_json"] is None
                    else UrlFetchResult.from_dict(json.loads(row["result_json"]))
                ),
                row["failure_code"],
                row["caller_id"],
                row["idempotency_key"],
                row["request_json"],
                row["request_fingerprint"],
                row["execution_request_json"],
            )
        except (TypeError, ValueError) as exc:
            raise JobStateError("url_fetch.persisted_invalid") from exc

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
                persisted = self._validate_persisted_snapshot(job, (event,))
                self._connection.execute("COMMIT")
                return persisted
            except BaseException:
                self._rollback()
                raise

    def submit_request(
        self,
        job_id: str,
        request: Request,
        *,
        caller_id: str,
        idempotency_key: str,
        at: str,
        execution_request: Request | None = None,
    ) -> Job:
        """Atomically persist a canonical Request and its idempotency identity."""
        identifier = _validate_job_id(job_id)
        timestamp = _validate_time(at)
        caller = _validate_boundary_text(caller_id, "caller.invalid", 256)
        key = _validate_idempotency_key(idempotency_key)
        canonical_request, request_json, fingerprint = canonical_request_facts(request)
        canonical_execution, execution_json, execution_fingerprint = (
            canonical_request_facts(
                request if execution_request is None else execution_request
            )
        )
        _validate_execution_authority(
            canonical_request,
            canonical_execution,
            code="request.execution_authority_invalid",
        )
        job = Job(
            identifier,
            JobStatus.SUBMITTED,
            timestamp,
            request_json=request_json,
            request_fingerprint=fingerprint,
            caller_id=caller,
            idempotency_key=key,
            execution_request_json=execution_json,
            execution_request_fingerprint=execution_fingerprint,
        )
        event = JobEvent(1, identifier, None, JobStatus.SUBMITTED, timestamp)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                existing = next(
                    (
                        item
                        for item in self._jobs.values()
                        if item.caller_id == caller and item.idempotency_key == key
                    ),
                    None,
                )
                if existing is not None:
                    if existing.request_fingerprint != fingerprint:
                        raise JobStateError("idempotency.conflict")
                    return existing
                if identifier in self._jobs:
                    raise JobStateError("job.duplicate")
                self._jobs[identifier] = job
                self._events[identifier] = [event]
                return job
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT * FROM jobs WHERE caller_id = ? AND idempotency_key = ?",
                    (caller, key),
                ).fetchone()
                if row is not None:
                    existing = self._require(row["job_id"])
                    if existing.request_fingerprint != fingerprint:
                        raise JobStateError("idempotency.conflict")
                    self._connection.execute("COMMIT")
                    return existing
                if self._job_row(identifier) is not None:
                    raise JobStateError("job.duplicate")
                self._connection.execute(
                    "INSERT INTO jobs (job_id,status,submitted_at,request_json,"
                    "request_fingerprint,caller_id,idempotency_key,execution_request_json,"
                    "execution_request_fingerprint) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        "submitted",
                        timestamp,
                        request_json,
                        fingerprint,
                        caller,
                        key,
                        execution_json,
                        execution_fingerprint,
                    ),
                )
                self._insert_event(event)
                persisted = self._validate_persisted_snapshot(job, (event,))
                self._connection.execute("COMMIT")
                return persisted
            except BaseException:
                self._rollback()
                raise

    def request(self, job_id: str) -> Request:
        """Read and revalidate the canonical Request owned by a submitted Job."""
        job = self.get(job_id)
        if job.request_json is None:
            raise JobStateError("job.request_unavailable")
        try:
            return _request_from_json(job.request_json)
        except (ValueError, TypeError) as exc:
            raise JobStateError("job.persisted_invalid") from exc

    def execution_request(self, job_id: str) -> Request:
        """Read the separately persisted admitted Request used by workers."""
        return self._execution_request(self.get(job_id))

    @staticmethod
    def _execution_request(job: Job) -> Request:
        """Revalidate the admitted Request held by one Job snapshot."""
        if job.execution_request_json is None:
            if job.request_json is None:
                raise JobStateError("job.request_unavailable")
            request_json = job.request_json
        else:
            request_json = job.execution_request_json
        try:
            return _request_from_json(request_json)
        except (ValueError, TypeError) as exc:
            raise JobStateError("job.persisted_invalid") from exc

    def claim_next(
        self, worker_id: str, *, at: str, lease_deadline: str
    ) -> JobClaim | None:
        """Atomically claim the oldest submitted persisted Request."""
        worker = _validate_boundary_text(worker_id, "worker.id_invalid", 128)
        claimed_at = _validate_time(at)
        deadline = _validate_time(lease_deadline)
        if parse_utc_time(deadline) <= parse_utc_time(claimed_at):
            raise JobStateError("job.lease_invalid")
        token = secrets.token_hex(32)
        with self._lock:
            self._ensure_open()
            candidates = (
                sorted(
                    (
                        job
                        for job in self._jobs.values()
                        if job.status is JobStatus.SUBMITTED and job.request_json
                    ),
                    key=lambda item: (item.submitted_at, item.job_id),
                )
                if self._connection is None
                else None
            )
            if candidates is not None:
                if not candidates:
                    return None
                current = candidates[0]
                request = self._execution_request(current)
                updated = replace(
                    _transition_snapshot(
                        current, JobStatus.RUNNING, claimed_at, None, None
                    ),
                    worker_id=worker,
                    claim_token=token,
                    claimed_at=claimed_at,
                    lease_deadline=deadline,
                )
                self._jobs[current.job_id] = updated
                self._events[current.job_id].append(
                    JobEvent(
                        2,
                        current.job_id,
                        JobStatus.SUBMITTED,
                        JobStatus.RUNNING,
                        claimed_at,
                    )
                )
                return JobClaim(updated, request, token)
            try:
                assert self._connection is not None
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT * FROM jobs WHERE status='submitted' AND request_json IS NOT NULL "
                    "ORDER BY submitted_at, job_id LIMIT 1"
                ).fetchone()
                if row is None:
                    self._connection.execute("COMMIT")
                    return None
                current = _job_from_row(row)
                request = self._execution_request(current)
                updated = replace(
                    _transition_snapshot(
                        current, JobStatus.RUNNING, claimed_at, None, None
                    ),
                    worker_id=worker,
                    claim_token=token,
                    claimed_at=claimed_at,
                    lease_deadline=deadline,
                )
                self._connection.execute(
                    "UPDATE jobs SET status='running',started_at=?,worker_id=?,claim_token=?,"
                    "claimed_at=?,lease_deadline=? WHERE job_id=? AND status='submitted'",
                    (
                        updated.started_at,
                        updated.worker_id,
                        updated.claim_token,
                        updated.claimed_at,
                        updated.lease_deadline,
                        updated.job_id,
                    ),
                )
                event = JobEvent(
                    2,
                    current.job_id,
                    JobStatus.SUBMITTED,
                    JobStatus.RUNNING,
                    claimed_at,
                )
                self._insert_event(event)
                claimed = self._validate_persisted_snapshot(
                    updated, (*_expected_events(current), event)
                )
                self._connection.execute("COMMIT")
                return JobClaim(claimed, request, token)
            except BaseException:
                self._rollback()
                raise

    def cancel(self, job_id: str, *, at: str) -> Job:
        """Persist the first cancellation request while terminal state wins races."""
        identifier = _validate_job_id(job_id)
        timestamp = _validate_time(at)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                current = self._require(identifier)
                if (
                    current.status in _TERMINAL
                    or current.cancel_requested_at is not None
                ):
                    return current
                updated = replace(current, cancel_requested_at=timestamp)
                self._jobs[identifier] = updated
                return updated
            try:
                assert self._connection is not None
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._require(identifier)
                if (
                    current.status not in _TERMINAL
                    and current.cancel_requested_at is None
                ):
                    updated = replace(current, cancel_requested_at=timestamp)
                    self._connection.execute(
                        "UPDATE jobs SET cancel_requested_at=?"
                        " WHERE job_id=? AND finished_at IS NULL",
                        (timestamp, identifier),
                    )
                else:
                    updated = current
                persisted = self._validate_persisted_snapshot(
                    updated, _expected_events(updated)
                )
                self._connection.execute("COMMIT")
                return persisted
            except BaseException:
                self._rollback()
                raise

    def reconcile(self, *, at: str) -> tuple[Job, ...]:
        """Fail-close abandoned running Jobs; submitted Jobs remain untouched."""
        timestamp = _validate_time(at)
        with self._lock:
            self._ensure_open()
            identifiers = (
                [
                    job.job_id
                    for job in self._jobs.values()
                    if job.status is JobStatus.RUNNING
                ]
                if self._connection is None
                else [
                    row[0]
                    for row in self._connection.execute(
                        "SELECT job_id FROM jobs WHERE status='running' ORDER BY job_id"
                    )
                ]
            )
            return tuple(
                self.transition(
                    identifier,
                    JobStatus.FAILED,
                    at=timestamp,
                    failure_code="service.restart_interrupted",
                    claim_token=self.get(identifier).claim_token,
                )
                for identifier in identifiers
            )

    def transition(  # pylint: disable=too-many-branches
        self,
        job_id: str,
        status: JobStatus,
        *,
        at: str,
        result: Result | None = None,
        failure_code: str | None = None,
        claim_token: str | None = None,
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
                _require_claim(current, status, claim_token)
                _require_cancellation_result(current, status, result, failure_code)
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
                self._record_artifact_grants(current, updated)
                return updated
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._require(identifier)
                _require_claim(current, status, claim_token)
                _require_cancellation_result(current, status, result, failure_code)
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
                self._insert_artifact_grants(current, updated)
                persisted = self._validate_persisted_snapshot(
                    updated, (*_expected_events(current), event)
                )
                self._connection.execute("COMMIT")
                return persisted
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

    def caller_has_artifact(self, caller_id: str, artifact_id: str) -> bool:
        """Query Artifact authority committed atomically with terminal Jobs."""
        caller = _validate_boundary_text(caller_id, "caller.invalid", 256)
        identifier = validate_artifact_id(artifact_id)
        with self._lock:
            self._ensure_open()
            if self._connection is None:
                return (caller, identifier) in self._artifact_grants
            return (
                self._connection.execute(
                    "SELECT 1 FROM job_artifact_grants WHERE caller_id=? AND artifact_id=?",
                    (caller, identifier),
                ).fetchone()
                is not None
                or self._connection.execute(
                    "SELECT 1 FROM url_fetch_artifact_grants WHERE caller_id=? AND artifact_id=?",
                    (caller, identifier),
                ).fetchone()
                is not None
            )

    def check(self) -> None:
        """Perform a minimal read-only repository integrity probe."""
        with self._lock:
            self._ensure_open()
            if self._connection is not None:
                result = self._connection.execute("PRAGMA quick_check(1)").fetchone()
                if result is None or result[0] != "ok":
                    raise JobStateError("repository.check_failed")

    def _record_artifact_grants(self, current: Job, updated: Job) -> None:
        if current.caller_id is not None and updated.result is not None:
            self._artifact_grants.update(
                (current.caller_id, item.artifact_id)
                for item in updated.result.artifacts
            )

    def _insert_artifact_grants(self, current: Job, updated: Job) -> None:
        if current.caller_id is None or updated.result is None:
            return
        assert self._connection is not None
        self._connection.executemany(
            "INSERT OR IGNORE INTO job_artifact_grants"
            " (job_id,caller_id,artifact_id) VALUES (?,?,?)",
            (
                (updated.job_id, current.caller_id, item.artifact_id)
                for item in updated.result.artifacts
            ),
        )

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
            "SELECT * FROM jobs WHERE job_id = ?",
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

    def _validate_persisted_snapshot(
        self, expected_job: Job, expected_events: tuple[JobEvent, ...]
    ) -> Job:
        persisted_job = self._load_job(expected_job.job_id)
        persisted_events = self._load_events(persisted_job)
        if persisted_job != expected_job or persisted_events != expected_events:
            raise JobStateError("job.persisted_invalid")
        return persisted_job

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
        CREATE TABLE IF NOT EXISTS job_artifact_grants (
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            caller_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            PRIMARY KEY (job_id, artifact_id)
        );
        CREATE TABLE IF NOT EXISTS site_batches (
            batch_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            cancel_requested_at TEXT,
            result_json TEXT,
            failure_code TEXT,
            caller_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_json TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL
            ,execution_request_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS site_batch_children (
            batch_id TEXT NOT NULL REFERENCES site_batches(batch_id),
            child_order INTEGER NOT NULL,
            site_key TEXT NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT,
            PRIMARY KEY (batch_id, child_order)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS site_batches_idempotency
        ON site_batches(caller_id,idempotency_key);
        CREATE TABLE IF NOT EXISTS url_fetches (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            cancel_requested_at TEXT,
            result_json TEXT,
            failure_code TEXT,
            caller_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_json TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL,
            execution_request_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS url_fetch_hops (
            job_id TEXT NOT NULL REFERENCES url_fetches(job_id),
            hop_order INTEGER NOT NULL,
            result_json TEXT NOT NULL,
            PRIMARY KEY (job_id,hop_order)
        );
        CREATE TABLE IF NOT EXISTS url_fetch_discovery (
            job_id TEXT NOT NULL REFERENCES url_fetches(job_id),
            discovery_order INTEGER NOT NULL,
            evidence_json TEXT NOT NULL,
            PRIMARY KEY (job_id,discovery_order)
        );
        CREATE TABLE IF NOT EXISTS url_fetch_artifact_grants (
            job_id TEXT NOT NULL REFERENCES url_fetches(job_id),
            caller_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            PRIMARY KEY (job_id,artifact_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS url_fetches_idempotency
        ON url_fetches(caller_id,idempotency_key);
        """)
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
    }
    additions = {
        "request_json": "TEXT",
        "request_fingerprint": "TEXT",
        "caller_id": "TEXT",
        "idempotency_key": "TEXT",
        "cancel_requested_at": "TEXT",
        "worker_id": "TEXT",
        "claim_token": "TEXT",
        "claimed_at": "TEXT",
        "lease_deadline": "TEXT",
        "execution_request_json": "TEXT",
        "execution_request_fingerprint": "TEXT",
    }
    for name, kind in additions.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE jobs ADD COLUMN {name} {kind}")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency "
        "ON jobs(caller_id,idempotency_key) WHERE caller_id IS NOT NULL"
    )


def _backfill_artifact_grants(connection: sqlite3.Connection) -> None:
    """Migrate caller-owned persisted Results into explicit grant rows."""
    rows = connection.execute(
        "SELECT job_id,caller_id,result_json FROM jobs "
        "WHERE caller_id IS NOT NULL AND result_json IS NOT NULL"
    ).fetchall()
    for row in rows:
        result = _result_from_json(row["result_json"])
        if result is not None:
            connection.executemany(
                "INSERT OR IGNORE INTO job_artifact_grants"
                " (job_id,caller_id,artifact_id) VALUES (?,?,?)",
                (
                    (row["job_id"], row["caller_id"], item.artifact_id)
                    for item in result.artifacts
                ),
            )


def _reject_symlink_chain(path: Path) -> None:
    for candidate in (*reversed(path.parents), path):
        try:
            candidate_stat = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if _is_link_like(candidate, candidate_stat):
            raise JobStateError("path.symlink")


def _require_directory(path: Path) -> None:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError as exc:
        raise JobStateError("path.missing") from exc
    if _is_link_like(path, path_stat):
        raise JobStateError("path.symlink")
    if not stat.S_ISDIR(path_stat.st_mode):
        raise JobStateError("path.not_directory")


def _require_regular_file(path: Path, *, missing_ok: bool) -> None:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError as exc:
        if missing_ok:
            return
        raise JobStateError("path.missing") from exc
    if _is_link_like(path, path_stat):
        raise JobStateError("path.symlink")
    if not stat.S_ISREG(path_stat.st_mode):
        raise JobStateError("path.not_file")


def _is_link_like(path: Path, path_stat: os.stat_result) -> bool:
    """Identify symlinks and Windows junction/reparse traversal points."""
    link_like = stat.S_ISLNK(path_stat.st_mode)
    is_junction = getattr(path, "is_junction", None)
    try:
        link_like = link_like or bool(is_junction and is_junction())
    except OSError:
        link_like = True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    file_attributes = getattr(path_stat, "st_file_attributes", 0)
    return link_like or bool(
        (file_attributes & reparse_flag) or getattr(path_stat, "st_reparse_tag", 0)
    )


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
        if result is None:
            if not (
                status is JobStatus.FAILED
                and failure_code == "service.restart_interrupted"
            ):
                raise JobStateError("job.result_required")
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
        _validate_persisted_requests(row)
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
            row["request_json"],
            row["request_fingerprint"],
            row["caller_id"],
            row["idempotency_key"],
            _optional_time(row["cancel_requested_at"]),
            row["worker_id"],
            row["claim_token"],
            _optional_time(row["claimed_at"]),
            _optional_time(row["lease_deadline"]),
            row["execution_request_json"],
            row["execution_request_fingerprint"],
        )
        rebuilt = replace(
            Job(identifier, JobStatus.SUBMITTED, submitted_at),
            request_json=row["request_json"],
            request_fingerprint=row["request_fingerprint"],
            caller_id=row["caller_id"],
            idempotency_key=row["idempotency_key"],
            cancel_requested_at=_optional_time(row["cancel_requested_at"]),
            execution_request_json=row["execution_request_json"],
            execution_request_fingerprint=row["execution_request_fingerprint"],
        )
        if status is not JobStatus.SUBMITTED:
            if started_at is None:
                raise JobStateError("job.persisted_invalid")
            rebuilt = _transition_snapshot(
                rebuilt, JobStatus.RUNNING, started_at, None, None
            )
            rebuilt = replace(
                rebuilt,
                worker_id=row["worker_id"],
                claim_token=row["claim_token"],
                claimed_at=_optional_time(row["claimed_at"]),
                lease_deadline=_optional_time(row["lease_deadline"]),
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


def _validate_boundary_text(value: object, code: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise JobStateError(code)
    return value


def _validate_idempotency_key(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise JobStateError("idempotency.key_invalid")
    return value


def _require_claim(job: Job, status: JobStatus, token: str | None) -> None:
    if (
        job.status is JobStatus.SUBMITTED
        and status is JobStatus.RUNNING
        and job.request_json is not None
    ):
        raise JobStateError("job.claim_required")
    if job.claim_token is not None and token != job.claim_token:
        raise JobStateError("job.claim_stale")


def _require_cancellation_result(
    job: Job,
    status: JobStatus,
    result: Result | None,
    failure_code: str | None,
) -> None:
    if (
        job.cancel_requested_at is not None
        and status in _TERMINAL
        and not (
            status is JobStatus.FAILED
            and result is None
            and failure_code == "service.restart_interrupted"
        )
        and (
            result is None
            or not any(error.code == "runtime.cancelled" for error in result.errors)
        )
    ):
        raise JobStateError("job.cancel_requested")


def canonical_request_facts(request: Request) -> tuple[Request, str, str]:
    """Validate and serialize the complete four-field Request canonically."""
    canonical = validate_request(request)
    skill = canonical.site_skill
    try:
        if isinstance(skill, SiteSkill):
            skill_model = site_skill_from_mapping(site_skill_to_mapping(skill))
            skill_mapping: object = site_skill_to_mapping(skill_model)
            skill = skill_model
        elif skill is None:
            skill_mapping = None
        else:
            skill_model = site_skill_from_mapping(skill)
            skill_mapping = site_skill_to_mapping(skill_model)
            skill = skill_model
    except SiteSkillError as exc:
        raise JobStateError(exc.code) from exc
    canonical = replace(
        canonical,
        scope=replace(
            canonical.scope,
            allowed_origins=tuple(sorted(canonical.scope.allowed_origins)),
            include_paths=tuple(sorted(canonical.scope.include_paths)),
            content_types=tuple(
                sorted(canonical.scope.content_types, key=lambda item: item.value)
            ),
        ),
        site_skill=skill,
    )
    mapping: dict[str, Any] = {
        "scope": {
            "seeds": list(canonical.scope.seeds),
            "allowed_origins": list(canonical.scope.allowed_origins),
            "include_paths": list(canonical.scope.include_paths),
            "content_types": [item.value for item in canonical.scope.content_types],
        },
        "site_skill": skill_mapping,
        "explore_all_tools": canonical.explore_all_tools,
        "budgets": {
            "max_requests": canonical.budgets.max_requests,
            "max_bytes": canonical.budgets.max_bytes,
            "max_runtime_seconds": canonical.budgets.max_runtime_seconds,
            "max_tool_attempts_per_target": canonical.budgets.max_tool_attempts_per_target,
        },
    }
    try:
        _ensure_request_payload_safe(mapping)
    except ResultValidationError as exc:
        raise JobStateError("request.sensitive_data") from exc
    payload = json.dumps(
        mapping, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return canonical, payload, hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _request_from_json(payload: str) -> Request:
    mapping = json.loads(payload)
    request = request_from_mapping(mapping)
    if request.site_skill is not None:
        request = replace(
            request, site_skill=site_skill_from_mapping(request.site_skill)
        )
    return request


def _validate_execution_authority(
    request: Request, execution: Request, *, code: str
) -> None:
    if replace(request, budgets=execution.budgets) != execution or any(
        getattr(execution.budgets, name) > getattr(request.budgets, name)
        for name in (
            "max_requests",
            "max_bytes",
            "max_runtime_seconds",
            "max_tool_attempts_per_target",
        )
    ):
        raise JobStateError(code)


def _ensure_request_payload_safe(value: object) -> None:
    """Apply existing secret validation while allowing governed scope paths."""
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        try:
            ensure_safe_text(value)
            if value.startswith(("http://", "https://")):
                _ensure_query_safe(urlsplit(value).query)
        except ResultValidationError as exc:
            if exc.code != "result.absolute_path":
                raise
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            _ensure_request_payload_safe(key)
            _ensure_request_payload_safe(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _ensure_request_payload_safe(child)
        return
    raise ResultValidationError("schema.invalid")


def _ensure_query_safe(query: str) -> None:
    for key, value in parse_qsl(query, keep_blank_values=True):
        normalized = key
        for _unused in range(3):
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded
        normalized = re.sub(
            r"[^a-z0-9]",
            "",
            unicodedata.normalize("NFKC", normalized).casefold(),
        )
        if normalized in _SECRET_QUERY_KEYS:
            raise ResultValidationError("result.sensitive_data")
        ensure_safe_text(key)
        ensure_safe_text(value)


def _validate_persisted_requests(row: sqlite3.Row) -> None:
    values = (
        row["request_json"],
        row["request_fingerprint"],
        row["execution_request_json"],
        row["execution_request_fingerprint"],
        row["caller_id"],
        row["idempotency_key"],
    )
    if all(value is None for value in values):
        return
    if any(type(value) is not str for value in values):
        raise JobStateError("job.persisted_invalid")
    request = _request_from_json(row["request_json"])
    execution = _request_from_json(row["execution_request_json"])
    _, request_json, fingerprint = canonical_request_facts(request)
    _, execution_json, execution_fingerprint = canonical_request_facts(execution)
    if (
        request_json != row["request_json"]
        or fingerprint != row["request_fingerprint"]
        or execution_json != row["execution_request_json"]
        or execution_fingerprint != row["execution_request_fingerprint"]
    ):
        raise JobStateError("job.persisted_invalid")
    _validate_execution_authority(request, execution, code="job.persisted_invalid")
    _validate_boundary_text(row["caller_id"], "job.persisted_invalid", 256)
    _validate_idempotency_key(row["idempotency_key"])


__all__ = [
    "BatchChild",
    "Job",
    "JobClaim",
    "JobEvent",
    "JobRepository",
    "JobStateError",
    "JobStatus",
    "SiteBatch",
    "SiteBatchClaim",
    "canonical_request_facts",
]
