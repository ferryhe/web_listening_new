"""Authenticated thin REST adapter over the public Runtime service."""

# pylint: disable=duplicate-code,too-many-statements,too-many-return-statements
# pylint: disable=broad-exception-caught
# pylint: disable=too-many-locals

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace

from fastapi import FastAPI
from fastapi import Request as HttpRequest
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse

from web_listening.artifact.model import ArtifactStoreError, StoredArtifact
from web_listening.request.model import RequestValidationError
from web_listening.request.site_refresh import site_refresh_request_from_json
from web_listening.request.validate import request_from_json
from web_listening.result.errors import SafeError
from web_listening.runtime.handoff import HandoffError
from web_listening.runtime.jobs import Job, JobStateError, JobStatus
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.model import SiteSkillError
from web_listening.site_skill.validate import site_skill_from_mapping

RuntimeProvider = Callable[[], RuntimeService]


@dataclass(frozen=True, slots=True)
class RestConfig:
    """Non-secret HTTP boundary configuration."""

    caller_id: str
    token_sha256: str
    binary_cap_bytes: int = 100 * 1024 * 1024
    base64_cap_bytes: int = 1024 * 1024


def _job_payload(job: Job) -> dict[str, object]:
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "submitted_at": job.submitted_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "cancel_requested_at": job.cancel_requested_at,
        "result": None if job.result is None else job.result.to_dict(),
        "failure_code": job.failure_code,
    }


def _artifact_payload(artifact: StoredArtifact) -> dict[str, object]:
    return {
        "artifact_id": artifact.artifact_id,
        "blob_sha256": artifact.blob_sha256,
        "size_bytes": artifact.size_bytes,
        "mime_type": artifact.mime_type,
        "content_encoding": "base64",
        "content": base64.b64encode(artifact.content).decode("ascii"),
    }


def _error(status: int, code: str, message: str, **headers: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": SafeError(code, message).to_dict()},
        headers=headers,
    )


def _runtime_error(exc: Exception) -> JSONResponse:
    code = getattr(exc, "code", "runtime.failed")
    if isinstance(exc, JobStateError) and code == "job.not_found":
        return _error(404, code, "Resource was not found.")
    if isinstance(exc, ArtifactStoreError) and code == "artifact.not_found":
        return _error(404, code, "Resource was not found.")
    if code == "idempotency.conflict":
        return _error(409, code, "Idempotency key conflicts with this request.")
    if isinstance(exc, HandoffError) and code == "handoff.not_terminal":
        return _error(409, code, "Job is not terminal.")
    if isinstance(exc, HandoffError) and code == "handoff.result_unavailable":
        return _error(404, code, "Resource was not found.")
    if isinstance(exc, (JobStateError, ArtifactStoreError)) and code.endswith(
        "invalid"
    ):
        return _error(422, code, "Identifier is invalid.")
    return _error(500, "runtime.failed", "Runtime request failed.")


def create_app(
    runtime_provider: RuntimeProvider,
    config: RestConfig,
    *,
    wake: Callable[[], None] | None = None,
    ready: Callable[[], bool] | None = None,
) -> FastAPI:
    """Create authenticated routes using an explicitly provided Runtime."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def caller(http_request: HttpRequest) -> str | JSONResponse:
        value = http_request.headers.get("authorization", "")
        parts = value.split(" ")
        valid = len(parts) == 2 and parts[0] == "Bearer" and bool(parts[1])
        digest = hashlib.sha256(parts[1].encode()).hexdigest() if valid else "0" * 64
        if not valid or not hmac.compare_digest(digest, config.token_sha256):
            return _error(
                401,
                "authentication.invalid",
                "Authentication is required.",
                **{"WWW-Authenticate": "Bearer"},
            )
        return config.caller_id

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def readiness() -> JSONResponse:
        is_ready = ready is None or ready()
        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={"status": "ready" if is_ready else "unready"},
        )

    @app.post("/v1/acquisitions")
    async def acquire(http_request: HttpRequest) -> JSONResponse:
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        key = http_request.headers.get("idempotency-key")
        if key is None:
            return _error(422, "idempotency.required", "Idempotency-Key is required.")
        try:
            request = request_from_json((await http_request.body()).decode("utf-8"))
            if request.site_skill is not None:
                request = replace(
                    request, site_skill=site_skill_from_mapping(request.site_skill)
                )
        except UnicodeDecodeError:
            return _error(422, "request.invalid_json", "Request is invalid.")
        except (RequestValidationError, SiteSkillError) as exc:
            return _error(422, exc.code, "Request is invalid.")
        try:
            job = runtime_provider().submit(
                request, caller_id=identity, idempotency_key=key
            )
            if wake is not None:
                wake()
            return JSONResponse(status_code=202, content=_job_payload(job))
        except Exception as exc:
            return _runtime_error(exc)

    @app.get("/v1/jobs/{job_id}")
    def get_job(job_id: str, http_request: HttpRequest) -> JSONResponse:
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        try:
            return JSONResponse(
                status_code=200,
                content=_job_payload(
                    runtime_provider().get_owned_job(job_id, identity)
                ),
            )
        except Exception as exc:
            return _runtime_error(exc)

    @app.post("/v1/jobs/{job_id}/cancel")
    def cancel(job_id: str, http_request: HttpRequest) -> JSONResponse:
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        try:
            job = runtime_provider().cancel_owned(job_id, identity)
            status = (
                200
                if job.status
                in {
                    JobStatus.COMPLETED,
                    JobStatus.PARTIAL,
                    JobStatus.FAILED,
                    JobStatus.REJECTED,
                }
                else 202
            )
            return JSONResponse(status_code=status, content=_job_payload(job))
        except Exception as exc:
            return _runtime_error(exc)

    @app.get("/v1/jobs/{job_id}/handoff")
    def handoff(job_id: str, http_request: HttpRequest) -> JSONResponse:
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        try:
            return JSONResponse(
                status_code=200,
                content=runtime_provider()
                .get_owned_handoff(job_id, identity)
                .to_dict(),
            )
        except Exception as exc:
            return _runtime_error(exc)

    @app.get("/v1/artifacts/{artifact_id}")
    def artifact(artifact_id: str, http_request: HttpRequest) -> JSONResponse:
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        context: AbstractContextManager = runtime_provider().open_owned_artifact(
            artifact_id, identity
        )
        try:
            opened = context.__enter__()  # pylint: disable=unnecessary-dunder-call
            if opened.size_bytes > config.base64_cap_bytes:
                context.__exit__(None, None, None)
                return _error(
                    413, "artifact.too_large", "Artifact exceeds response limit."
                )
            try:
                content = opened.stream.read(opened.size_bytes + 1)
            finally:
                context.__exit__(None, None, None)
            if len(content) != opened.size_bytes:
                raise ArtifactStoreError("blob.corrupt")
            stored = StoredArtifact(
                opened.artifact_id,
                opened.blob_sha256,
                opened.size_bytes,
                opened.mime_type,
                content,
            )
            return JSONResponse(status_code=200, content=_artifact_payload(stored))
        except Exception as exc:
            return _runtime_error(exc)

    @app.get("/v1/artifacts/{artifact_id}/content")
    def artifact_content(artifact_id: str, http_request: HttpRequest):
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        if "range" in http_request.headers:
            return _error(416, "range.unsupported", "Range requests are unsupported.")
        context: AbstractContextManager = runtime_provider().open_owned_artifact(
            artifact_id, identity
        )
        try:
            opened = context.__enter__()  # pylint: disable=unnecessary-dunder-call
            if opened.size_bytes > config.binary_cap_bytes:
                context.__exit__(None, None, None)
                return _error(
                    413, "artifact.too_large", "Artifact exceeds response limit."
                )
        except Exception as exc:
            return _runtime_error(exc)

        def chunks() -> Iterator[bytes]:
            try:
                while chunk := opened.stream.read(1024 * 1024):
                    yield chunk
            finally:
                context.__exit__(None, None, None)

        headers = {
            "Content-Length": str(opened.size_bytes),
            "ETag": f'"{opened.blob_sha256}"',
            "Digest": f"sha-256={opened.blob_sha256}",
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Type": opened.mime_type,
        }
        return StreamingResponse(chunks(), headers=headers)

    async def synchronous(http_request: HttpRequest, refresh: bool) -> JSONResponse:
        identity = caller(http_request)
        if isinstance(identity, JSONResponse):
            return identity
        try:
            raw = (await http_request.body()).decode("utf-8")
            if refresh:
                request = site_refresh_request_from_json(raw)
            else:
                request = request_from_json(raw)
                if request.site_skill is not None:
                    request = replace(
                        request, site_skill=site_skill_from_mapping(request.site_skill)
                    )
        except UnicodeDecodeError:
            return _error(422, "request.invalid_json", "Request is invalid.")
        except (RequestValidationError, SiteSkillError) as exc:
            return _error(422, exc.code, "Request is invalid.")
        try:
            if refresh:
                result = await run_in_threadpool(
                    runtime_provider().refresh_site_owned, request, identity
                )
            else:
                result = await run_in_threadpool(
                    runtime_provider().explore_site_owned, request, identity
                )
            status = {"rejected": 422, "failed": 500}.get(result.status.value, 201)
            return JSONResponse(status_code=status, content=result.to_dict())
        except Exception as exc:
            return _runtime_error(exc)

    @app.post("/v1/site-explorations")
    async def site_explore(http_request: HttpRequest) -> JSONResponse:
        return await synchronous(http_request, False)

    @app.post("/v1/site-refreshes")
    async def site_refresh(http_request: HttpRequest) -> JSONResponse:
        return await synchronous(http_request, True)

    return app


__all__ = ["RestConfig", "create_app"]
