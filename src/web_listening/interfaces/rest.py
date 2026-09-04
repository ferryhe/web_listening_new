"""Thin REST adapter over the public Runtime service."""

# pylint: disable=duplicate-code,too-many-return-statements,too-many-statements

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import replace

from fastapi import FastAPI  # pylint: disable=import-error
from fastapi import Request as HttpRequest  # pylint: disable=import-error
from fastapi.concurrency import run_in_threadpool  # pylint: disable=import-error
from fastapi.responses import JSONResponse  # pylint: disable=import-error

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


def _job_payload(job: Job) -> dict[str, object]:
    result = None if job.result is None else job.result.to_dict()
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "submitted_at": job.submitted_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "result": result,
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


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": SafeError(code, message).to_dict()},
    )


def _runtime_error_response(exc: Exception) -> JSONResponse:
    if isinstance(exc, HandoffError):
        if exc.code == "handoff.not_terminal":
            return _error_response(409, exc.code, "Job is not terminal.")
        if exc.code == "handoff.result_unavailable":
            return _error_response(404, exc.code, "Result is unavailable.")
        return _error_response(500, exc.code, "Handoff export failed.")
    if isinstance(exc, JobStateError):
        if exc.code == "job.not_found":
            return _error_response(404, exc.code, "Resource was not found.")
        if exc.code == "job.id_invalid":
            return _error_response(422, exc.code, "Identifier is invalid.")
    if isinstance(exc, ArtifactStoreError):
        if exc.code == "artifact.not_found":
            return _error_response(404, exc.code, "Resource was not found.")
        if exc.code == "artifact.id_invalid":
            return _error_response(422, exc.code, "Identifier is invalid.")
    return _error_response(500, "runtime.failed", "Runtime request failed.")


def create_app(runtime_provider: RuntimeProvider) -> FastAPI:
    """Create thin routes using an explicitly provided Runtime."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/acquisitions", status_code=201)
    async def acquire(http_request: HttpRequest) -> JSONResponse:
        try:
            payload = (await http_request.body()).decode("utf-8")
            request = request_from_json(payload)
            if request.site_skill is not None:
                request = replace(
                    request,
                    site_skill=site_skill_from_mapping(request.site_skill),
                )
        except UnicodeDecodeError:
            return _error_response(422, "request.invalid_json", "Request is invalid.")
        except (RequestValidationError, SiteSkillError) as exc:
            return _error_response(422, exc.code, "Request is invalid.")
        try:
            runtime = runtime_provider()
            job = await run_in_threadpool(runtime.run, request)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _runtime_error_response(exc)
        status_code = {
            JobStatus.REJECTED: 422,
            JobStatus.FAILED: 500,
        }.get(job.status, 201)
        return JSONResponse(status_code=status_code, content=_job_payload(job))

    @app.get("/v1/jobs/{run_id}")
    def get_job(run_id: str) -> JSONResponse:
        try:
            runtime = runtime_provider()
            job = runtime.get_job(run_id)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _runtime_error_response(exc)
        return JSONResponse(status_code=200, content=_job_payload(job))

    @app.get("/v1/jobs/{job_id}/handoff")
    def get_handoff(job_id: str) -> JSONResponse:
        try:
            runtime = runtime_provider()
            handoff = runtime.get_handoff(job_id)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _runtime_error_response(exc)
        return JSONResponse(status_code=200, content=handoff.to_dict())

    @app.get("/v1/artifacts/{artifact_id}")
    def read_artifact(artifact_id: str) -> JSONResponse:
        try:
            runtime = runtime_provider()
            artifact = runtime.read_artifact(artifact_id)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _runtime_error_response(exc)
        return JSONResponse(status_code=200, content=_artifact_payload(artifact))

    @app.post("/v1/site-explorations", status_code=201)
    async def site_explore(http_request: HttpRequest) -> JSONResponse:
        try:
            payload = (await http_request.body()).decode("utf-8")
            request = request_from_json(payload)
            if request.site_skill is not None:
                request = replace(
                    request,
                    site_skill=site_skill_from_mapping(request.site_skill),
                )
        except UnicodeDecodeError:
            return _error_response(422, "request.invalid_json", "Request is invalid.")
        except (RequestValidationError, SiteSkillError) as exc:
            return _error_response(422, exc.code, "Request is invalid.")
        try:
            runtime = runtime_provider()
            result = await run_in_threadpool(runtime.explore_site, request)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _runtime_error_response(exc)
        status_code = {
            "rejected": 422,
            "failed": 500,
        }.get(result.status.value, 201)
        return JSONResponse(status_code=status_code, content=result.to_dict())

    @app.post("/v1/site-refreshes", status_code=201)
    async def site_refresh(http_request: HttpRequest) -> JSONResponse:
        try:
            payload = (await http_request.body()).decode("utf-8")
            request = site_refresh_request_from_json(payload)
        except UnicodeDecodeError:
            return _error_response(422, "request.invalid_json", "Request is invalid.")
        except RequestValidationError as exc:
            return _error_response(422, exc.code, "Request is invalid.")
        try:
            runtime = runtime_provider()
            result = await run_in_threadpool(runtime.refresh_site, request)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return _runtime_error_response(exc)
        status_code = {
            "rejected": 422,
            "failed": 500,
        }.get(result.status.value, 201)
        return JSONResponse(status_code=status_code, content=result.to_dict())

    return app


__all__ = ["RuntimeProvider", "create_app"]
