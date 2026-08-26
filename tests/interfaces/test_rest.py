"""Focused contract tests for the Phase 10 thin REST adapter."""

# pylint: disable=missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods
# pylint: disable=consider-using-from-import,duplicate-code
# pylint: disable=redefined-outer-name,too-many-instance-attributes
# pylint: disable=wrong-import-position

from __future__ import annotations

import base64
import json
import tomllib
from pathlib import Path
from threading import get_ident

import pytest

pytest.importorskip("fastapi", reason="install the optional web-listening[rest] extra")

from fastapi.testclient import TestClient  # pylint: disable=import-error

import web_listening.interfaces.cli as cli
import web_listening.interfaces.rest as rest
from web_listening.artifact.model import ArtifactStoreError, StoredArtifact
from web_listening.request.model import Request, RequestValidationError
from web_listening.result.model import Result
from web_listening.runtime.jobs import Job, JobStateError, JobStatus
from web_listening.site_skill.model import SiteSkill, SiteSkillError

ROOT = Path(__file__).parents[2]
RESULT_FIXTURES = ROOT / "tests" / "result" / "fixtures"
SITE_SKILL_CATALOG = ROOT / "tests" / "live" / "catalog" / "site_skill_cases.json"


def _result(name: str = "completed.v1.json") -> Result:
    return Result.from_dict(
        json.loads((RESULT_FIXTURES / name).read_text(encoding="utf-8"))
    )


def _job(name: str = "completed.v1.json") -> Job:
    result = _result(name)
    failure_code = result.errors[0].code if result.errors else None
    return Job(
        job_id=result.manifest.run_id,
        status=JobStatus(result.status.value),
        submitted_at="2026-08-25T11:59:58Z",
        started_at="2026-08-25T11:59:59Z",
        finished_at="2026-08-25T12:00:01Z",
        result=result,
        failure_code=failure_code,
    )


def _request_payload(site_skill: object = None) -> dict[str, object]:
    return {
        "scope": {
            "seeds": ["https://www.ipcc.ch/"],
            "allowed_origins": ["https://www.ipcc.ch"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": site_skill,
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 1,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 1,
        },
    }


def _site_skill() -> dict[str, object]:
    payload = json.loads(SITE_SKILL_CATALOG.read_text(encoding="utf-8"))
    return next(
        item["site_skill"] for item in payload["cases"] if item["site_key"] == "ipcc"
    )


class FakeRuntime:
    """Programmable test double exposing only RuntimeService public methods."""

    def __init__(self) -> None:
        self.run_job = _job()
        self.get_job_result = _job()
        content = b"\x00phase-10\xff"
        self.artifact = StoredArtifact(
            artifact_id="artifact-one",
            blob_sha256="a" * 64,
            size_bytes=len(content),
            mime_type="application/octet-stream",
            content=content,
        )
        self.run_error: Exception | None = None
        self.get_error: Exception | None = None
        self.read_error: Exception | None = None
        self.requests: list[Request] = []
        self.run_thread_ids: list[int] = []
        self.job_ids: list[str] = []
        self.artifact_ids: list[str] = []

    def run(self, request: Request) -> Job:
        self.run_thread_ids.append(get_ident())
        self.requests.append(request)
        if self.run_error is not None:
            raise self.run_error
        return self.run_job

    def get_job(self, job_id: str) -> Job:
        self.job_ids.append(job_id)
        if self.get_error is not None:
            raise self.get_error
        return self.get_job_result

    def read_artifact(self, artifact_id: str) -> StoredArtifact:
        self.artifact_ids.append(artifact_id)
        if self.read_error is not None:
            raise self.read_error
        return self.artifact


@pytest.fixture
def runtime() -> FakeRuntime:
    return FakeRuntime()


def _client(runtime: FakeRuntime) -> TestClient:
    return TestClient(rest.create_app(lambda: runtime))


def test_app_exposes_exactly_the_three_readme_routes_and_disables_docs(
    runtime: FakeRuntime,
) -> None:
    app = rest.create_app(lambda: runtime)

    observed = {(route.path, tuple(sorted(route.methods))) for route in app.routes}
    assert observed == {
        ("/v1/acquisitions", ("POST",)),
        ("/v1/jobs/{run_id}", ("GET",)),
        ("/v1/artifacts/{artifact_id}", ("GET",)),
    }
    client = TestClient(app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).post("/v1/acquisitions", json=_request_payload())

    assert response.status_code == 201
    assert len(runtime.requests) == 1
    assert isinstance(runtime.requests[0], Request)
    assert response.json() == cli._job_payload(runtime.run_job)
    assert Result.from_dict(response.json()["result"]) == runtime.run_job.result


def test_acquire_offloads_runtime_run_from_the_handler_thread(
    runtime: FakeRuntime,
) -> None:
    provider_thread_ids: list[int] = []

    def provider() -> FakeRuntime:
        provider_thread_ids.append(get_ident())
        return runtime

    response = TestClient(rest.create_app(provider)).post(
        "/v1/acquisitions", json=_request_payload()
    )

    assert response.status_code == 201
    assert len(provider_thread_ids) == len(runtime.run_thread_ids) == 1
    assert runtime.run_thread_ids[0] != provider_thread_ids[0]


def test_acquire_validates_embedded_site_skill_before_runtime(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).post(
        "/v1/acquisitions", json=_request_payload(_site_skill())
    )

    assert response.status_code == 201
    assert len(runtime.requests) == 1
    parsed = runtime.requests[0]
    assert isinstance(parsed.site_skill, SiteSkill)
    assert parsed.site_skill.site_key == "ipcc"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"scope":', "request.invalid_json"),
        (json.dumps({"scope": {}}).encode(), "request.missing"),
        (
            json.dumps({**_request_payload(), "private": "C:/private/canary"}).encode(),
            "request.unknown_field",
        ),
        (
            json.dumps(_request_payload({})).encode(),
            "site_skill.missing",
        ),
    ],
)
def test_invalid_acquisition_input_is_stable_safe_422_without_calling_runtime(
    runtime: FakeRuntime, body: bytes, code: str
) -> None:
    client = _client(runtime)

    first = client.post(
        "/v1/acquisitions",
        content=body,
        headers={"content-type": "application/json"},
    )
    second = client.post(
        "/v1/acquisitions",
        content=body,
        headers={"content-type": "application/json"},
    )

    assert first.status_code == second.status_code == 422
    assert first.content == second.content
    assert first.json() == {
        "error": {
            "code": code,
            "message": "Request is invalid.",
            "details": {},
        }
    }
    assert "private" not in first.text.lower()
    assert "canary" not in first.text.lower()
    assert runtime.requests == []


@pytest.mark.parametrize(
    ("failure_source", "error"),
    [
        ("provider", RequestValidationError("private.provider_request")),
        ("provider", SiteSkillError("private.provider_site_skill")),
        ("runtime", RequestValidationError("private.runtime_request")),
        ("runtime", SiteSkillError("private.runtime_site_skill")),
    ],
)
def test_acquire_redacts_provider_and_runtime_validation_errors(
    runtime: FakeRuntime, failure_source: str, error: Exception
) -> None:
    def failing_provider() -> FakeRuntime:
        raise error

    if failure_source == "provider":
        client = TestClient(rest.create_app(failing_provider))
    else:
        runtime.run_error = error
        client = _client(runtime)

    response = client.post("/v1/acquisitions", json=_request_payload())

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "runtime.failed",
            "message": "Runtime request failed.",
            "details": {},
        }
    }
    assert str(error) not in response.text


@pytest.mark.parametrize(
    ("fixture", "status"),
    [("rejected-boundary.v1.json", 422), ("failed.v1.json", 500)],
)
def test_acquire_maps_rejected_and_failed_jobs_without_changing_result_body(
    runtime: FakeRuntime, fixture: str, status: int
) -> None:
    runtime.run_job = _job(fixture)

    response = _client(runtime).post("/v1/acquisitions", json=_request_payload())

    assert response.status_code == status
    assert response.json() == cli._job_payload(runtime.run_job)
    assert Result.from_dict(response.json()["result"]) == runtime.run_job.result


def test_get_job_calls_only_public_runtime_and_returns_cli_parity(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).get("/v1/jobs/run-completed-001")

    assert response.status_code == 200
    assert runtime.job_ids == ["run-completed-001"]
    assert response.json() == cli._job_payload(runtime.get_job_result)


@pytest.mark.parametrize(
    ("path", "error", "status", "code"),
    [
        ("/v1/jobs/missing", JobStateError("job.not_found"), 404, "job.not_found"),
        ("/v1/jobs/bad%20id", JobStateError("job.id_invalid"), 422, "job.id_invalid"),
    ],
)
def test_get_job_maps_safe_repository_errors(
    runtime: FakeRuntime, path: str, error: Exception, status: int, code: str
) -> None:
    runtime.get_error = error

    response = _client(runtime).get(path)

    assert response.status_code == status
    assert response.json() == {
        "error": {
            "code": code,
            "message": (
                "Resource was not found." if status == 404 else "Identifier is invalid."
            ),
            "details": {},
        }
    }


def test_read_artifact_returns_lossless_base64_with_cli_parity(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).get("/v1/artifacts/artifact-one")

    assert response.status_code == 200
    assert runtime.artifact_ids == ["artifact-one"]
    assert response.json() == cli._artifact_payload(runtime.artifact)
    assert base64.b64decode(response.json()["content"], validate=True) == (
        runtime.artifact.content
    )


@pytest.mark.parametrize(
    ("path", "error", "status", "code"),
    [
        (
            "/v1/artifacts/missing",
            ArtifactStoreError("artifact.not_found"),
            404,
            "artifact.not_found",
        ),
        (
            "/v1/artifacts/bad",
            ArtifactStoreError("artifact.id_invalid"),
            422,
            "artifact.id_invalid",
        ),
    ],
)
def test_read_artifact_maps_safe_repository_errors(
    runtime: FakeRuntime, path: str, error: Exception, status: int, code: str
) -> None:
    runtime.read_error = error

    response = _client(runtime).get(path)

    assert response.status_code == status
    assert response.json()["error"] == {
        "code": code,
        "message": (
            "Resource was not found." if status == 404 else "Identifier is invalid."
        ),
        "details": {},
    }


@pytest.mark.parametrize(
    ("route", "error_attribute", "error"),
    [
        (
            "/v1/jobs/private",
            "get_error",
            JobStateError("private.job_state.not_found"),
        ),
        (
            "/v1/jobs/cross-type",
            "get_error",
            JobStateError("artifact.not_found"),
        ),
        (
            "/v1/artifacts/private",
            "read_error",
            ArtifactStoreError("blob.not_found"),
        ),
        (
            "/v1/artifacts/cross-type",
            "read_error",
            ArtifactStoreError("job.not_found"),
        ),
        (
            "/v1/artifacts/corrupt",
            "read_error",
            ArtifactStoreError("artifact.corrupt"),
        ),
    ],
)
def test_unallowlisted_typed_runtime_errors_are_redacted(
    runtime: FakeRuntime, route: str, error_attribute: str, error: Exception
) -> None:
    setattr(runtime, error_attribute, error)

    response = _client(runtime).get(route)

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "runtime.failed",
            "message": "Runtime request failed.",
            "details": {},
        }
    }
    assert str(error) not in response.text


def test_unexpected_runtime_failure_is_redacted_and_deterministic(
    runtime: FakeRuntime, tmp_path: Path
) -> None:
    private_error = RuntimeError(f"PRIVATE:{tmp_path}")
    private_error.code = "private.not_found"  # type: ignore[attr-defined]
    runtime.run_error = private_error
    client = _client(runtime)

    first = client.post("/v1/acquisitions", json=_request_payload())
    second = client.post("/v1/acquisitions", json=_request_payload())

    assert first.status_code == second.status_code == 500
    assert first.content == second.content
    assert first.json() == {
        "error": {
            "code": "runtime.failed",
            "message": "Runtime request failed.",
            "details": {},
        }
    }
    assert "PRIVATE" not in first.text
    assert str(tmp_path) not in first.text


def test_rest_source_has_only_interface_dto_and_public_runtime_authority() -> None:
    source = Path(rest.__file__).read_text(encoding="utf-8")
    forbidden = (
        "tool_registry",
        "Registry",
        "Gateway",
        "artifact.store",
        "ArtifactStore(",
        "runtime.workflow",
        "acquisition.builtins",
        "sqlite",
    )

    assert "RuntimeService" in source
    assert "runtime_provider" in source
    assert "run_in_threadpool(runtime.run, request)" in source
    assert "runtime.get_job(" in source
    assert "runtime.read_artifact(" in source
    assert "RuntimeService.open" not in source
    assert all(name not in source for name in forbidden)


def test_pyproject_keeps_rest_dependencies_in_one_optional_extra() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    assert project["dependencies"] == []
    rest_dependencies = project["optional-dependencies"]["rest"]
    assert len(rest_dependencies) == 1
    assert rest_dependencies[0].startswith("fastapi>=")
